"""端口与服务探测模块。

思路（也是本项目一直遵循的“可解释”风格）：
    1. 对每个端口做一次 TCP 连接；
    2. 连接成功就按该端口对应的协议发探测包（有的服务会自己先报 banner，
       这时只读不发）；
    3. 拿回的数据用正则匹配，识别出具体是什么服务。

只依赖标准库 socket / ssl / json / re，不引入第三方。
"""

import json
import os
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .http_client import normalize_url
from .models import Finding

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")

# 从目标 URL 里若带显式端口，会额外补扫一下；这是没在 -p 里指定端口时的兜底。
DEFAULT_TIMEOUT = 3.0
DEFAULT_THREADS = 200


# ---------------------------------------------------------------------- #
# 字典读取
# ---------------------------------------------------------------------- #
def load_probes(path: Optional[str] = None) -> Dict:
    """读取 service_probes.json，返回端口 -> 规则 的映射和默认端口列表。

    返回结构::

        {
          "map": {22: {...ssh规则...}, 80: {...http规则...}},
          "default": [21, 22, 25, 80, ...],
          "fallback": {"probe": "...", "regex": [...]},
        }
    """
    path = path or os.path.join(DICT_DIR, "service_probes.json")
    with open(path, "r", encoding="utf-8") as fp:
        rules = json.load(fp)

    port_map: Dict[int, dict] = {}
    default_ports: List[int] = []
    for rule in rules:
        for port in rule.get("ports", []):
            port_map[int(port)] = rule
            if int(port) not in default_ports:
                default_ports.append(int(port))
    default_ports.sort()

    return {
        "map": port_map,
        "default": default_ports,
        # 对“没有专属规则”的端口，用这个通用探测包先试一把
        "fallback": {
            "name": "HTTP",
            "probe": "GET / HTTP/1.0\r\nHost: {host}\r\n"
                     "User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
            "regex": ["^HTTP/1\\.[01]\\s"],
            "note": "Web 服务（通用 HTTP 探测识别）",
        },
    }


def parse_ports(spec: Optional[str]) -> Optional[List[int]]:
    """解析 -p 端口参数：支持 80 / 80,443 / 1-1000 / 80,443,8000-9000。"""
    if not spec:
        return None
    ports: List[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, _, b = chunk.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            ports.extend(range(lo, hi + 1))
        else:
            try:
                ports.append(int(chunk))
            except ValueError:
                continue
    return sorted(set(ports))


def extract_host(target: str) -> str:
    """从目标 URL 里取出主机名（不含端口）。"""
    url = normalize_url(target)
    return urlsplit(url).hostname or ""


def extract_explicit_port(target: str) -> Optional[int]:
    """取出 URL 里显式写的端口，没有则返回 None。"""
    url = normalize_url(target)
    try:
        return urlsplit(url).port
    except ValueError:
        return None


# ---------------------------------------------------------------------- #
# 探测包编解码
# ---------------------------------------------------------------------- #
def _decode_probe(probe: Optional[str]) -> bytes:
    """把字典里的 probe 字符串转成字节。

    支持 ``\\xNN`` 十六进制字节、``\\r`` ``\\n`` ``\\0`` 转义；
    普通字符按 latin-1 编码（保证二进制 banner 不乱）。
    """
    if not probe:
        return b""
    out = bytearray()
    i, n = 0, len(probe)
    while i < n:
        c = probe[i]
        if c == "\\" and i + 1 < n:
            nxt = probe[i + 1]
            if nxt == "x" and i + 3 < n:
                try:
                    out.append(int(probe[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            elif nxt == "r":
                out.append(0x0D)
                i += 2
                continue
            elif nxt == "n":
                out.append(0x0A)
                i += 2
                continue
            elif nxt == "0":
                out.append(0x00)
                i += 2
                continue
        out.append(ord(c))
        i += 1
    return bytes(out)


def _read_some(sock: socket.socket, limit: int = 4096) -> bytes:
    """读到超时或对端关闭为止，最多 limit 字节。"""
    chunks: List[bytes] = []
    total = 0
    try:
        while total < limit:
            data = sock.recv(1024)
            if not data:
                break
            chunks.append(data)
            total += len(data)
    except (socket.timeout, OSError):
        pass
    return b"".join(chunks)


# ---------------------------------------------------------------------- #
# 单端口探测
# ---------------------------------------------------------------------- #
def _probe_port(
    host: str,
    port: int,
    rule: Optional[dict],
    fallback: dict,
    timeout: float,
) -> Dict:
    """对一个端口做 TCP 连接 + 探测 + 正则识别，返回结构化结果。"""
    result = {
        "port": port, "open": False, "service": None,
        "banner": "", "evidence": [], "ssl": False,
    }

    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
    except (OSError, socket.timeout):
        return result

    result["open"] = True
    banner = b""

    try:
        # 有专属规则：按规则走（可能先 TLS 包裹）
        use_tls = bool(rule and rule.get("ssl"))
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
            result["ssl"] = True

        if rule:
            probe = rule.get("probe")
            if probe:
                sock.sendall(_decode_probe(probe.replace("{host}", host)))
            banner = _read_some(sock)
        else:
            # 无专属规则：先被动等一小会 banner，没有再发通用 HTTP 探测
            banner = _read_some(sock)
            if not banner:
                sock.sendall(_decode_probe(fallback["probe"].replace("{host}", host)))
                banner = _read_some(sock)
    except (OSError, socket.timeout, ssl.SSLError):
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

    text = banner.decode("latin-1", errors="replace")
    result["banner"] = text.strip()[:200]

    # 正则识别：先试专属规则，再试通用 fallback
    matched = None
    rules_to_try = []
    if rule:
        rules_to_try.append(rule)
    rules_to_try.append(fallback)

    for candidate in rules_to_try:
        for pattern in candidate.get("regex", []):
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    matched = candidate
                    break
            except re.error:
                continue
        if matched:
            break

    if matched and matched.get("name"):
        result["service"] = matched.get("name")
        note = matched.get("note")
        result["evidence"].append(f"端口 {port}/tcp 开放")
        result["evidence"].append(
            f"返回数据命中正则，识别为 {matched['name']}"
        )
        if note:
            result["evidence"].append(f"说明：{note}")
    return result


# ---------------------------------------------------------------------- #
# 模块入口
# ---------------------------------------------------------------------- #
def run(
    target: str,
    ports: Optional[List[int]] = None,
    probes: Optional[Dict] = None,
    timeout: float = DEFAULT_TIMEOUT,
    threads: int = DEFAULT_THREADS,
    verbose: bool = False,
) -> List[Finding]:
    """对目标主机做端口与服务探测，返回 Finding 列表。"""
    host = extract_host(target)
    if not host:
        print(f"    [Ports] 无法从目标提取主机名：{target}")
        return []

    probes = probes or load_probes()
    port_map: Dict[int, dict] = probes["map"]
    fallback: dict = probes["fallback"]

    # 决定要扫的端口
    scan_ports: List[int] = list(ports) if ports else list(probes["default"])
    explicit = extract_explicit_port(target)
    if explicit and explicit not in scan_ports:
        scan_ports.append(explicit)
    scan_ports = sorted(set(scan_ports))

    if verbose:
        print(f"    [Ports] 主机 {host}，待扫端口 {len(scan_ports)} 个"
              f"（{scan_ports[0]}-{scan_ports[-1]}）")

    opened: List[Dict] = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {
            pool.submit(_probe_port, host, port, port_map.get(port), fallback, timeout): port
            for port in scan_ports
        }
        for future in as_completed(futures):
            res = future.result()
            if res["open"]:
                opened.append(res)
    opened.sort(key=lambda r: r["port"])

    findings: List[Finding] = []
    for res in opened:
        if verbose:
            print(f"    [Ports] {res['port']}/tcp open"
                  + (f" -> {res['service']}" if res["service"] else "（未识别）"))
        if res["service"]:
            findings.append(Finding(
                module="ports",
                name=res["service"],
                confidence="high",
                score=5,
                evidence=res["evidence"],
                url=f"{host}:{res['port']}",
            ))
        else:
            evidence = [f"端口 {res['port']}/tcp 开放，但未匹配到已知服务"]
            if res["banner"]:
                evidence.append(f"返回数据：{res['banner']}")
            findings.append(Finding(
                module="ports",
                name=f"开放端口 {res['port']}（未识别服务）",
                confidence="low",
                score=1,
                evidence=evidence,
                url=f"{host}:{res['port']}",
            ))
    return findings