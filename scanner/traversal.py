"""路径遍历 / 目录穿越检测模块（Path Traversal）。

与 LFI 模块的区别：本模块聚焦“文件读取 / 下载”类接口，先按参数名识别
可能承载文件路径的参数（file/path/filename/... 见字典 path_params），只对这类
参数注入目录穿越 payload，避免对无关参数（如 id、q、host）盲目发包，减少误报。

思路：
    1. 抓带参 URL：请求页面，从 <a href> 里捡带 ? 的链接；
    2. 逐个参数判断是否命中路径参数特征；
    3. 对命中参数拼接目录穿越 payload（../../etc/passwd、..\\windows\\win.ini 等）；
    4. 看响应是否回显目标文件的特征内容（root: / for 16-bit 等）—— 命中即判定存在路径穿越。

只依赖标准库，只用只读文件特征，不做任何写操作。
"""

import json
import os
from typing import Dict, List, Optional

from .http_client import HttpClient, normalize_url
from .models import Finding
from .sqli import extract_param_links, get_param_names, inject_param

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")

MAX_LINKS = 20
MAX_PARAMS = 10
MAX_PAYLOADS = 20


def load_payloads(path: Optional[str] = None) -> dict:
    """读取 traversal_payloads.json，返回 {path_params, payloads}。"""
    path = path or os.path.join(DICT_DIR, "traversal_payloads.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def is_path_param(param: str, path_params: List[str]) -> bool:
    """判断参数名是否像文件路径参数（子串匹配，忽略大小写）。"""
    p = param.lower()
    return any(k and k in p for k in path_params)


def run(
    client: HttpClient,
    base_url: str,
    config: dict,
    verbose: bool = False,
) -> List[Finding]:
    """对站点做路径遍历探测，返回 Finding 列表。"""
    path_params = [k.lower() for k in (config.get("path_params") or [])]
    payloads = (config.get("payloads") or [])[:MAX_PAYLOADS]
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [路径遍历] 目标不可达，跳过：{home.error or base_url}")
        return []

    links = extract_param_links(home.body or "", base_url)[:MAX_LINKS]
    if verbose:
        print(f"    [路径遍历] 抓取到 {len(links)} 个带参链接，"
              f"路径参数特征 {len(path_params)} 个")

    findings: List[Finding] = []
    for url in links:
        for param in get_param_names(url)[:MAX_PARAMS]:
            if not is_path_param(param, path_params):
                continue
            for payload in payloads:
                injected = inject_param(url, param, payload["template"])
                resp = client.get(injected)
                if verbose:
                    print(f"    [路径遍历] {param}={payload['id']:<18} -> "
                          f"{resp.error or 'HTTP ' + str(resp.status)}")
                body = resp.body or ""
                if payload.get("check", "") and payload["check"] in body:
                    findings.append(Finding(
                        module="traversal",
                        name=f"疑似路径遍历（参数 {param}）",
                        confidence="high",
                        score=8,
                        evidence=[f"注入点：{injected}",
                                  f"payload：{payload['name']}",
                                  f"响应回显了目标文件特征：{payload['check']}"],
                        url=url,
                    ))
                    break

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings