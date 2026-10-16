"""CRLF 注入检测模块（HTTP 响应头注入 / 响应拆分）。

思路：
    1. 抓带参链接，找可能被反射进响应头的参数（跳转 / Cookie 类）；
    2. 往这些参数注入 %0d%0a（CRLF）+ 伪造响应头；
    3. 看响应里是否出现了被注入的伪造响应头（如 X-CRLF-Test）；
    4. 出现即为 CRLF 注入。

只用标准库。payload 只注入无害的自定义响应头，不做真正的响应拆分演示。
"""

import json
import os
from typing import List, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .http_client import HttpClient, normalize_url
from .models import Finding
from .sqli import extract_param_links, get_param_names

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")

MAX_PARAMS = 10
MAX_PAYLOADS = 20

# 常见“可能反射进响应头”的参数名（跳转 / Cookie 相关）
CRLF_PARAM_KEYWORDS = (
    "url", "uri", "link", "redirect", "redirect_uri", "redirect_url",
    "next", "return", "return_to", "return_url", "target", "goto",
    "goto_url", "dest", "destination", "forward", "callback", "jump",
    "location", "cookie", "path", "ref", "rurl",
)


def load_payloads(path: Optional[str] = None) -> List[dict]:
    """读取 crlf_payloads.json，返回 payload 列表。"""
    path = path or os.path.join(DICT_DIR, "crlf_payloads.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp).get("payloads", [])


def is_crlf_param(name: str) -> bool:
    """判断参数名是否像“可能反射进响应头”的参数。"""
    lowered = (name or "").lower()
    return any(kw in lowered for kw in CRLF_PARAM_KEYWORDS)


def inject_crlf(url: str, param: str, value: str) -> str:
    """把参数值替换成注入值，保留 %0d%0a 不被二次 URL 编码。"""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    new_pairs = [(n, value) if n == param else (n, v) for n, v in pairs]
    query = "&".join(f"{n}={v}" for n, v in new_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _header_hit(resp, payload: dict) -> bool:
    """检查响应里是否出现了被注入的伪造响应头或 Set-Cookie。"""
    header_name = payload.get("check_header", "").lower()
    check_value = payload.get("check_value", "").lower()
    if not header_name or not check_value:
        return False
    if check_value in resp.header(header_name).lower():
        return True
    for cookie in resp.set_cookies:
        if check_value in cookie.lower():
            return True
    return False


def run(
    client: HttpClient,
    base_url: str,
    payloads: List[dict],
    verbose: bool = False,
) -> List[Finding]:
    """对站点做 CRLF 注入探测，返回 Finding 列表。"""
    payloads = list(payloads)[:MAX_PAYLOADS]
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [CRLF] 目标不可达，跳过：{home.error or base_url}")
        return []

    links = extract_param_links(home.body or "", base_url)
    if verbose:
        print(f"    [CRLF] 抓取到 {len(links)} 个带参链接")

    findings: List[Finding] = []
    for url in links:
        for param in get_param_names(url)[:MAX_PARAMS]:
            if not is_crlf_param(param):
                continue
            for payload in payloads:
                injected = inject_crlf(url, param, payload["value"])
                resp = client.get(injected, follow_redirect=False)
                if verbose:
                    print(f"    [CRLF] {param}={payload['id']:<14} -> "
                          f"{resp.error or 'HTTP ' + str(resp.status)}")
                if _header_hit(resp, payload):
                    findings.append(Finding(
                        module="crlf",
                        name=f"疑似 CRLF 注入（参数 {param}）",
                        confidence="high",
                        score=7,
                        evidence=[f"注入点：{injected}",
                                  f"响应出现了被注入的响应头："
                                  f"{payload['check_header']}: {payload['check_value']}"],
                        url=url,
                    ))
                    break

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings