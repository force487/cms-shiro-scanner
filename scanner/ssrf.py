"""SSRF 检测模块（Server-Side Request Forgery，服务端请求伪造）。

思路（复用参数注入框架）：
    1. 抓带参 URL：请求页面，从 <a href> 里捡带 ? 的链接；
    2. 找出“URL 类参数”（url / link / src / redirect 等常见发起请求的参数名）；
    3. 注入内网探测 payload（回环地址、云元数据服务等），每条带特征 check；
    4. 看响应是否回显目标内网资源的特征指纹 —— 命中即判定 SSRF。

只用标准库。探测 payload 指向只读的本地/元数据资源，不做任何破坏性操作。
"""

import json
import os
from typing import List, Optional

from .http_client import HttpClient, normalize_url
from .models import Finding
from .sqli import extract_param_links, get_param_names, inject_param

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")

MAX_PARAMS = 10
MAX_PAYLOADS = 20

# 常见“服务端发起请求”的参数名
URL_PARAM_KEYWORDS = (
    "url", "link", "uri", "src", "href", "redirect", "redirect_uri",
    "next", "target", "path", "file", "image", "img", "domain", "host",
    "callback", "webhook", "proxy", "feed", "load", "fetch", "download",
)


def load_payloads(path: Optional[str] = None) -> List[dict]:
    """读取 ssrf_payloads.json，返回 payload 列表。"""
    path = path or os.path.join(DICT_DIR, "ssrf_payloads.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp).get("payloads", [])


def is_url_param(name: str) -> bool:
    """判断参数名是否像“触发服务端请求”的参数。"""
    lowered = (name or "").lower()
    return any(kw in lowered for kw in URL_PARAM_KEYWORDS)


def run(
    client: HttpClient,
    base_url: str,
    payloads: List[dict],
    verbose: bool = False,
) -> List[Finding]:
    """对站点做 SSRF 探测，返回 Finding 列表。"""
    payloads = list(payloads)[:MAX_PAYLOADS]
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [SSRF] 目标不可达，跳过：{home.error or base_url}")
        return []

    links = extract_param_links(home.body or "", base_url)
    if verbose:
        print(f"    [SSRF] 抓取到 {len(links)} 个带参链接")

    findings: List[Finding] = []
    for url in links:
        for param in get_param_names(url)[:MAX_PARAMS]:
            if not is_url_param(param):
                continue
            for payload in payloads:
                injected = inject_param(url, param, payload["template"])
                resp = client.get(injected)
                if verbose:
                    print(f"    [SSRF] {param}={payload['id']:<14} -> "
                          f"{resp.error or 'HTTP ' + str(resp.status)}")
                body = resp.body or ""
                if payload.get("check", "") and payload["check"] in body:
                    findings.append(Finding(
                        module="ssrf",
                        name=f"疑似 SSRF（参数 {param}）",
                        confidence="high",
                        score=8,
                        evidence=[f"注入点：{injected}",
                                  f"payload：{payload['name']}",
                                  f"响应回显了内网资源特征：{payload['check']}"],
                        url=url,
                    ))
                    break

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings