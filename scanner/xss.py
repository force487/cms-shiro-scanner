"""XSS 检测模块（反射型）。

思路（与 SQLi 模块对称）：
    1. 抓带参 URL：请求页面，从 <a href> 里捡带 ? 的链接；
    2. 逐个参数注入带唯一标记（marker）的 payload；
    3. 看响应里是否原样反射：marker 出现，且标签没有被 HTML 转义（判断 < 是否还在）。

marker 用随机字符串，避免把页面里本来就有的 alert 之类误判成回显。
"""

import json
import os
import random
import string
from typing import List, Optional

from .http_client import HttpClient, normalize_url
from .models import Finding
from .sqli import extract_param_links, get_param_names, inject_param

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")

MAX_LINKS = 20
MAX_PARAMS = 10
MAX_PAYLOADS = 20


def load_payloads(path: Optional[str] = None) -> List[dict]:
    """读取 xss_payloads.json，返回 payload 列表。"""
    path = path or os.path.join(DICT_DIR, "xss_payloads.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp).get("payloads", [])


def make_marker(length: int = 8) -> str:
    """生成一个随机标记，用于判断 payload 是否真的被原样反射回来。"""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def run(
    client: HttpClient,
    base_url: str,
    payloads: List[dict],
    verbose: bool = False,
) -> List[Finding]:
    """对站点做反射型 XSS 探测，返回 Finding 列表。"""
    payloads = list(payloads)[:MAX_PAYLOADS]
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [XSS] 目标不可达，跳过：{home.error or base_url}")
        return []

    links = extract_param_links(home.body or "", base_url)
    if verbose:
        print(f"    [XSS] 抓取到 {len(links)} 个带参链接")

    marker = make_marker()
    findings: List[Finding] = []
    for url in links:
        for param in get_param_names(url)[:MAX_PARAMS]:
            hit_name, hit_url = None, None
            for payload in payloads:
                template = payload["template"].replace("{marker}", marker)
                injected = inject_param(url, param, template)
                resp = client.get(injected)
                body = resp.body or ""
                if verbose:
                    print(f"    [XSS] {param}={payload['id']:<14} -> "
                          f"{resp.error or 'HTTP ' + str(resp.status)}")
                # 判定：marker 被反射回来，且标签尖括号未被转义
                if marker in body and payload.get("check", "") in body:
                    hit_name, hit_url = payload["name"], injected
                    break
            if hit_name:
                findings.append(Finding(
                    module="xss",
                    name=f"疑似反射型 XSS（参数 {param}）",
                    confidence="high",
                    score=8,
                    evidence=[f"注入点：{hit_url}",
                              f"payload：{hit_name}",
                              "payload 被原样反射且标签未被 HTML 转义"],
                    url=url,
                ))

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings