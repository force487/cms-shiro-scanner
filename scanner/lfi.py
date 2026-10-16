"""文件包含 / 路径穿越检测模块（LFI / Local File Inclusion）。

思路（与 SQLi / RCE 模块对称）：
    1. 抓带参 URL：请求页面，从 <a href> 里捡带 ? 的链接；
    2. 逐个参数拼接路径穿越 payload（../../etc/passwd 等）；
    3. 看响应里是否出现目标文件的特征内容（root: 等）—— 命中即判定存在文件包含。

只依赖标准库，只用只读文件特征（/etc/passwd、win.ini、/etc/hosts），不做任何写操作。
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


def load_payloads(path: Optional[str] = None) -> List[dict]:
    """读取 lfi_payloads.json，返回 payload 列表。"""
    path = path or os.path.join(DICT_DIR, "lfi_payloads.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp).get("payloads", [])


def run(
    client: HttpClient,
    base_url: str,
    payloads: List[dict],
    verbose: bool = False,
) -> List[Finding]:
    """对站点做文件包含探测，返回 Finding 列表。"""
    payloads = list(payloads)[:MAX_PAYLOADS]
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [LFI] 目标不可达，跳过：{home.error or base_url}")
        return []

    links = extract_param_links(home.body or "", base_url)
    if verbose:
        print(f"    [LFI] 抓取到 {len(links)} 个带参链接")

    findings: List[Finding] = []
    for url in links:
        for param in get_param_names(url)[:MAX_PARAMS]:
            for payload in payloads:
                injected = inject_param(url, param, payload["template"])
                resp = client.get(injected)
                if verbose:
                    print(f"    [LFI] {param}={payload['id']:<14} -> "
                          f"{resp.error or 'HTTP ' + str(resp.status)}")
                body = resp.body or ""
                if payload.get("check", "") and payload["check"] in body:
                    findings.append(Finding(
                        module="lfi",
                        name=f"疑似文件包含（参数 {param}）",
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