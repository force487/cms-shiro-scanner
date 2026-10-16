"""命令注入检测模块（回显型，OS Command Injection）。

思路（与 SQLi / XSS 模块对称）：
    1. 抓带参 URL：请求页面，从 <a href> 里捡带 ? 的链接；
    2. 逐个参数注入命令拼接 payload（; echo、| echo、$(echo) 等），
       每条 payload 都带一个唯一随机标记 marker；
    3. 看响应里是否原样反射 marker —— marker 出现说明注入的命令被执行且输出回显了。

marker 用随机字符串，避免把页面里本来就有的 uid= / root: 之类误判成回显。
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

MAX_PARAMS = 10
MAX_PAYLOADS = 20


def load_payloads(path: Optional[str] = None) -> List[dict]:
    """读取 rce_payloads.json，返回 payload 列表。"""
    path = path or os.path.join(DICT_DIR, "rce_payloads.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp).get("payloads", [])


def make_marker(length: int = 8) -> str:
    """生成随机标记，用于判断注入的命令是否真的被执行并回显。"""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def run(
    client: HttpClient,
    base_url: str,
    payloads: List[dict],
    verbose: bool = False,
) -> List[Finding]:
    """对站点做命令注入探测，返回 Finding 列表。"""
    payloads = list(payloads)[:MAX_PAYLOADS]
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [RCE] 目标不可达，跳过：{home.error or base_url}")
        return []

    links = extract_param_links(home.body or "", base_url)
    if verbose:
        print(f"    [RCE] 抓取到 {len(links)} 个带参链接")

    marker = make_marker()
    findings: List[Finding] = []
    for url in links:
        for param in get_param_names(url)[:MAX_PARAMS]:
            hit_name, hit_url = None, None
            for payload in payloads:
                template = payload["template"].replace("{marker}", marker)
                injected = inject_param(url, param, template)
                resp = client.get(injected)
                if verbose:
                    print(f"    [RCE] {param}={payload['id']:<14} -> "
                          f"{resp.error or 'HTTP ' + str(resp.status)}")
                body = resp.body or ""
                # 命令执行的输出只有 marker；而参数被原样反射时，
                # 注入关键字面量（如 echo）会跟着一起出现，据此排除反射干扰
                exclude = payload.get("exclude", "echo")
                if marker in body and exclude not in body:
                    hit_name, hit_url = payload["name"], injected
                    break
            if hit_name:
                findings.append(Finding(
                    module="rce",
                    name=f"疑似命令注入（参数 {param}）",
                    confidence="high",
                    score=8,
                    evidence=[f"注入点：{hit_url}",
                              f"payload：{hit_name}",
                              "注入的命令被执行且输出回显了标记"],
                    url=url,
                ))

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings