"""XXE 检测模块（XML External Entity Injection，XML 外部实体注入）。

思路（回显型、只读探测）:
    1. 找可能接收 XML 的入口：站点根 URL + 页面里 <form> 的 POST action；
    2. 向这些入口 POST 一个带外部实体的 XML payload；
    3. 若响应回显了目标资源特征（如 /etc/passwd 的 root:），判定存在 XXE。

只用标准库。payload 指向本地只读文件，不做破坏性操作，也不做带外回调探测。
"""

import json
import os
import re
from typing import List, Optional
from urllib.parse import urljoin

from .http_client import HttpClient, normalize_url
from .models import Finding

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")

MAX_TARGETS = 10
MAX_PAYLOADS = 10

FORM_ACTION_RE = re.compile(
    r"<form\b[^>]*?\baction\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)


def load_payloads(path: Optional[str] = None) -> List[dict]:
    """读取 xxe_payloads.json，返回 payload 列表。"""
    path = path or os.path.join(DICT_DIR, "xxe_payloads.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp).get("payloads", [])


def _candidate_targets(html: str, base_url: str) -> List[str]:
    """收集可能接收 XML 的入口：根 URL + 页面里的表单 action。"""
    targets: List[str] = [normalize_url(base_url)]
    seen = {targets[0]}
    for m in FORM_ACTION_RE.finditer(html or ""):
        url = urljoin(base_url, m.group(1))
        if url not in seen:
            seen.add(url)
            targets.append(url)
    return targets[:MAX_TARGETS]


def run(
    client: HttpClient,
    base_url: str,
    payloads: List[dict],
    verbose: bool = False,
) -> List[Finding]:
    """对站点做 XXE 探测，返回 Finding 列表。"""
    payloads = list(payloads)[:MAX_PAYLOADS]
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [XXE] 目标不可达，跳过：{home.error or base_url}")
        return []

    targets = _candidate_targets(home.body or "", base_url)
    if verbose:
        print(f"    [XXE] 候选 XML 入口 {len(targets)} 个")

    findings: List[Finding] = []
    for target in targets:
        for payload in payloads:
            resp = client.post_raw(target, payload["body"], content_type="application/xml")
            if verbose:
                print(f"    [XXE] {target:<40} <- {payload['id']:<12} -> "
                      f"{resp.error or 'HTTP ' + str(resp.status)}")
            body = resp.body or ""
            if payload.get("check", "") and payload["check"] in body:
                findings.append(Finding(
                    module="xxe",
                    name=f"疑似 XXE（{target}）",
                    confidence="high",
                    score=8,
                    evidence=[f"入口：{target}",
                              f"payload：{payload['name']}",
                              f"响应回显了资源特征：{payload['check']}"],
                    url=target,
                ))
                break

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings