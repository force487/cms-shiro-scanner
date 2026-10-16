"""安全响应头检查模块（基线配置检查）。

只读检查：读取目标响应头，对照常见安全响应头规则，报告缺失或配置较弱的项。
不发送任何攻击载荷，属于配置合规类检查。

规则字典 security_headers.json，每条包含：
    name     响应头名（小写）
    label    中文名称
    score    缺失时的分数（危害级别）
    note     说明
    expected 可选，合法值列表；存在但不在列表内则判定“配置较弱”
"""

import json
import os
from typing import List, Optional

from .http_client import HttpClient, normalize_url
from .models import Finding

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")


def load_headers(path: Optional[str] = None) -> List[dict]:
    """读取 security_headers.json，返回规则列表。"""
    path = path or os.path.join(DICT_DIR, "security_headers.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp).get("headers", [])


def run(
    client: HttpClient,
    base_url: str,
    rules: List[dict],
    verbose: bool = False,
) -> List[Finding]:
    """检查目标的安全响应头，返回 Finding 列表。"""
    rules = list(rules)
    base_url = normalize_url(base_url)

    resp = client.get(base_url)
    if not resp.ok:
        print(f"    [响应头] 目标不可达，跳过：{resp.error or base_url}")
        return []

    findings: List[Finding] = []
    for rule in rules:
        name = rule.get("name", "")
        label = rule.get("label", name)
        score = rule.get("score", 2)
        value = resp.header(name)
        expected = rule.get("expected", [])

        if not value:
            if verbose:
                print(f"    [响应头] 缺失 {name}")
            findings.append(Finding(
                module="headers",
                name=f"缺失 {label}",
                confidence="high",
                score=score,
                evidence=[f"响应头未包含 {name}", rule.get("note", "")],
            ))
        elif expected and value.lower() not in [e.lower() for e in expected]:
            if verbose:
                print(f"    [响应头] {name} 较弱：{value}")
            findings.append(Finding(
                module="headers",
                name=f"{label} 配置较弱",
                confidence="high",
                score=max(1, score - 1),
                evidence=[f"当前值：{value}", rule.get("note", "")],
            ))

    if verbose and not findings:
        print("    [响应头] 未发现缺失或较弱的安全响应头")

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings