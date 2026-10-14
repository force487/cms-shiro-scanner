"""CMS 指纹识别模块。

流程（三步）：
    1. 取首页响应 → 用字典里所有规则跑一遍核心匹配函数
    2. 对已命中的规则，再请求它指定的特征路径（如 /wp-login.php）做二次确认
    3. 汇总成 Finding 列表，按分数从高到低返回
"""

from typing import List, Optional

from .fingerprint import confidence_of, describe, match_response, score_of
from .http_client import HttpClient, join_url
from .models import Finding

# 低于这个分数就不输出，避免“正文出现一个 php 就判定成 CMS”这种误报
MIN_SCORE = 2


def run(
    client: HttpClient,
    base_url: str,
    rules: List[dict],
    min_score: int = MIN_SCORE,
    verbose: bool = False,
) -> List[Finding]:
    """对一个站点执行 CMS 指纹识别。"""
    findings: List[Finding] = []

    home = client.get(base_url)
    if verbose:
        print(f"    [CMS] 首页 {base_url} -> HTTP {home.status}"
              f" ({len(home.body)} 字节)")

    if not home.ok:
        print(f"    [CMS] 首页请求失败：{home.error or 'HTTP ' + str(home.status)}")
        return findings

    for rule in rules:
        evidence = match_response(rule, home)

        # 已经有命中，且规则带特征路径 -> 二次确认，提高准确率
        path = rule.get("path")
        if evidence and path:
            probe = client.get(join_url(base_url, path))
            probe_body = (probe.body or "").lower()
            for keyword in rule.get("path_body", []) or []:
                if keyword.lower() in probe_body:
                    evidence.append(
                        ("path", f"特征路径 {path} 命中 “{keyword}”", 2)
                    )
            if verbose and probe.ok:
                print(f"    [CMS] 二次确认 {path} -> HTTP {probe.status}")

        score = score_of(evidence)
        if score < min_score:
            continue

        findings.append(
            Finding(
                module="cms",
                name=f"{rule.get('name', rule.get('id', 'unknown'))}"
                     f"（{rule.get('category', '未知')}）",
                confidence=confidence_of(score),
                score=score,
                evidence=describe(evidence),
                url=home.url,
            )
        )

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings
