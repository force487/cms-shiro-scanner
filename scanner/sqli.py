"""SQL 注入检测模块（联合查询 + 报错注入）。

思路（沿用本项目“可解释、字典驱动”的风格）：
    1. 抓带参 URL：请求页面，从 <a href> 里把带 ? 的链接都捡出来；
    2. 逐个参数拼接 payload 字典里的测试语句，发请求；
    3. 在响应里搜数据库报错特征（error_patterns），命中即判定该参数疑似可注入。

只依赖标准库，检测以“报错回显”为主、联合查询为辅，不碰 DROP / DELETE 等破坏性语句。
"""

import json
import os
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .http_client import HttpClient, normalize_url
from .models import Finding

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")

# 抓取 / 探测的数量上限，防止请求量失控
MAX_LINKS = 20
MAX_PARAMS = 10
MAX_PAYLOADS = 20

LINK_RE = re.compile(r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)


def load_payloads(path: Optional[str] = None) -> dict:
    """读取 sqli_payloads.json，返回 {error_patterns, payloads}。"""
    path = path or os.path.join(DICT_DIR, "sqli_payloads.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def extract_param_links(html: str, base_url: str) -> List[str]:
    """从 HTML 里提取所有带 ? 的链接（顺带把 base_url 自身也算进去）。"""
    links: List[str] = []
    seen = set()
    base = normalize_url(base_url)
    if "?" in urlsplit(base).query or "?" in base:
        links.append(base)
        seen.add(base)
    for m in LINK_RE.finditer(html or ""):
        raw = m.group(1)
        if "?" not in raw:
            continue
        url = urljoin(base, raw)
        if url not in seen:
            seen.add(url)
            links.append(url)
    return links[:MAX_LINKS]


def get_param_names(url: str) -> List[str]:
    """提取 URL query 里的参数名（保持顺序，含空值参数）。"""
    return [name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]


def inject_param(url: str, param: str, template: str) -> str:
    """把指定参数的值替换成 payload；模板里的 {value} 用原值替换（默认 1）。"""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    new_pairs = [
        (name, template.replace("{value}", value or "1")) if name == param else (name, value)
        for name, value in pairs
    ]
    query = urlencode(new_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def match_errors(response, patterns: List[dict]) -> List[str]:
    """在响应头 + 正文里搜数据库报错特征，返回人话证据列表。"""
    header_text = " ".join(f"{k}: {v}" for k, v in response.headers.items())
    text = (response.body or "") + " " + header_text
    evidence: List[str] = []
    for pat in patterns:
        try:
            if re.search(pat["regex"], text, re.IGNORECASE):
                db = pat.get("db", "")
                evidence.append(f"响应含 {db} 报错特征：{pat['note']}")
        except re.error:
            continue
    return evidence


def run(
    client: HttpClient,
    base_url: str,
    payload_defs: dict,
    verbose: bool = False,
) -> List[Finding]:
    """对站点做 SQL 注入探测，返回 Finding 列表。"""
    payloads = (payload_defs.get("payloads") or [])[:MAX_PAYLOADS]
    patterns = payload_defs.get("error_patterns") or []
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [SQLi] 目标不可达，跳过：{home.error or base_url}")
        return []

    links = extract_param_links(home.body or "", base_url)
    if verbose:
        print(f"    [SQLi] 抓取到 {len(links)} 个带参链接")

    findings: List[Finding] = []
    for url in links:
        for param in get_param_names(url)[:MAX_PARAMS]:
            # 记录该参数命中的第一条 payload 即可，避免刷请求
            hit_name, hit_errors, hit_url = None, [], None
            for payload in payloads:
                injected = inject_param(url, param, payload["template"])
                resp = client.get(injected)
                if verbose:
                    print(f"    [SQLi] {param}={payload['id']:<16} -> "
                          f"{resp.error or 'HTTP ' + str(resp.status)}")
                if not resp.ok:
                    continue
                errs = match_errors(resp, patterns)
                if errs:
                    hit_name, hit_errors, hit_url = payload["name"], errs, injected
                    break
            if hit_name:
                findings.append(Finding(
                    module="sqli",
                    name=f"疑似 SQL 注入（参数 {param}）",
                    confidence="high",
                    score=8,
                    evidence=[f"注入点：{hit_url}",
                              f"payload：{hit_name}"] + hit_errors,
                    url=url,
                ))

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings