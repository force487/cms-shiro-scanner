"""HTTP 参数污染（HPP）检测模块。

思路：
    1. 抓带参链接，对每个参数构造“重复参数”注入：在原 query 末尾追加同名参数，
       值是一个随机 marker；
    2. 看响应正文里是否出现了这个 marker —— 出现说明后端接收并采用了
       重复参数的第二个值（或把重复参数拼接），存在参数污染。

只用标准库。marker 用随机串，避免与页面正常内容冲突。
"""

import json
import os
import uuid
from typing import List, Optional
from urllib.parse import urlsplit, urlunsplit

from .http_client import HttpClient, normalize_url
from .models import Finding
from .sqli import extract_param_links, get_param_names

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")

MAX_PARAMS = 10


def load_config(path: Optional[str] = None) -> dict:
    """读取 hpp_config.json，返回配置（含 marker_prefix）。"""
    path = path or os.path.join(DICT_DIR, "hpp_config.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def append_param(url: str, param: str, value: str) -> str:
    """在原 query 末尾追加一个同名参数，构造重复参数。"""
    parts = urlsplit(url)
    extra = f"{param}={value}"
    new_query = f"{parts.query}&{extra}" if parts.query else extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def run(
    client: HttpClient,
    base_url: str,
    config: dict,
    verbose: bool = False,
) -> List[Finding]:
    """对站点做 HTTP 参数污染探测，返回 Finding 列表。"""
    config = config or {}
    prefix = config.get("marker_prefix", "hppmarker")
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [HPP] 目标不可达，跳过：{home.error or base_url}")
        return []

    links = extract_param_links(home.body or "", base_url)
    if verbose:
        print(f"    [HPP] 抓取到 {len(links)} 个带参链接")

    findings: List[Finding] = []
    for url in links:
        for param in get_param_names(url)[:MAX_PARAMS]:
            marker = f"{prefix}{uuid.uuid4().hex[:10]}"
            injected = append_param(url, param, marker)
            resp = client.get(injected, follow_redirect=False)
            if verbose:
                print(f"    [HPP] {param} 重复注入 -> "
                      f"{resp.error or 'HTTP ' + str(resp.status)}")
            body = (resp.body or "").lower()
            if marker in body:
                findings.append(Finding(
                    module="hpp",
                    name=f"疑似 HTTP 参数污染（参数 {param}）",
                    confidence="medium",
                    score=5,
                    evidence=[f"注入点：{injected}",
                              f"重复参数的第二个值（marker）被后端采用并回显"],
                    url=url,
                ))

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings