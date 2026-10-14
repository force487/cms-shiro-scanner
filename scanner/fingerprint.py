"""核心功能：字典匹配引擎。

这是整个扫描器最关键的一个文件 —— “检测响应”的通用函数就放在这里：

    match_response(rule, response) -> 命中证据列表
    score_of(evidence)             -> 权重总分
    confidence_of(score)           -> high / medium / low

CMS 模块和 Shiro 模块都复用这套逻辑，区别只是喂进来的字典不同。
"""

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from .models import HttpResponse

# 字典里每一类匹配方式的权重，权重越高说明该特征越“硬”
WEIGHTS: Dict[str, int] = {
    "header": 3,   # 响应头命中（如 Server: nginx、X-Powered-By: ThinkPHP）
    "cookie": 3,   # Set-Cookie 命中（如 wordpress_、JSESSIONID）
    "regex": 2,    # 正文正则命中（比纯关键字更精确）
    "path": 2,     # 二次探测路径的响应命中
    "body": 1,     # 正文关键字命中（最容易误报，权重最低）
    "status": 1,   # 状态码命中
}

# 证据元组：(类型, 证据描述, 权重)
Evidence = Tuple[str, str, int]

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")


# ---------------------------------------------------------------------- #
# 字典读取
# ---------------------------------------------------------------------- #
def load_rules(path: Optional[str] = None) -> List[dict]:
    """读取 CMS 指纹字典（JSON 数组）。"""
    path = path or os.path.join(DICT_DIR, "cms_rules.json")
    with open(path, "r", encoding="utf-8") as fp:
        rules = json.load(fp)
    if not isinstance(rules, list):
        raise ValueError(f"字典格式错误，应为 JSON 数组: {path}")
    return rules


def load_wordlist(path: Optional[str] = None) -> List[str]:
    """读取纯文本字典（一行一条，# 开头为注释）。"""
    path = path or os.path.join(DICT_DIR, "shiro_paths.txt")
    words: List[str] = []
    with open(path, "r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
    return words


# ---------------------------------------------------------------------- #
# 核心匹配函数
# ---------------------------------------------------------------------- #
def match_response(rule: dict, response: HttpResponse) -> List[Evidence]:
    """用一条字典规则去匹配一条 HTTP 响应，返回所有命中的证据。

    规则结构（JSON 里的字段都是可选的）::

        {
          "id": "wordpress",
          "name": "WordPress",
          "category": "CMS",
          "match": {
              "body":    ["wp-content", "wp-includes"],
              "regex":   ["<meta name=\"generator\" content=\"WordPress"],
              "headers": {"x-powered-by": "PHP"},
              "cookies": ["wordpress_"],
              "status":  [200]
          },
          "path": "/wp-login.php",
          "path_body": ["wp-submit"]
        }
    """
    if not response.ok:
        return []

    hits: List[Evidence] = []
    matcher = rule.get("match", {}) or {}
    body = (response.body or "").lower()

    # 1) 正文关键字
    for keyword in matcher.get("body", []) or []:
        if keyword.lower() in body:
            hits.append(("body", f"正文含关键字 “{keyword}”", WEIGHTS["body"]))

    # 2) 正文正则
    for pattern in matcher.get("regex", []) or []:
        try:
            if re.search(pattern, response.body or "", re.IGNORECASE | re.DOTALL):
                hits.append(("regex", f"正文匹配正则 {pattern}", WEIGHTS["regex"]))
        except re.error:
            continue

    # 3) 响应头
    for name, expect in (matcher.get("headers", {}) or {}).items():
        actual = response.header(name)
        if actual and expect.lower() in actual.lower():
            hits.append(("header", f"响应头 {name}: {actual}", WEIGHTS["header"]))

    # 4) Set-Cookie
    cookie_text = response.set_cookie_text().lower()
    for token in matcher.get("cookies", []) or []:
        if token.lower() in cookie_text:
            hits.append(("cookie", f"Set-Cookie 含 “{token}”", WEIGHTS["cookie"]))

    # 5) 状态码
    for code in matcher.get("status", []) or []:
        if response.status == int(code):
            hits.append(("status", f"状态码为 {code}", WEIGHTS["status"]))

    return hits


def score_of(evidence: List[Evidence]) -> int:
    """把命中证据换算成总分。"""
    return sum(item[2] for item in evidence)


def confidence_of(score: int) -> str:
    """按总分给出置信度：>=5 高，>=3 中，>=1 低。"""
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    if score >= 1:
        return "low"
    return "none"


def describe(evidence: List[Evidence]) -> List[str]:
    """把证据元组转成人类可读的字符串列表。"""
    return [f"[{kind}] {text}" for kind, text, _ in evidence]
