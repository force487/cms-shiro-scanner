"""CSRF 检测模块（Cross-Site Request Forgery，跨站请求伪造）。

思路（被动、只读，不主动提交任何改变服务器状态的请求）:
    1. 抓取页面，解析里面所有的 <form> 表单；
    2. 识别“敏感表单”：POST 提交，或 action / 字段名命中了敏感动作词
       （登录、改密、转账、删除、更新资料等）；
    3. 检查表单里有没有 CSRF 防护 token（隐藏字段名匹配 token 特征且值非空）；
    4. 顺带检查会话 Cookie 是否带 SameSite=Strict/Lax 防护；
    5. 敏感表单缺 token -> 判定疑似 CSRF。

只用标准库。不发送任何实际提交请求，避免产生副作用。
"""

import json
import os
import re
from html import unescape
from typing import List, Optional

from .http_client import HttpClient, normalize_url
from .models import Finding

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")

MAX_FORMS = 20

FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
INPUT_RE = re.compile(r"<input\b([^>]*)/?>", re.IGNORECASE)

# 兜底默认值：即使字典缺失也能用
DEFAULT_TOKEN_PATTERNS = ("csrf", "token", "authenticity", "xsrf", "nonce", "anti_forgery")
DEFAULT_SENSITIVE_KEYWORDS = (
    "login", "logout", "password", "passwd", "pwd", "email", "transfer",
    "pay", "order", "delete", "remove", "update", "edit", "profile",
    "account", "setting", "reset", "money", "balance", "admin", "upload",
)


def load_config(path: Optional[str] = None) -> dict:
    """读取 csrf_config.json，返回 {token_patterns, sensitive_keywords}。"""
    path = path or os.path.join(DICT_DIR, "csrf_config.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def _attr(tag: str, name: str) -> str:
    """从一段标签文本里取某个属性的值（优先带引号的写法）。"""
    m = re.search(rf"""{name}\s*=\s*["']([^"']*)["']""", tag or "", re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(rf"""{name}\s*=\s*([^\s"'<>]+)""", tag or "", re.IGNORECASE)
    return m.group(1) if m else ""


def _sensitive_form(method: str, action: str, input_names: List[str],
                    keywords: List[str]) -> bool:
    """判断一个表单是不是会改变状态的敏感动作。"""
    if (method or "").strip().lower() == "post":
        return True
    text = f"{action or ''} {' '.join(input_names)}".lower()
    return any(kw in text for kw in keywords)


def _find_token(inputs: List[dict], patterns: List[str]) -> Optional[str]:
    """在表单输入项里找 CSRF 防护 token，找到返回其字段名。"""
    for inp in inputs:
        name = (inp.get("name") or "").lower()
        if inp.get("type", "").lower() == "hidden" and inp.get("value") \
                and any(p in name for p in patterns):
            return inp["name"]
    return None


def _samesite_note(set_cookies: List[str]) -> str:
    """检查会话 Cookie 是否带 SameSite=Strict/Lax，返回缺失提示。"""
    if not set_cookies:
        return ""
    has_samesite = any(
        re.search(r"samesite\s*=\s*(strict|lax)", c, re.IGNORECASE)
        for c in set_cookies
    )
    return "" if has_samesite else "会话 Cookie 未设置 SameSite=Strict/Lax（缺少 SameSite 防护）"


def run(
    client: HttpClient,
    base_url: str,
    config: dict,
    verbose: bool = False,
) -> List[Finding]:
    """对站点做 CSRF 检测，返回 Finding 列表。"""
    config = config or {}
    patterns = config.get("token_patterns") or list(DEFAULT_TOKEN_PATTERNS)
    keywords = config.get("sensitive_keywords") or list(DEFAULT_SENSITIVE_KEYWORDS)
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [CSRF] 目标不可达，跳过：{home.error or base_url}")
        return []

    forms = FORM_RE.findall(home.body or "")
    if verbose:
        print(f"    [CSRF] 发现 {len(forms)} 个表单")

    findings: List[Finding] = []
    for attrs, inner in forms[:MAX_FORMS]:
        action = unescape(_attr(attrs, "action"))
        method = _attr(attrs, "method") or "get"
        inputs: List[dict] = []
        input_names: List[str] = []
        for m in INPUT_RE.finditer(inner):
            tag = m.group(1)
            name = unescape(_attr(tag, "name"))
            itype = _attr(tag, "type") or "text"
            value = unescape(_attr(tag, "value"))
            inputs.append({"name": name, "type": itype, "value": value})
            if name:
                input_names.append(name)

        if not _sensitive_form(method, action, input_names, keywords):
            continue

        token = _find_token(inputs, patterns)
        if token:
            if verbose:
                print(f"    [CSRF] {method.upper()} {action or '/'} 有防护 token（{token}）")
            continue

        note = _samesite_note(home.set_cookies)
        evidence = [
            f"敏感表单：{method.upper()} {action or '(当前页)'}",
            f"字段：{', '.join(input_names) or '(无命名字段)'}",
        ]
        if note:
            evidence.append(note)
        findings.append(Finding(
            module="csrf",
            name=f"疑似 CSRF（表单 {action or method.upper()}）",
            confidence="high",
            score=9 if note else 8,
            evidence=evidence,
            url=base_url,
        ))
        if verbose:
            print(f"    [CSRF] {method.upper()} {action or '/'} 缺 token -> 疑似 CSRF")

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings