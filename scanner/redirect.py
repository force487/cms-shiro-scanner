"""开放重定向（Open Redirect）检测模块。

思路：
    1. 抓带参链接，找“跳转类”参数（url / redirect / next / target 等）；
    2. 往这些参数注入外部测试域名；
    3. 关闭重定向跟随发起请求，看响应 Location 是否指向注入的域名；
    4. 指向即为开放重定向。

只用标准库。测试域名默认是 evil-example.com（保留域名），可通过 --redirect-dict
换成自己的回调域名。
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

# 常见“跳转目标”参数名
REDIRECT_PARAM_KEYWORDS = (
    "url", "uri", "link", "redirect", "redirect_uri", "redirect_url",
    "next", "return", "return_to", "return_url", "target", "goto",
    "goto_url", "dest", "destination", "continue", "forward", "callback",
    "jump", "location", "returnurl", "redir",
)


def load_payloads(path: Optional[str] = None) -> List[dict]:
    """读取 redirect_payloads.json，返回 payload 列表。"""
    path = path or os.path.join(DICT_DIR, "redirect_payloads.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp).get("payloads", [])


def is_redirect_param(name: str) -> bool:
    """判断参数名是否像“跳转目标”参数。"""
    lowered = (name or "").lower()
    return any(kw in lowered for kw in REDIRECT_PARAM_KEYWORDS)


def run(
    client: HttpClient,
    base_url: str,
    payloads: List[dict],
    verbose: bool = False,
) -> List[Finding]:
    """对站点做开放重定向探测，返回 Finding 列表。"""
    payloads = list(payloads)[:MAX_PAYLOADS]
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [重定向] 目标不可达，跳过：{home.error or base_url}")
        return []

    links = extract_param_links(home.body or "", base_url)
    if verbose:
        print(f"    [重定向] 抓取到 {len(links)} 个带参链接")

    findings: List[Finding] = []
    for url in links:
        for param in get_param_names(url)[:MAX_PARAMS]:
            if not is_redirect_param(param):
                continue
            for payload in payloads:
                injected = inject_param(url, param, payload["url"])
                resp = client.get(injected, follow_redirect=False)
                if verbose:
                    print(f"    [重定向] {param}={payload['id']:<16} -> "
                          f"{resp.error or 'HTTP ' + str(resp.status)}")
                location = resp.header("Location")
                if location and payload.get("check", "") \
                        and payload["check"] in location.lower():
                    findings.append(Finding(
                        module="redirect",
                        name=f"疑似开放重定向（参数 {param}）",
                        confidence="high",
                        score=7,
                        evidence=[f"注入点：{injected}",
                                  f"响应跳转 Location -> {location}",
                                  f"payload：{payload['name']}"],
                        url=url,
                    ))
                    break

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings