"""Apache Shiro 探测模块。

两种探测手段：
    1. rememberMe=deleteMe 主动探测：带 Cookie: rememberMe=deleteMe 请求，
       若响应 Set-Cookie 里回显 rememberMe=deleteMe，基本可以确认后端用了 Shiro。
    2. 目录路径探测：拿 shiro_paths.txt 字典逐个访问受保护路径，同样带
       deleteMe Cookie，观察每一跳是否有 Shiro 特征回显。

另外会顺带做一次“被动特征匹配”：在响应头 / 正文里搜 Shiro 的类名、Cookie 名，
作为辅助证据（置信度较低，仅供参考）。
"""

from typing import Dict, List

from .fingerprint import confidence_of
from .http_client import HttpClient, join_url
from .models import Finding, HttpResponse

DELETE_ME_COOKIE = {"rememberMe": "deleteMe"}

# 被动匹配用的 Shiro 特征关键字（全部小写）
SHIRO_TOKENS = [
    "org.apache.shiro",
    "shirofilterfactorybean",
    "shirofilter",
    "delegatingfilterproxy",
    "rememberme",
    "shiro.loginurl",
]


def _passive_hits(response: HttpResponse) -> List[str]:
    """在一条响应里找 Shiro 的被动特征。"""
    hits: List[str] = []
    header_text = " ".join(f"{k}: {v}" for k, v in response.headers.items()).lower()
    body = (response.body or "").lower()

    for token in SHIRO_TOKENS:
        if token in header_text:
            hits.append(f"响应头含特征 “{token}”")
        elif token in body:
            hits.append(f"正文含特征 “{token}”")
    return hits


def probe_one(client: HttpClient, url: str, verbose: bool = False) -> Dict:
    """对单个 URL 做一次 deleteMe 探测，返回结构化结果。

    这里必须关闭重定向跟随：真实站点命中 deleteMe 时通常是
    “302 + Set-Cookie: rememberMe=deleteMe -> 跳转登录页”，
    如果跟着跳转走，302 上的那个 Set-Cookie 就丢了，判断会失效。
    """
    resp = client.get(url, cookies=DELETE_ME_COOKIE, follow_redirect=False)
    if verbose:
        print(f"    [Shiro] {url} -> {resp.error or 'HTTP ' + str(resp.status)}")

    if not resp.ok:
        return {"url": url, "status": resp.status, "confirmed": False,
                "evidence": [], "error": resp.error}

    confirmed = resp.is_shiro_delete_me()
    evidence = ["响应 Set-Cookie 回显 rememberMe=deleteMe"] if confirmed \
        else _passive_hits(resp)
    return {"url": url, "status": resp.status, "confirmed": confirmed,
            "evidence": evidence, "error": ""}


def probe_paths(
    client: HttpClient,
    base_url: str,
    paths: List[str],
    verbose: bool = False,
) -> List[Dict]:
    """用字典逐条探测目录路径，返回每个路径的探测结果。"""
    results: List[Dict] = []
    for path in paths:
        item = probe_one(client, join_url(base_url, path), verbose=verbose)
        item["path"] = path
        results.append(item)
    return results


def run(
    client: HttpClient,
    base_url: str,
    paths: List[str],
    verbose: bool = False,
) -> List[Finding]:
    """对一个站点执行 Shiro 探测，并把结果聚合成少量结论。"""
    findings: List[Finding] = []

    # 第 1 步：直接对首页发 deleteMe 探测
    home = probe_one(client, base_url, verbose=verbose)
    if home["error"]:
        # 首页都连不上，就没必要把整个路径字典都跑一遍了
        print(f"    [Shiro] 目标不可达，跳过路径字典探测：{home['error']}")
        return findings
    # 第 2 步：目录路径字典探测
    probes = probe_paths(client, base_url, paths, verbose=verbose)

    confirmed = [p for p in probes if p["confirmed"]]
    passive_only = [p for p in probes if p["evidence"] and not p["confirmed"]]

    if home["confirmed"] or confirmed:
        # 确认命中：把所有证据合并成一条高置信度结论，避免重复刷屏
        evidence: List[str] = []
        if home["confirmed"]:
            evidence.append(f"首页 {base_url} 回显 rememberMe=deleteMe")
        for item in confirmed:
            evidence.append(
                f"探测路径 {item['path']} 回显 rememberMe=deleteMe"
                f"（HTTP {item['status']}）"
            )
        findings.append(Finding(
            module="shiro",
            name="Apache Shiro（rememberMe=deleteMe 回显确认）",
            confidence="high",
            score=10,
            evidence=evidence,
            url=base_url,
        ))
    elif home["evidence"]:
        # 没回显 deleteMe，但首页有 Shiro 被动特征 -> 只能给低置信度
        findings.append(Finding(
            module="shiro",
            name="Apache Shiro（仅被动特征疑似）",
            confidence="low",
            score=len(home["evidence"]),
            evidence=home["evidence"],
            url=base_url,
        ))

    # 被动命中、但没有回显 deleteMe 的路径，单独作为低置信度线索列出
    for item in passive_only:
        findings.append(Finding(
            module="shiro",
            name=f"路径 {item['path']} 存在疑似 Shiro 特征（未回显 deleteMe）",
            confidence=confidence_of(len(item["evidence"])),
            score=len(item["evidence"]),
            evidence=item["evidence"],
            url=item["url"],
        ))

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings
