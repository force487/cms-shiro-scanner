"""敏感文件 / 目录扫描模块。

思路（与 Shiro 路径探测同源，字典驱动）：
    1. 拿敏感路径字典（备份文件、Git/SVN 泄露、配置文件、后台入口等）逐个拼接；
    2. 发 GET，看状态码与响应特征：
       - HTTP 200 且命中特征串 -> 确认敏感文件 / 目录存在；
    3. 每条命中输出一条 Finding。

对“内容特征 check 非空”的项要求正文回显特征，避免软 404 误判；
check 为空的项仅依赖 HTTP 200 判定路径存在。
"""

import json
import os
from typing import List, Optional

from .http_client import HttpClient, join_url, normalize_url
from .models import Finding

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")

MAX_PATHS = 200


def load_paths(path: Optional[str] = None) -> List[dict]:
    """读取 dirscan_paths.json，返回 paths 列表。"""
    path = path or os.path.join(DICT_DIR, "dirscan_paths.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp).get("paths", [])


def run(
    client: HttpClient,
    base_url: str,
    paths: List[dict],
    verbose: bool = False,
) -> List[Finding]:
    """对站点做敏感文件 / 目录探测，返回 Finding 列表。"""
    paths = list(paths)[:MAX_PATHS]
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [DirScan] 目标不可达，跳过：{home.error or base_url}")
        return []

    findings: List[Finding] = []
    for item in paths:
        url = join_url(base_url, item["path"])
        resp = client.get(url)
        if verbose:
            print(f"    [DirScan] {item['path']:<16} -> "
                  f"{resp.error or 'HTTP ' + str(resp.status)}")
        if not resp.ok:
            continue

        check = item.get("check", "")
        if check and check not in (resp.body or ""):
            continue

        confirmed = bool(check)
        findings.append(Finding(
            module="dirscan",
            name=item["name"],
            confidence="high" if confirmed else "medium",
            score=8 if confirmed else 5,
            evidence=[f"路径：{url}",
                      f"HTTP {resp.status}",
                      (f"响应回显特征：{check}" if confirmed else "路径存在（默认响应 200）")],
            url=url,
        ))

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings