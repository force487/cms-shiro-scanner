"""文件上传点检测模块。

思路：
    1. 抓上传表单：从页面 HTML 里找含 <input type="file"> 的表单，拿到 action 和文件字段名；
    2. 上传危险扩展名文件（含随机标记 marker）；
    3. 从响应里提取保存路径，再访问该路径看 marker 是否回显 —— 回显说明文件可被执行。

只依赖标准库，标记用随机串，避免把页面本身内容误判成回显。
"""

import json
import os
import random
import re
import string
from typing import List, Optional
from urllib.parse import urljoin

from .http_client import HttpClient, normalize_url
from .models import Finding

DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")

MAX_FORMS = 10

FORM_RE = re.compile(
    r"<form\b[^>]*action\s*=\s*[\"']([^\"']*)[\"'][^>]*>(.*?)</form>",
    re.IGNORECASE | re.DOTALL,
)
FILE_INPUT_RE = re.compile(r"<input\b[^>]*type\s*=\s*[\"']?file[\"']?[^>]*>", re.IGNORECASE)
NAME_RE = re.compile(r"name\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
# 响应里出现的"可执行文件路径"，用于提取上传后的保存位置
PATH_RE = re.compile(r"[A-Za-z0-9_./-]+\.(?:php|jsp|asp|aspx)", re.IGNORECASE)


def load_files(path: Optional[str] = None) -> dict:
    """读取 upload_payloads.json，返回 {files: [...]}。"""
    path = path or os.path.join(DICT_DIR, "upload_payloads.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def make_marker(length: int = 8) -> str:
    """生成随机标记，用于判断上传的文件是否真的被原样执行/回显。"""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def find_upload_forms(html: str, base_url: str) -> List[tuple]:
    """找含 <input type="file"> 的表单，返回 [(action_url, 文件字段名)]。"""
    results: List[tuple] = []
    for m in FORM_RE.finditer(html or ""):
        form_html = m.group(0)
        if not FILE_INPUT_RE.search(form_html):
            continue
        name_m = NAME_RE.search(FILE_INPUT_RE.search(form_html).group(0))
        if not name_m:
            continue
        action = urljoin(base_url, m.group(1) or "")
        results.append((action, name_m.group(1)))
    return results[:MAX_FORMS]


def run(
    client: HttpClient,
    base_url: str,
    files_def: dict,
    verbose: bool = False,
) -> List[Finding]:
    """对站点做文件上传漏洞探测，返回 Finding 列表。"""
    file_templates = files_def.get("files", [])
    base_url = normalize_url(base_url)

    home = client.get(base_url)
    if not home.ok:
        print(f"    [Upload] 目标不可达，跳过：{home.error or base_url}")
        return []

    forms = find_upload_forms(home.body or "", base_url)
    if verbose:
        print(f"    [Upload] 找到 {len(forms)} 个上传表单")

    findings: List[Finding] = []
    for action, field in forms:
        for file_def in file_templates:
            marker = make_marker()
            ext = file_def["ext"]
            filename = f"{marker}.{ext}"
            content = file_def["content"].replace("{marker}", marker)
            mime = file_def.get("mime", "application/octet-stream")

            resp = client.post(action, files={field: (filename, content, mime)})
            if verbose:
                print(f"    [Upload] 上传 {filename} -> "
                      f"{resp.error or 'HTTP ' + str(resp.status)}")
            if not resp.ok:
                continue

            path_m = PATH_RE.search(resp.body or "")
            if not path_m:
                continue
            saved_path = path_m.group(0)
            check_url = urljoin(base_url, saved_path)
            check = client.get(check_url)
            if marker in (check.body or ""):
                findings.append(Finding(
                    module="upload",
                    name="疑似任意文件上传（可执行）",
                    confidence="high",
                    score=8,
                    evidence=[f"上传点：{action}",
                              f"上传文件：{filename}",
                              f"访问 {check_url} 回显了标记 → 上传的脚本可被执行"],
                    url=action,
                ))
                break

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings