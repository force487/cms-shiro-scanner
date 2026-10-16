"""HTML 报告模块：把扫描结果渲染成一个自包含的网页报告（零第三方依赖）。

由 main.py 调用，例如::

    write_html_report(all_results, "report.html",
                      meta={"modules": ["cms", "shiro"], "version": "1.0.0"})

生成的 HTML 不引用任何外部资源（CSS 内联），双击即可用浏览器打开、离线可看。
"""

import html
import os
from datetime import datetime
from typing import Dict, List, Optional

from .models import Finding

CONFIDENCE_LABEL = {"high": "高", "medium": "中", "low": "低", "none": "无"}
MODULE_LABEL = {"cms": "CMS 指纹识别", "shiro": "Shiro 探测", "ports": "端口与服务探测", "sqli": "SQL 注入检测", "xss": "XSS 检测", "upload": "文件上传检测", "rce": "命令注入检测", "lfi": "文件包含检测", "dirscan": "敏感文件/目录扫描", "ssrf": "SSRF 检测", "csrf": "CSRF 检测", "xxe": "XXE 检测", "redirect": "开放重定向", "crlf": "CRLF 注入"}
MODULE_ORDER = ["cms", "shiro", "ports", "sqli", "xss", "upload", "rce", "lfi", "dirscan", "ssrf", "csrf", "xxe", "redirect", "crlf"]

_STYLE = """
:root{
  --bg:#f5f6f8; --card:#fff; --ink:#1f2328; --muted:#6b7280;
  --line:#e5e7eb; --high:#d93025; --medium:#e37400; --low:#6b7280;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;}
.wrap{max-width:960px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--muted);font-size:13px;margin-bottom:20px}
.summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px}
.summary div{background:var(--card);border:1px solid var(--line);border-radius:10px;
  padding:10px 16px;min-width:96px}
.summary b{display:block;font-size:20px}
.target{background:var(--card);border:1px solid var(--line);border-radius:12px;
  padding:18px 20px;margin-bottom:18px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.target h2{font-size:16px;margin:0 0 2px;word-break:break-all}
.target .mod{color:var(--muted);font-size:12px;margin-bottom:12px}
.module{margin-top:14px}
.module h3{font-size:12px;text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted);margin:0 0 8px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.finding{border-left:4px solid var(--low);background:#fafbfc;border-radius:8px;
  padding:10px 14px;margin-bottom:10px}
.finding.conf-high{border-left-color:var(--high)}
.finding.conf-medium{border-left-color:var(--medium)}
.finding header{display:flex;justify-content:space-between;gap:10px;align-items:baseline}
.finding h4{margin:0;font-size:14px}
.badge{font-size:12px;color:#fff;background:var(--low);border-radius:999px;
  padding:2px 10px;white-space:nowrap}
.conf-high .badge{background:var(--high)}
.conf-medium .badge{background:var(--medium)}
.finding .url{color:var(--muted);font-size:12px;word-break:break-all;margin:4px 0 6px}
.finding ul{margin:6px 0 0;padding-left:18px}
.finding li{font-size:13px}
.empty,.none{color:var(--muted);font-size:13px}
.none{padding:8px 0}
footer{color:var(--muted);font-size:12px;margin-top:26px;text-align:center}
"""


def _esc(value) -> str:
    """HTML 转义，避免目标返回的内容破坏页面结构。"""
    return html.escape(str(value), quote=True)


def _render_finding(finding: Finding) -> str:
    conf = finding.confidence if finding.confidence in CONFIDENCE_LABEL else "low"
    label = CONFIDENCE_LABEL.get(conf, conf)

    if finding.evidence:
        items = "\n".join(f"      <li>{_esc(item)}</li>" for item in finding.evidence)
        evidence_html = f"    <ul>\n{items}\n    </ul>"
    else:
        evidence_html = '    <div class="empty">（无证据明细）</div>'

    url_html = f'    <div class="url">{_esc(finding.url)}</div>' if finding.url else ""

    return (
        f'  <article class="finding conf-{_esc(conf)}">\n'
        f"    <header>\n"
        f"      <h4>{_esc(finding.name)}</h4>\n"
        f'      <span class="badge">{_esc(label)} · 分数 {_esc(finding.score)}</span>\n'
        f"    </header>\n"
        f"{url_html}\n"
        f"{evidence_html}\n"
        f"  </article>"
    )


def _render_target(target: str, modules_map: Dict[str, List[Finding]]) -> str:
    parts: List[str] = []
    ordered = [m for m in MODULE_ORDER if m in modules_map]
    ordered += [m for m in modules_map if m not in MODULE_ORDER]

    for module in ordered:
        findings = modules_map.get(module) or []
        title = MODULE_LABEL.get(module, module)
        if findings:
            body = "\n".join(_render_finding(f) for f in findings)
        else:
            body = '  <div class="none">未发现匹配的特征</div>'
        parts.append(
            f'  <section class="module">\n'
            f"    <h3>{_esc(title)}</h3>\n"
            f"{body}\n"
            f"  </section>"
        )

    total = sum(len(v) for v in modules_map.values())
    return (
        f'<section class="target">\n'
        f"  <h2>{_esc(target)}</h2>\n"
        f'  <div class="mod">共 {total} 条结论</div>\n'
        + "\n".join(parts) + "\n</section>"
    )


def count_by_confidence(all_results: Dict[str, Dict[str, List[Finding]]]) -> Dict[str, int]:
    """统计各置信度的结论数量。"""
    counts = {"high": 0, "medium": 0, "low": 0}
    for modules_map in all_results.values():
        for findings in modules_map.values():
            for finding in findings:
                counts[finding.confidence] = counts.get(finding.confidence, 0) + 1
    return counts


def render_html(
    all_results: Dict[str, Dict[str, List[Finding]]],
    meta: Optional[Dict] = None,
) -> str:
    """把扫描结果渲染成完整的 HTML 字符串。"""
    meta = meta or {}
    modules = meta.get("modules") or []
    modules_text = ", ".join(_esc(m) for m in modules) or "全部"
    version = _esc(meta.get("version", ""))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    counts = count_by_confidence(all_results)
    total = sum(counts.values())

    targets_html = "\n".join(
        _render_target(target, modules_map) for target, modules_map in all_results.items()
    )
    if not targets_html:
        targets_html = '<section class="target"><div class="none">没有扫描结果。</div></section>'

    return (
        "<!DOCTYPE html>\n"
        '<html lang="zh-CN">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>扫描报告 · CMS 指纹 + Shiro 探测</title>\n"
        "<style>" + _STYLE + "</style>\n"
        "</head>\n<body>\n<div class=\"wrap\">\n"
        "<h1>CMS 指纹识别 + Apache Shiro 探测扫描报告</h1>\n"
        f'<div class="sub">生成时间：{timestamp}　·　目标数：{len(all_results)}'
        f"　·　模块：{modules_text}　·　版本：{version}</div>\n"
        '<div class="summary">\n'
        f"  <div><b>{total}</b>结论总数</div>\n"
        f"  <div><b>{counts.get('high', 0)}</b>高置信度</div>\n"
        f"  <div><b>{counts.get('medium', 0)}</b>中置信度</div>\n"
        f"  <div><b>{counts.get('low', 0)}</b>低置信度</div>\n"
        "</div>\n"
        f"{targets_html}\n"
        "<footer>本报告由 cms_shiro_scanner 生成，仅供安全学习与已授权测试使用。</footer>\n"
        "</div>\n</body>\n</html>\n"
    )


def write_html_report(
    all_results: Dict[str, Dict[str, List[Finding]]],
    path: str,
    meta: Optional[Dict] = None,
) -> str:
    """生成 HTML 报告并写入 path，返回绝对路径。"""
    doc = render_html(all_results, meta)
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(doc)
    return os.path.abspath(path)
