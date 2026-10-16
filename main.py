"""CMS 指纹识别 + Shiro 探测扫描器 —— 命令行入口。

用法示例::

    python main.py -u http://127.0.0.1:8080            # 扫描单个目标
    python main.py -u http://127.0.0.1:8080 -v         # 打印探测过程
    python main.py -u http://a.com -u http://b.com     # 多目标
    python main.py -f urls.txt -o result.json          # 批量 + 结果存 JSON
    python main.py -u http://a.com -m cms              # 只跑 CMS 模块
"""

import argparse
import json
import os
import sys
import time
from typing import Dict, List

from scanner import cms, crlf, csrf, dirscan, hpp, lfi, ports, rce, redirect, report, shiro, sqli, ssrf, upload, xss, xxe
from scanner.fingerprint import load_rules, load_wordlist
from scanner.http_client import HttpClient, normalize_url
from scanner.models import Finding


def setup_stdout() -> None:
    """让 Windows 控制台能稳定输出中文。"""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - 老版本 Python 没有 reconfigure
        pass


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CMS 指纹识别 + Apache Shiro 探测扫描器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", action="append", default=[],
                        help="目标 URL，可重复指定多个")
    parser.add_argument("-f", "--file", help="从文本文件读取目标 URL（一行一个）")
    parser.add_argument("-m", "--modules", default="cms,shiro,ports",
                        help="要运行的模块，逗号分隔：cms,shiro,ports,sqli,xss,upload,rce,lfi,dirscan,ssrf,csrf,xxe,redirect,crlf,hpp（默认 cms,shiro,ports）")
    parser.add_argument("--timeout", type=float, default=8.0, help="单次请求超时秒数")
    parser.add_argument("--cms-dict", help="自定义 CMS 指纹字典路径")
    parser.add_argument("--shiro-dict", help="自定义 Shiro 路径字典路径")
    parser.add_argument("-p", "--ports", help="要扫描的端口，如 80,443,3306 或 1-1000")
    parser.add_argument("--port-threads", type=int, default=200, help="端口扫描并发线程数")
    parser.add_argument("--service-dict", help="自定义服务探测字典路径")
    parser.add_argument("--sqli-dict", help="自定义 SQL 注入 payload 字典路径")
    parser.add_argument("--xss-dict", help="自定义 XSS payload 字典路径")
    parser.add_argument("--upload-dict", help="自定义文件上传 payload 字典路径")
    parser.add_argument("--rce-dict", help="自定义命令注入 payload 字典路径")
    parser.add_argument("--lfi-dict", help="自定义文件包含 payload 字典路径")
    parser.add_argument("--dirscan-dict", help="自定义敏感路径扫描字典路径")
    parser.add_argument("--ssrf-dict", help="自定义 SSRF payload 字典路径")
    parser.add_argument("--csrf-dict", help="自定义 CSRF 检测配置路径")
    parser.add_argument("--xxe-dict", help="自定义 XXE payload 字典路径")
    parser.add_argument("--redirect-dict", help="自定义开放重定向 payload 字典路径")
    parser.add_argument("--crlf-dict", help="自定义 CRLF 注入 payload 字典路径")
    parser.add_argument("--hpp-dict", help="自定义 HPP 检测配置路径")
    parser.add_argument("--min-score", type=int, default=2,
                        help="CMS 模块最低输出分数（默认 2）")
    parser.add_argument("-o", "--output",
                        help="保存结果：扩展名 .html 生成网页报告，其它为 JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="打印详细探测过程")
    return parser.parse_args(argv)


def collect_targets(args: argparse.Namespace) -> List[str]:
    targets = list(args.url)
    if args.file:
        if not os.path.isfile(args.file):
            print(f"[!] 目标文件不存在：{args.file}")
        else:
            with open(args.file, "r", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
    # 去重但保持顺序
    seen, result = set(), []
    for target in targets:
        url = normalize_url(target)
        if url and url not in seen:
            seen.add(url)
            result.append(url)
    return result


def print_findings(findings: List[Finding]) -> None:
    if not findings:
        print("    [-] 未发现匹配的特征")
        return
    for item in findings:
        print(f"    [+] {item.name}   [置信度: {item.confidence} / 分数: {item.score}]")
        for evidence in item.evidence:
            print(f"          · {evidence}")


def scan_one(client: HttpClient, target: str, args: argparse.Namespace,
             rules: List[dict], shiro_paths: List[str],
             probes: dict, ports_spec: List[int],
             sqli_dict: dict,
             xss_payloads: List[dict],
             upload_files: dict,
             rce_payloads: List[dict],
             lfi_payloads: List[dict],
             dirscan_paths: List[dict],
             ssrf_payloads: List[dict],
             csrf_config: dict,
             xxe_payloads: List[dict],
             redirect_payloads: List[dict],
             crlf_payloads: List[dict],
             hpp_config: dict) -> Dict[str, List[Finding]]:
    print(f"\n[*] 目标：{target}")
    started = time.time()
    result: Dict[str, List[Finding]] = {}

    if "cms" in args.modules:
        print("  [CMS 指纹识别]")
        result["cms"] = cms.run(client, target, rules,
                                min_score=args.min_score, verbose=args.verbose)
        print_findings(result["cms"])

    if "shiro" in args.modules:
        print("  [Shiro 探测]")
        result["shiro"] = shiro.run(client, target, shiro_paths, verbose=args.verbose)
        print_findings(result["shiro"])

    if "ports" in args.modules:
        print("  [端口与服务探测]")
        result["ports"] = ports.run(
            target, ports=ports_spec, probes=probes,
            timeout=min(args.timeout, 3.0), threads=args.port_threads,
            verbose=args.verbose,
        )
        print_findings(result["ports"])

    if "sqli" in args.modules:
        print("  [SQL 注入检测]")
        result["sqli"] = sqli.run(client, target, sqli_dict, verbose=args.verbose)
        print_findings(result["sqli"])

    if "xss" in args.modules:
        print("  [XSS 检测]")
        result["xss"] = xss.run(client, target, xss_payloads, verbose=args.verbose)
        print_findings(result["xss"])

    if "upload" in args.modules:
        print("  [文件上传点检测]")
        result["upload"] = upload.run(client, target, upload_files, verbose=args.verbose)
        print_findings(result["upload"])

    if "rce" in args.modules:
        print("  [命令注入检测]")
        result["rce"] = rce.run(client, target, rce_payloads, verbose=args.verbose)
        print_findings(result["rce"])

    if "lfi" in args.modules:
        print("  [文件包含检测]")
        result["lfi"] = lfi.run(client, target, lfi_payloads, verbose=args.verbose)
        print_findings(result["lfi"])

    if "dirscan" in args.modules:
        print("  [敏感文件/目录扫描]")
        result["dirscan"] = dirscan.run(client, target, dirscan_paths, verbose=args.verbose)
        print_findings(result["dirscan"])

    if "ssrf" in args.modules:
        print("  [SSRF 检测]")
        result["ssrf"] = ssrf.run(client, target, ssrf_payloads, verbose=args.verbose)
        print_findings(result["ssrf"])

    if "csrf" in args.modules:
        print("  [CSRF 检测]")
        result["csrf"] = csrf.run(client, target, csrf_config, verbose=args.verbose)
        print_findings(result["csrf"])

    if "xxe" in args.modules:
        print("  [XXE 检测]")
        result["xxe"] = xxe.run(client, target, xxe_payloads, verbose=args.verbose)
        print_findings(result["xxe"])

    if "redirect" in args.modules:
        print("  [开放重定向检测]")
        result["redirect"] = redirect.run(client, target, redirect_payloads, verbose=args.verbose)
        print_findings(result["redirect"])

    if "crlf" in args.modules:
        print("  [CRLF 注入检测]")
        result["crlf"] = crlf.run(client, target, crlf_payloads, verbose=args.verbose)
        print_findings(result["crlf"])

    if "hpp" in args.modules:
        print("  [HTTP 参数污染检测]")
        result["hpp"] = hpp.run(client, target, hpp_config, verbose=args.verbose)
        print_findings(result["hpp"])

    print(f"  [完成] 用时 {time.time() - started:.2f}s")
    return result


def main(argv: List[str]) -> int:
    setup_stdout()
    args = parse_args(argv)

    targets = collect_targets(args)
    if not targets:
        print("用法：python main.py -u http://目标地址   （-h 查看全部参数）")
        return 2

    modules = {m.strip().lower() for m in args.modules.split(",") if m.strip()}
    unknown = modules - {"cms", "shiro", "ports", "sqli", "xss", "upload", "rce", "lfi", "dirscan", "ssrf", "csrf", "xxe", "redirect", "crlf", "hpp"}
    if unknown:
        print(f"[!] 未知模块：{', '.join(unknown)}"
              f"（只支持 cms / shiro / ports / sqli / xss / upload / rce / lfi / dirscan / ssrf / csrf / xxe / redirect / crlf / hpp）")
        return 2

    print("=" * 62)
    print("  CMS 指纹识别 + Apache Shiro 探测扫描器  v1.0.0")
    print(f"  目标数量：{len(targets)}    模块：{', '.join(sorted(modules))}")
    print("=" * 62)

    rules = load_rules(args.cms_dict) if "cms" in modules else []
    shiro_paths = load_wordlist(args.shiro_dict) if "shiro" in modules else []
    probes = ports.load_probes(args.service_dict) if "ports" in modules else {}
    ports_spec = ports.parse_ports(args.ports) if "ports" in modules else None
    sqli_dict = sqli.load_payloads(args.sqli_dict) if "sqli" in modules else {}
    xss_payloads = xss.load_payloads(args.xss_dict) if "xss" in modules else []
    upload_files = upload.load_files(args.upload_dict) if "upload" in modules else {}
    rce_payloads = rce.load_payloads(args.rce_dict) if "rce" in modules else []
    lfi_payloads = lfi.load_payloads(args.lfi_dict) if "lfi" in modules else []
    dirscan_paths = dirscan.load_paths(args.dirscan_dict) if "dirscan" in modules else []
    ssrf_payloads = ssrf.load_payloads(args.ssrf_dict) if "ssrf" in modules else []
    csrf_config = csrf.load_config(args.csrf_dict) if "csrf" in modules else {}
    xxe_payloads = xxe.load_payloads(args.xxe_dict) if "xxe" in modules else []
    redirect_payloads = redirect.load_payloads(args.redirect_dict) if "redirect" in modules else []
    crlf_payloads = crlf.load_payloads(args.crlf_dict) if "crlf" in modules else []
    hpp_config = hpp.load_config(args.hpp_dict) if "hpp" in modules else {}
    if "cms" in modules:
        print(f"[*] 已加载 CMS 指纹规则 {len(rules)} 条")
    if "shiro" in modules:
        print(f"[*] 已加载 Shiro 探测路径 {len(shiro_paths)} 条")
    if "ports" in modules:
        print(f"[*] 已加载服务探测规则 {len(probes.get('map', {}))} 条")
    if "sqli" in modules:
        print(f"[*] 已加载 SQL 注入 payload {len(sqli_dict.get('payloads', []))} 条"
              f" / 报错特征 {len(sqli_dict.get('error_patterns', []))} 条")
    if "xss" in modules:
        print(f"[*] 已加载 XSS payload {len(xss_payloads)} 条")
    if "upload" in modules:
        print(f"[*] 已加载文件上传模板 {len(upload_files.get('files', []))} 条")
    if "rce" in modules:
        print(f"[*] 已加载命令注入 payload {len(rce_payloads)} 条")
    if "lfi" in modules:
        print(f"[*] 已加载文件包含 payload {len(lfi_payloads)} 条")
    if "dirscan" in modules:
        print(f"[*] 已加载敏感路径 {len(dirscan_paths)} 条")
    if "ssrf" in modules:
        print(f"[*] 已加载 SSRF payload {len(ssrf_payloads)} 条")
    if "csrf" in modules:
        print(f"[*] 已加载 CSRF 检测配置（token 特征 {len(csrf_config.get('token_patterns', []))} 条 / 敏感词 {len(csrf_config.get('sensitive_keywords', []))} 条）")
    if "xxe" in modules:
        print(f"[*] 已加载 XXE payload {len(xxe_payloads)} 条")
    if "redirect" in modules:
        print(f"[*] 已加载开放重定向 payload {len(redirect_payloads)} 条")
    if "crlf" in modules:
        print(f"[*] 已加载 CRLF 注入 payload {len(crlf_payloads)} 条")
    if "hpp" in modules:
        print(f"[*] 已加载 HPP 检测配置")

    client = HttpClient(timeout=args.timeout)
    all_results: Dict[str, Dict[str, List[Finding]]] = {}
    for target in targets:
        all_results[target] = scan_one(client, target, args, rules, shiro_paths,
                                       probes, ports_spec, sqli_dict, xss_payloads, upload_files,
                                       rce_payloads, lfi_payloads, dirscan_paths, ssrf_payloads,
                                       csrf_config, xxe_payloads, redirect_payloads,
                                       crlf_payloads, hpp_config)

    if args.output:
        if args.output.lower().endswith((".html", ".htm")):
            path = report.write_html_report(
                all_results, args.output,
                meta={"modules": sorted(modules), "version": "1.0.0"},
            )
            print(f"\n[*] HTML 报告已生成：{path}")
        else:
            payload = {
                target: {module: [f.to_dict() for f in findings]
                         for module, findings in modules_map.items()}
                for target, modules_map in all_results.items()
            }
            with open(args.output, "w", encoding="utf-8") as fp:
                json.dump(payload, fp, ensure_ascii=False, indent=2)
            print(f"\n[*] 结果已保存：{os.path.abspath(args.output)}")

    print("\n[*] 扫描结束。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
