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

from scanner import cms, report, shiro
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
    parser.add_argument("-m", "--modules", default="cms,shiro",
                        help="要运行的模块，逗号分隔：cms,shiro（默认全部）")
    parser.add_argument("--timeout", type=float, default=8.0, help="单次请求超时秒数")
    parser.add_argument("--cms-dict", help="自定义 CMS 指纹字典路径")
    parser.add_argument("--shiro-dict", help="自定义 Shiro 路径字典路径")
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
             rules: List[dict], shiro_paths: List[str]) -> Dict[str, List[Finding]]:
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
    unknown = modules - {"cms", "shiro"}
    if unknown:
        print(f"[!] 未知模块：{', '.join(unknown)}（只支持 cms / shiro）")
        return 2

    print("=" * 62)
    print("  CMS 指纹识别 + Apache Shiro 探测扫描器  v1.0.0")
    print(f"  目标数量：{len(targets)}    模块：{', '.join(sorted(modules))}")
    print("=" * 62)

    rules = load_rules(args.cms_dict) if "cms" in modules else []
    shiro_paths = load_wordlist(args.shiro_dict) if "shiro" in modules else []
    if "cms" in modules:
        print(f"[*] 已加载 CMS 指纹规则 {len(rules)} 条")
    if "shiro" in modules:
        print(f"[*] 已加载 Shiro 探测路径 {len(shiro_paths)} 条")

    client = HttpClient(timeout=args.timeout)
    all_results: Dict[str, Dict[str, List[Finding]]] = {}
    for target in targets:
        all_results[target] = scan_one(client, target, args, rules, shiro_paths)

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
