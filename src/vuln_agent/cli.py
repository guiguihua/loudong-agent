"""CLI 入口 — 输入指令就能运行漏洞修复流水线。

用法：
  python -m vuln_agent list                            # 列出预置 demo
  python -m vuln_agent run code-sqli                   # 运行指定 demo
  python -m vuln_agent run --file <path>.json          # 从任意 JSON 运行完整流水线
  python -m vuln_agent run --file <path>.json --llm    # LLM 推理模式
  python -m vuln_agent run --file <path>.json --source-dir ./src --llm  # LLM + 源码
  python -m vuln_agent run --all-deps                  # 批量运行所有 CVE demo
  python -m vuln_agent run --all                       # 运行所有 demo
  python -m vuln_agent serve                           # 启动 API
  python -m vuln_agent chat                            # 交互式 REPL
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from vuln_agent.demos import DEMOS, get_demo, list_demos
from vuln_agent.models import RepairLoopStatus
from vuln_agent.runner import run_dict as runner_run_dict, run_file as runner_run_file


# ── 公共执行函数 ──────────────────────────────────────────────────────


def run_preset_demo(key: str, output_dir: Path | None = None) -> int:
    """运行预置 demo（兼容旧 API，内部委托给 runner）。"""
    preset = get_demo(key)
    if preset is None:
        print(f"[错误] 未知的 demo key: {key}")
        print(f"可用: {', '.join(d.key for d in DEMOS)}")
        return 1

    print(f"\n{'='*60}")
    print(f"  {preset.title}")
    print(f"  {preset.description}")
    print(f"{'='*60}\n")

    # 从 preset 提取 raw input
    raw, sources, val_results = _unpack_preset(preset)

    try:
        result = runner_run_dict(
            raw,
            language=preset.engineering.language,
            framework=preset.engineering.framework,
            database=preset.engineering.database,
            package_manager=preset.engineering.package_manager,
            repository=preset.repository.repository,
            branch=preset.repository.branch,
            test_framework=preset.repository.test_framework,
            source_files=sources,
            validation_results=val_results,
        )
    except Exception as exc:
        print(f"[异常] {key}: {exc}")
        return 1

    return _print_result(result, key, output_dir)


def run_json_file(
    file_path: str,
    output_dir: Path | None = None,
    full_pipeline: bool = True,
    source_dir: str | None = None,
) -> int:
    """从 JSON 文件运行 Agent 流水线。

    Args:
        file_path: JSON 文件路径
        output_dir: 输出目录
        full_pipeline: True=完整流水线(含补丁生成), False=仅分析
        source_dir: 源码目录，自动加载目录下所有文本文件作为源码上下文
    """
    path = Path(file_path)
    if not path.exists():
        print(f"[错误] 文件不存在: {file_path}")
        return 1

    out = output_dir or (ROOT / "outputs")

    # 加载源码
    source_files = _load_source_files(source_dir, path)

    try:
        if full_pipeline:
            result = runner_run_file(
                file_path, source_files=source_files,
                source_dir=source_dir or str(path.parent),
            )
            return _print_result(result, path.stem, output_dir)
        else:
            from vuln_agent.runner import run_file_simple
            result = run_file_simple(file_path)
            out.mkdir(exist_ok=True)
            finding_id = result["finding"]["finding_id"]
            out_path = out / f"{finding_id}-analysis.json"
            out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"\n分析完成: {finding_id}")
            print(f"  类型: {result['finding']['vulnerability_type']}")
            print(f"  严重性: {result['finding']['severity']}")
            print(f"  评估状态: {result['impact']['status']}")
            print(f"  根因分类: {result['root_cause']['root_cause_category']}")
            print(f"  输出: {out_path}")
            return 0
    except Exception as exc:
        print(f"[异常] {file_path}: {exc}")
        return 1


def run_all_deps(output_dir: Path | None = None) -> int:
    """批量运行所有依赖 CVE demo。"""
    dep_demos = [d for d in DEMOS if d.is_dependency_type]
    return _batch_run(dep_demos, output_dir)


def run_all(output_dir: Path | None = None) -> int:
    """批量运行所有 demo。"""
    return _batch_run(DEMOS, output_dir)


# ── 内部辅助 ──────────────────────────────────────────────────────────

# 文本文件扩展名（加载为源码）
_SOURCE_EXTENSIONS = {
    ".py", ".java", ".js", ".ts", ".go", ".rs", ".c", ".cpp", ".h", ".hpp",
    ".rb", ".php", ".swift", ".kt", ".scala", ".cs", ".vb", ".sh", ".bash",
    ".xml", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".conf",
    ".txt", ".md", ".sql", ".html", ".css", ".jsx", ".tsx", ".vue", ".svelte",
    ".dockerfile", ".dockerignore", ".gitignore", ".env",
}

# 排除的目录
_SOURCE_EXCLUDE_DIRS = {
    ".git", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", "target",
    ".idea", ".vscode", ".claude",
}

# 排除的文件名模式
_SOURCE_EXCLUDE_NAMES = {
    "package-lock.json", "yarn.lock", "poetry.lock", "pnpm-lock.yaml",
    "Cargo.lock", "Gemfile.lock", "pipfile.lock",
}


def _load_source_files(source_dir: str | None, vuln_path: Path) -> dict[str, str]:
    """从目录加载源文件。如未指定目录，尝试从漏洞文件同级目录推断。"""
    if not source_dir:
        # 尝试从漏洞文件的同级目录加载源码
        parent = vuln_path.parent
        if parent != Path(".") and parent.exists():
            source_dir = str(parent)
        else:
            return {}

    src_path = Path(source_dir)
    if not src_path.exists():
        print(f"[警告] 源码目录不存在: {source_dir}")
        return {}

    files: dict[str, str] = {}
    for f in src_path.rglob("*"):
        if not f.is_file():
            continue
        # 检查排除目录
        if any(excl in f.parts for excl in _SOURCE_EXCLUDE_DIRS):
            continue
        # 检查排除文件名
        if f.name in _SOURCE_EXCLUDE_NAMES:
            continue
        # 检查扩展名
        if f.suffix.lower() not in _SOURCE_EXTENSIONS and f.name.lower() not in _SOURCE_EXTENSIONS:
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # 用相对路径作为 key
        try:
            rel = str(f.relative_to(src_path))
        except ValueError:
            rel = str(f)
        files[rel] = content

    if files:
        print(f"[源码] 从 {source_dir} 加载了 {len(files)} 个文件")
    return files


def _unpack_preset(preset):
    """从 DemoPreset 提取 runner 所需的参数。"""
    raw = preset.raw_input
    if callable(raw):
        raw = raw()
    elif isinstance(raw, str):
        raw = json.loads((ROOT / "examples" / raw).read_text(encoding="utf-8"))

    # 源文件
    sources = {}
    for sf in preset.source_files():
        sources[sf.path] = sf.content

    # 验证结果
    if preset.validation_summaries:
        val_results = [
            {"layer": layer.value, "tool_name": name, "summary": summary}
            for (layer, name, summary) in preset.validation_summaries("")
        ]
    else:
        from vuln_agent.models import ValidationLayer
        val_results = [
            {"layer": "build", "tool_name": "build", "summary": "构建验证通过。"},
            {"layer": "business_regression", "tool_name": "business regression", "summary": "业务回归通过。"},
            {"layer": "security_regression", "tool_name": "security regression", "summary": "安全回归通过。"},
            {"layer": "scanner_rescan", "tool_name": "scanner rescan", "summary": "扫描器复扫通过。"},
            {"layer": "differential_risk", "tool_name": "diff risk", "summary": "差异风险可接受。"},
        ]

    return raw, sources, val_results


def _print_result(result: dict, label: str, output_dir: Path | None = None) -> int:
    """打印 runner 返回的结果字典。"""
    out = output_dir or (ROOT / "outputs")
    out.mkdir(exist_ok=True)

    finding_id = result["finding"]["finding_id"]
    status = result["status"]

    if status == RepairLoopStatus.SUCCEEDED.value and "report_markdown" in result:
        report_path = out / f"{finding_id}-report.md"
        report_path.write_text(result["report_markdown"], encoding="utf-8")
        print(f"\n[成功] {finding_id}")
        print(f"  状态: {status}")
        if "patch_candidate" in result:
            pc = result["patch_candidate"]
            print(f"  补丁: {pc['patch_id']}")
            for art in pc.get("artifacts", []):
                print(f"    [{art['patch_type']}] {art['target']}")
        print(f"  报告: {report_path}")
        return 0
    else:
        failure_path = out / f"{label}-failure.json"
        failure_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n[失败] {finding_id}")
        print(f"  状态: {status}")
        print(f"  详情: {failure_path}")
        if "failure_analysis" in result:
            fa = result["failure_analysis"]
            print(f"  失败原因: {fa.get('summary', 'unknown')}")
        return 1


def _batch_run(demos_list, output_dir: Path | None = None) -> int:
    failures = []
    total = len(demos_list)
    for i, preset in enumerate(demos_list, 1):
        print(f"\n{'─'*60}")
        print(f"  [{i}/{total}] {preset.key}")
        print(f"{'─'*60}")
        try:
            raw, sources, val_results = _unpack_preset(preset)
            result = runner_run_dict(
                raw,
                language=preset.engineering.language,
                framework=preset.engineering.framework,
                database=preset.engineering.database,
                package_manager=preset.engineering.package_manager,
                repository=preset.repository.repository,
                branch=preset.repository.branch,
                test_framework=preset.repository.test_framework,
                source_files=sources,
                validation_results=val_results,
            )
            if _print_result(result, preset.key, output_dir) != 0:
                failures.append(preset.key)
            else:
                print(f"  [OK] {result['finding']['finding_id']}")
        except KeyboardInterrupt:
            print(f"\n  用户中断，跳过 {preset.key}")
            failures.append(preset.key)
        except Exception as exc:
            print(f"  [异常] {preset.key}: {exc}")
            failures.append(preset.key)

    print(f"\n{'='*60}")
    print(f"  完成: {total} 个, 成功 {total - len(failures)} 个, 失败 {len(failures)} 个")
    print(f"{'='*60}")
    return 1 if failures else 0


# ── chat ──────────────────────────────────────────────────────────────


def _chat_repl(output_dir: str | None = None) -> int:
    out = Path(output_dir) if output_dir else (ROOT / "outputs")
    print(r"""
╔══════════════════════════════════════════════════════════════╗
║       漏洞修复 Agent - 交互式对话模式                          ║
║                                                              ║
║  输入指令运行漏洞分析与补丁生成：                                ║
║    list / ls        列出预置 demo                             ║
║    file <路径>      从 JSON 文件运行完整流水线                   ║
║    run <key>        运行预置 demo                             ║
║    help / quit                                                ║
╚══════════════════════════════════════════════════════════════╝
""")
    print(f"输出目录: {out}\n")

    aliases = {
        "sql注入": "code-sqli", "sqli": "code-sqli",
        "django": "django-alias",
        "struts": "struts-cve", "log4j": "log4j-cve", "log4shell": "log4j-cve",
        "spring": "spring-cve",
        "所有": "__all__", "全部": "__all__", "all": "__all__",
    }

    while True:
        try:
            raw_cmd = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n再见!")
            return 0

        if not raw_cmd:
            continue
        cmd_lower = raw_cmd.lower()

        if cmd_lower in ("quit", "exit", "q", "退出"):
            print("再见!")
            return 0
        if cmd_lower in ("help", "h", "帮助", "?"):
            _chat_help()
            continue
        if cmd_lower in ("list", "ls", "列表"):
            _print_demo_list()
            continue
        if cmd_lower.startswith("file "):
            file_path = raw_cmd[5:].strip().strip('"').strip("'")
            run_json_file(file_path, out)
            continue

        # "run <key>" 或直接输入 key
        key = raw_cmd
        for prefix in ("run ", "运行 ", "运行"):
            if cmd_lower.startswith(prefix):
                key = raw_cmd[len(prefix):].strip()
                break
        resolved = aliases.get(key.lower(), key.lower())
        if resolved == "__all__":
            run_all(out)
        elif resolved in {d.key for d in DEMOS}:
            run_preset_demo(resolved, out)
        else:
            # 尝试解释为文件路径
            p = Path(key)
            if p.exists() and p.suffix == ".json":
                run_json_file(key, out)
            else:
                print(f"未知: {raw_cmd}")
                print(f"可用 demo: {', '.join(d.key for d in DEMOS)}")
                print("输入 'list' / 'help' / 'file <路径>' 或直接输入 demo key。")


def _chat_help():
    print("""
可用指令:
  list / ls          列出预置 demo
  file <path>        从 JSON 文件运行完整流水线 (自动推断类型和上下文)
  run <key>          运行预置 demo
  run all            运行所有 demo
  help               帮助
  quit               退出

快捷别名: sqli / django / struts / log4j / spring
直接输入 JSON 文件路径也可以运行。""")


def _print_demo_list():
    for d in list_demos():
        print(f"  {d['key']:<22} {d['title']}")
    print()


# ── serve ─────────────────────────────────────────────────────────────


def _serve(host: str, port: int, reload: bool) -> None:
    import uvicorn
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    print(f"启动 API 服务: http://{host}:{port}")
    uvicorn.run("vuln_agent.api:app", host=host, port=port, reload=reload)


# ── argparse ──────────────────────────────────────────────────────────


def _run_evaluate(args) -> int:
    """运行 Agent 评估测试流程（仅 LLM 模式）。"""
    from .evaluate import evaluate_all

    # 自动加载 .env
    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    except ImportError:
        pass

    output_dir = Path(args.output_dir) if args.output_dir else None
    demo_filter = args.demo if hasattr(args, 'demo') and args.demo else None
    try:
        evaluate_all(demo_filter=demo_filter, output_dir=output_dir)
        return 0
    except Exception as exc:
        print(f"[评估异常] {exc}")
        import traceback
        traceback.print_exc()
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-agent",
        description="漏洞修复 Agent — 输入指令即可运行漏洞分析与补丁生成。",
    )
    sub = parser.add_subparsers(dest="command", help="子命令")

    sub.add_parser("list", aliases=["ls"], help="列出预置 demo")

    run_p = sub.add_parser("run", help="运行流水线")
    run_p.add_argument("key", nargs="?", default=None, help="demo key 或 JSON 文件路径")
    run_p.add_argument("--file", "-f", dest="file_path", default=None, help="从 JSON 文件运行")
    run_p.add_argument("--source-dir", "-s", default=None, help="源码目录，自动加载目录下所有代码文件")
    run_p.add_argument("--all-deps", action="store_true", help="运行所有 CVE demo")
    run_p.add_argument("--all", action="store_true", help="运行所有 demo")
    run_p.add_argument("--output-dir", "-o", default=None, help="输出目录")
    run_p.add_argument("--analyze-only", action="store_true", help="仅分析，不生成补丁")

    serve_p = sub.add_parser("serve", help="启动 API")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8000)
    serve_p.add_argument("--no-reload", action="store_true", help="禁用热重载")

    chat_p = sub.add_parser("chat", help="交互式对话")
    chat_p.add_argument("--output-dir", "-o", default=None, help="输出目录")

    eval_p = sub.add_parser("evaluate", help="运行 Agent 评估测试流程")
    eval_p.add_argument("--demo", "-d", nargs="+", default=None,
                        help="指定要评估的 demo key（默认全部）")
    eval_p.add_argument("--output-dir", "-o", default=None, help="输出目录")

    return parser


def main(argv: list[str] | None = None) -> int:
    # 自动加载 .env（所有子命令都需要 DEEPSEEK_API_KEY）
    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    except ImportError:
        pass

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command in ("list", "ls"):
        _print_demo_list()

    elif args.command == "run":
        output_dir = Path(args.output_dir) if args.output_dir else None
        if args.all:
            return run_all(output_dir)
        if args.all_deps:
            return run_all_deps(output_dir)
        if args.file_path:
            return run_json_file(
                args.file_path, output_dir,
                full_pipeline=not args.analyze_only,
                source_dir=args.source_dir,
            )
        if args.key:
            # 先尝试 demo key，再尝试文件路径
            if get_demo(args.key):
                return run_preset_demo(args.key, output_dir)
            p = Path(args.key)
            if p.exists() and p.suffix == ".json":
                return run_json_file(args.key, output_dir, full_pipeline=not args.analyze_only, source_dir=args.source_dir)
            print(f"[错误] 未知 demo key 且文件不存在: {args.key}")
            print(f"可用 demo: {', '.join(d.key for d in DEMOS)}")
            return 1
        # 无参数 → 帮助
        parser.parse_args(["run", "--help"])
        print("\n可用的预置 demo:")
        _print_demo_list()
        return 0

    elif args.command == "serve":
        _serve(args.host, args.port, not args.no_reload)

    elif args.command == "chat":
        return _chat_repl(args.output_dir)

    elif args.command == "evaluate":
        return _run_evaluate(args)

    else:
        print("漏洞修复 Agent CLI\n")
        print("用法:")
        print("  python -m vuln_agent list                  列出预置 demo")
        print("  python -m vuln_agent run <key>             运行预置 demo")
        print("  python -m vuln_agent run --file <路径>     从 JSON 文件运行完整流水线")
        print("  python -m vuln_agent evaluate              运行完整评估测试流程")
        print("  python -m vuln_agent serve                 启动 API")
        print("  python -m vuln_agent chat                  交互式对话")
        print("\n在 Claude Code 中可以直接说:")
        print('  "分析 examples/struts_cve_2017_5638.json"')
        print('  "运行所有 CVE demo"')

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
