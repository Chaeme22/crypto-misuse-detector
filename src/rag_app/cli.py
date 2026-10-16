"""
CryptoMisuse-OSS CLI.

저장소를 검사해 SARIF 보고서를 만드는 것이 이 도구의 일이다(analyze). 예전에는
문서 질의응답 챗봇 명령(ask/scan/status/rebuild)도 있었으나, 시스템이 검사 도구로
방향을 바꾸면서 그 부품(generation/ingestion/persistence/retrieval)과 함께 걷어냈다.
"""

import sys
import argparse
from pathlib import Path
from typing import Optional

from .config.loader import load_config
from .observability.logging import setup_logging, get_logger

logger = get_logger(__name__)


def create_parser() -> argparse.ArgumentParser:
    """Create main CLI argument parser with subcommands."""
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to JSON configuration file (e.g. config/config.production.json)",
    )

    parser = argparse.ArgumentParser(
        prog="rag_app",
        description="CryptoMisuse-OSS - 저장소의 암호 오용을 검사해 SARIF로 보고",
        parents=[parent_parser],
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 저장소를 검사해 SARIF 보고서를 만든다. 이 도구의 본래 출력이다.
    analyze_parser = subparsers.add_parser(
        "analyze", help="저장소나 프로젝트 경로를 검사해 SARIF 보고서를 만든다",
        parents=[parent_parser])
    analyze_parser.add_argument("target", type=str, help="GitHub URL 또는 로컬 경로")
    analyze_parser.add_argument("--out", type=Path, default=Path("data/report.sarif"),
                                help="SARIF 출력 경로 (기본 data/report.sarif)")
    # 기본: 배포 판정 모델이 Ollama에 있으면 AI 판정을 함께 쓰고, 없으면 정적 판정 + 설치 안내.
    # AI는 코드 문맥을 봐야 하는 자리에만 쓰인다(표·출처로 결론 난 자리는 부르지 않는다).
    mode = analyze_parser.add_mutually_exclusive_group()
    mode.add_argument("--llm", action="store_true",
                      help="AI 판정을 반드시 쓴다(모델이 없으면 오류). 기본은 자동 감지")
    mode.add_argument("--no-llm", action="store_true",
                      help="AI 판정을 끄고 정적 판정만 쓴다(빠른 검사, CI)")
    analyze_parser.add_argument("--llm-backend", choices=("local", "ollama"), default=None,
                                help="판정 모델을 어디서 돌릴지. 기본 ollama(배포 모델). "
                                     "local은 GPU 서버에서 HF 가중치+어댑터")
    analyze_parser.add_argument("--llm-model", type=str, default=None,
                                help="판정 모델. ollama 기본은 배포 모델 crypto-verdict:qwen7b-v2, "
                                     "local 기본은 Qwen/Qwen2.5-Coder-7B-Instruct")
    analyze_parser.add_argument("--llm-adapter", type=str, default=None,
                                help="local 백엔드에 얹을 LoRA 어댑터 폴더 (training/train_lora.py 산출물)")
    analyze_parser.add_argument("--llm-4bit", action="store_true",
                                help="판정 모델을 4비트로 올린다. 임베딩·재순위와 같이 쓸 때.")
    analyze_parser.add_argument("--no-clauses", action="store_true",
                                help="Tier-2 조항 인용을 붙이지 않는다. 색인 없이 빠르게 볼 때.")
    analyze_parser.add_argument("--report", choices=("md", "pdf", "none"), default="md",
                                help="SARIF 옆에 사람이 읽는 보고서를 함께 쓴다(기본 md). "
                                     "pdf는 fpdf2와 한글 TTF 글꼴이 필요하다")

    # 이미 만든 SARIF에서 사람이 읽는 보고서만 다시 만든다. 검사를 다시 하지 않는다.
    report_parser = subparsers.add_parser(
        "report", help="SARIF 파일을 Markdown 또는 PDF 보고서로 바꾼다", parents=[parent_parser])
    report_parser.add_argument("sarif", type=Path, help="analyze가 만든 SARIF 파일")
    report_parser.add_argument("--format", choices=("md", "pdf"), default="md")
    report_parser.add_argument("--out", type=Path, default=None,
                               help="출력 경로(기본: SARIF와 같은 이름에 확장자만 바꿈)")

    setup_parser = subparsers.add_parser(
        "setup", help="AI 판정 모델을 설치한다(기본 모델 받기 + 학습한 어댑터 등록, 한 번만)",
        parents=[parent_parser])
    setup_parser.add_argument("--adapter", type=Path, default=None,
                              help="GGUF 어댑터 폴더(기본 adapters/qwen7b-v2)")

    subparsers.add_parser("validate-config", help="Validate JSON configuration file syntax and security rules", parents=[parent_parser])

    return parser


def handle_validate_config(config_path: Optional[str]) -> int:
    """Handle 'validate-config' subcommand."""
    print("\n설정 파일 검증 중...")
    path = Path(config_path) if config_path else None
    config = load_config(path)

    print("SUCCESS: JSON 설정 파일 규격 및 보안 검증 통과!")
    print(f"  - Environment: {config.environment}")
    print(f"  - Document Root: {config.paths.document_root.resolve()}")
    print(f"  - Embedding Model: {config.models.embedding.model_id}")
    print(f"  - LLM Model: {config.models.llm.model_id}\n")
    return 0


def handle_analyze(config, target: str, out_path: Path, use_llm: bool,
                   with_clauses: bool, llm_backend: Optional[str] = None,
                   llm_model: Optional[str] = None,
                   llm_4bit: bool = False, llm_adapter: Optional[str] = None,
                   no_llm: bool = False, report_format: str = "md") -> int:
    """
    저장소를 검사해 SARIF를 쓴다.

    LLM은 판정만 한다. 위치와 규칙 번호와 인용 조항은 각각 정적 추출, 규칙표, 조항 검색이
    이미 아는 값이라 LLM에게 옮겨 적게 하지 않는다. SARIF 문서 자체는 코드가 만든다.

    AI 판정을 쓸지는 기본으로 자동 감지한다(`models/release.py`). 배포 모델이 Ollama에 있으면 쓴다.
    """
    from rag_app.analysis import pipeline
    from rag_app.analysis.verdict import LlmVerdict, StaticVerdict
    from rag_app.models import release

    installed = None if (no_llm or use_llm) else release.installed_models(config.ollama_host)
    mode = release.resolve_mode(use_llm, no_llm, installed, llm_backend, llm_model)
    if mode.notice:
        print(f"[안내] {mode.notice}")

    provider = StaticVerdict()
    verdict_info = {"mode": "static"}
    if mode.use_llm:
        from rag_app.models.llm import make_verdict_model
        provider = LlmVerdict(make_verdict_model(config, mode.backend, mode.model or None,
                                                 llm_4bit, llm_adapter))
        verdict_info = {"mode": "llm", "backend": mode.backend,
                        "model": mode.model or "(backend default)",
                        **({"adapter": Path(llm_adapter).name} if llm_adapter else {})}

    document, state = pipeline.run(target, out_path, config, provider=provider,
                                   with_clauses=with_clauses, verdict_info=verdict_info)
    results = document["runs"][0]["results"]
    violations = [r for r in results if r["kind"] == "fail"]
    reviews = [r for r in results if r["kind"] == "review"]
    clean = len(state.findings) - len(results)

    print(f"검사 대상: {state.root}")
    if state.provenance:
        where = state.provenance.get("branch", "")
        print(f"커밋: {state.provenance['revisionId'][:12]}"
              + (f" ({where})" if where else ""))
    else:
        print("커밋: git 저장소가 아니라 스냅샷 없음")
    if state.dependencies:
        print(f"선언된 의존성: {len(state.dependencies)}개")
    print("판정 방식: " + ("정적 판정 + AI 판정(" + verdict_info["model"] + ")" if mode.use_llm
                          else "정적 판정")
          + ("" if with_clauses else " (조항 인용 없음)"))
    tests = sum(1 for f in state.findings if f.site.is_test)
    print(f"사용 지점 {len(state.sites)}건 → 위반 {len(violations)}건, "
          f"확인 필요 {len(reviews)}건, 문제없음 {clean}건"
          + (f" (그중 테스트 소스 {tests}건 제외)" if tests else ""))
    for result in results:
        location = result["locations"][0]["physicalLocation"]
        properties = result["properties"]
        mark = "위반  " if result["kind"] == "fail" else "확인필요"
        state = []
        if properties["unresolvedArgs"]:
            state.append(f"값 못 찾음({', '.join(properties['unresolvedArgs'])})")
        elif properties["tracedValues"]:
            state.append(f"값 확정({', '.join(properties['tracedValues'])})")
        else:
            state.append("값 확정")
        state.append("근거 검수됨" if properties["evidenceReviewed"] else "근거 미검수")
        print(f"  {mark} [{result['ruleId']}] {location['artifactLocation']['uri']}"
              f":{location['region']['startLine']}  " + " · ".join(state))
    print(f"\nSARIF: {out_path.resolve()}")
    if report_format != "none":
        from rag_app.analysis import report
        try:
            written = report.write(document, out_path.with_suffix("." + report_format), report_format)
            print(f"보고서: {written.resolve()}")
        except RuntimeError as exc:
            print(f"[안내] 보고서를 만들지 못했다: {exc}")
    return 0


def handle_report(sarif_path: Path, fmt: str, out_path: Optional[Path]) -> int:
    """SARIF 파일에서 사람이 읽는 보고서를 만든다."""
    from rag_app.analysis import report
    target = out_path or sarif_path.with_suffix("." + fmt)
    try:
        written = report.from_sarif(sarif_path, target, fmt)
    except RuntimeError as exc:
        print(f"[오류] {exc}")
        return 1
    print(f"보고서: {written.resolve()}")
    return 0


def main(args: Optional[list] = None) -> int:
    """CLI Main Entry Point."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return 0

    # Validate config for subcommand
    if parsed_args.command == "validate-config":
        return handle_validate_config(parsed_args.config)

    if parsed_args.command == "report":
        return handle_report(parsed_args.sarif, parsed_args.format, parsed_args.out)

    config_path = Path(parsed_args.config) if parsed_args.config else None
    config = load_config(config_path)

    # Setup Logging
    setup_logging(config.logging, config.paths.log_dir)

    if parsed_args.command == "setup":
        from rag_app.models import release
        return release.setup(config.ollama_host,
                             parsed_args.adapter or release.RELEASE_ADAPTER)

    if parsed_args.command == "analyze":
        return handle_analyze(config, parsed_args.target, parsed_args.out,
                             use_llm=parsed_args.llm,
                             no_llm=parsed_args.no_llm,
                             with_clauses=not parsed_args.no_clauses,
                             llm_backend=parsed_args.llm_backend,
                             llm_model=parsed_args.llm_model,
                             llm_adapter=parsed_args.llm_adapter,
                             llm_4bit=parsed_args.llm_4bit,
                             report_format=parsed_args.report)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
