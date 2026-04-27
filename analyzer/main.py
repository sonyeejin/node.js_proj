import json
from pathlib import Path
from typing import Any, List, Dict

from graph_builder import DependencyGraphBuilder
from detectors.install_script_detector import detect_install_scripts
from detectors.typosquatting_detector import detect_typosquatting
from detectors.dependency_confusion_detector import detect_dependency_confusion
from detectors.ast_detector import detect_ast_risks
from detectors.dynamic_analyzer import detect_dynamic_risks
from comparator import compare


# ─── 출력 저장 ────────────────────────────────────────────────────────────────

def save_output(data: Any, output_path: str) -> None:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ─── 출력 유틸 ────────────────────────────────────────────────────────────────

def div(char: str = "-", width: int = 52) -> None:
    print(char * width)

def header(title: str) -> None:
    print(f"\n+{'-' * 50}+")
    print(f"|  {title:<48}|")
    print(f"+{'-' * 50}+")

def ok(msg: str)    : print(f"  [OK]  {msg}")
def warn(msg: str)  : print(f"  [!!]  {msg}")
def info(msg: str)  : print(f"  -  {msg}")


# ─── 단계별 출력 ──────────────────────────────────────────────────────────────

def print_step1(
    graph: dict,
    install_results: list,
    typo_results: list,
    confusion_results: list
) -> None:
    header("1단계 · 메타데이터 분석")
    pkg_count = len([n for n in graph['nodes'].values() if n.get('path', '') != ''])
    info(f"패키지 수  : {pkg_count}개  |  의존성 엣지 : {len(graph['edges'])}개")
    print()

    if not install_results and not typo_results and not confusion_results:
        ok("Install Script / Typosquatting / Dependency Confusion — 이상 없음")
        return

    for item in install_results[:5]:
        warn(f"[Install Script]  {item['package']} @ {item['version']}  ->  {item['reason']}")
    for item in typo_results[:5]:
        warn(f"[Typosquatting]   {item['package']} @ {item['version']}  ->  {item['reason']}  (거리={item['distance']})")
    for item in confusion_results[:5]:
        warn(f"[Dep Confusion]   {item['package']} @ {item['version']}  ->  {item['reason']}")


def print_step2(ast_results: list) -> None:
    header("2단계 · AST 정적 분석")

    total_findings = sum(len(p.get("findings", [])) for p in ast_results)
    # [수정] 탐지 건수 내림차순 정렬
    pkgs_with = sorted(
        [p for p in ast_results if p.get("findings")],
        key=lambda p: len(p.get("findings", [])),
        reverse=True
    )

    info(f"분석 패키지  : {len(ast_results)}개")
    info(f"탐지 패키지  : {len(pkgs_with)}개  |  총 탐지 건수 : {total_findings}건")
    print()

    if not pkgs_with:
        ok("정적 분석 — 위험 패턴 없음")
        return

    # 탐지 유형 집계
    type_counter: Dict[str, int] = {}
    for pkg in ast_results:
        for f in pkg.get("findings", []):
            t = f.get("type", "unknown")
            type_counter[t] = type_counter.get(t, 0) + 1

    TYPE_KO = {
        "dynamic_execution":        "동적 코드 실행",
        "system_command_execution": "시스템 명령 실행",
        "external_communication":   "외부 통신",
        "system_info_access":       "시스템 정보 접근",
        "obfuscation":              "난독화 패턴",
    }
    for t, cnt in sorted(type_counter.items(), key=lambda x: -x[1]):
        label = TYPE_KO.get(t, t)
        warn(f"{label:<18} : {cnt}건")

    print()
    info("주요 탐지 패키지 (탐지 건수 상위 5개)")
    for pkg in pkgs_with[:5]:
        cnt = len(pkg.get("findings", []))
        info(f"  {pkg['package']} @ {pkg['version']}  ->  {cnt}건")

    if len(pkgs_with) > 5:
        info(f"  ... 외 {len(pkgs_with) - 5}개 (detection_results.json 참고)")


def print_step3(dynamic_results: list) -> None:
    header("3단계 · 동적 분석")

    active = [
        p for p in dynamic_results
        if any(len(p.get(k, [])) > 0
               for k in ["network", "process_execution", "env_access", "filesystem"])
    ]
    errors = [
        p for p in dynamic_results
        if any(e.get("type") == "analysis_error" for e in p.get("errors", []))
    ]

    info(f"분석 패키지  : {len(dynamic_results)}개")
    info(f"행위 발생    : {len(active)}개  |  분석 실패 : {len(errors)}개")
    print()

    if not active:
        ok("동적 분석 — 실제 행위 없음")
        return

    cat_counter = {"network": 0, "process_execution": 0, "env_access": 0, "filesystem": 0}
    for pkg in active:
        for cat in cat_counter:
            cat_counter[cat] += len(pkg.get(cat, []))

    CAT_KO = {
        "network":           "네트워크 요청",
        "process_execution": "프로세스 실행",
        "env_access":        "환경 변수 접근",
        "filesystem":        "파일 시스템 접근",
    }
    for cat, cnt in cat_counter.items():
        if cnt > 0:
            warn(f"{CAT_KO[cat]:<16} : {cnt}건")

    print()
    # [수정] 행위 건수 합계 기준 내림차순 정렬
    active_sorted = sorted(
        active,
        key=lambda p: sum(len(p.get(k, [])) for k in ["network", "process_execution", "env_access", "filesystem"]),
        reverse=True
    )
    info("실제 행위 발생 패키지 (상위 5개)")
    for pkg in active_sorted[:5]:
        name    = pkg.get("metadata", {}).get("package", "unknown")
        version = pkg.get("metadata", {}).get("version", "unknown")
        acts    = []
        if pkg.get("network"):           acts.append(f"네트워크 {len(pkg['network'])}건")
        if pkg.get("process_execution"): acts.append(f"프로세스 {len(pkg['process_execution'])}건")
        if pkg.get("env_access"):        acts.append(f"env {len(pkg['env_access'])}건")
        if pkg.get("filesystem"):        acts.append(f"파일 {len(pkg['filesystem'])}건")
        info(f"  {name} @ {version}  ->  {', '.join(acts)}")

    if len(active) > 5:
        info(f"  ... 외 {len(active) - 5}개 (detection_results.json 참고)")


def print_comparison(comparison_results: list) -> None:
    header("정적 vs 동적 비교")

    high    = [r for r in comparison_results if r.get("risk_level") == "HIGH"]
    medium  = [r for r in comparison_results if r.get("risk_level") == "MEDIUM"]
    low     = [r for r in comparison_results if r.get("risk_level") == "LOW"]
    unknown = [r for r in comparison_results if r.get("risk_level") == "UNKNOWN"]

    medium_static_only  = [r for r in medium if r.get("summary", {}).get("static_only_count", 0) > 0
                           and r.get("summary", {}).get("dynamic_only_count", 0) == 0]
    medium_dynamic_only = [r for r in medium if r.get("summary", {}).get("dynamic_only_count", 0) > 0]

    info(f"HIGH    : {len(high)}개   (행위 조합 기반 위험 탐지)")
    if medium_static_only:
        info(f"MEDIUM  : {len(medium_static_only)}개   (정적에서만 탐지)")
    if medium_dynamic_only:
        info(f"MEDIUM  : {len(medium_dynamic_only)}개   (동적에서만 탐지)")
    info(f"LOW     : {len(low)}개   (탐지 없음)")
    info(f"UNKNOWN : {len(unknown)}개   (분석 실패)")
    print()

    # HIGH 상세 출력 — 판정 근거 포함
    if high:
        info("-- 위험 탐지 패키지 --")
        for r in high[:5]:
            static_cnt  = r.get("summary", {}).get("static_finding_count", 0)
            dynamic_cnt = r.get("summary", {}).get("both_detected_count", 0)
            warn(f"{r['package']} @ {r['version']}  (정적 {static_cnt}건 / 동적 {dynamic_cnt}건)")
            for reason in r.get("risk_reasons", []):
                print(f"       근거: {reason}")
        if len(high) > 5:
            info(f"  ... 외 {len(high) - 5}개 (comparison_results.json 참고)")
        print()

    # 정적이 놓친 항목
    dynamic_only_pkgs = [
        r for r in medium
        if r.get("summary", {}).get("dynamic_only_count", 0) > 0
    ]
    if dynamic_only_pkgs:
        info("-- 정적 분석이 놓친 항목 --")
        for r in dynamic_only_pkgs[:5]:
            cats = [d.get("category", "") for d in r.get("dynamic_only", [])]
            warn(f"{r['package']} @ {r['version']}  ({', '.join(cats)})")
        if len(dynamic_only_pkgs) > 5:
            info(f"  ... 외 {len(dynamic_only_pkgs) - 5}개")
        print()

    # 정적 오탐 의심
    static_only_pkgs = [
        r for r in medium
        if r.get("summary", {}).get("static_only_count", 0) > 0
        and r.get("summary", {}).get("dynamic_executed") == False
    ]
    if static_only_pkgs:
        info("-- 정적 분석 오탐 의심 (동적 행위 없음) --")
        for r in static_only_pkgs[:5]:
            ok(f"{r['package']} @ {r['version']}  ->  정적 {r['summary']['static_only_count']}건 탐지, 동적 행위 없음")
        if len(static_only_pkgs) > 5:
            info(f"  ... 외 {len(static_only_pkgs) - 5}개")


def print_final_verdict(
    comparison_results: list,
    install_results: list,
    typo_results: list,
    confusion_results: list
) -> None:
    header("최종 판정")

    high        = [r for r in comparison_results if r.get("risk_level") == "HIGH"]
    meta_issues = len(install_results) + len(typo_results) + len(confusion_results)

    div("=")
    if high:
        print(f"  [위험]  --  위험 행위 조합이 탐지된 패키지가 있습니다.")
        print(f"       탐지 패키지 : {len(high)}개")
        for r in high:
            print(f"         - {r['package']} @ {r['version']}")
            for reason in r.get("risk_reasons", []):
                print(f"             {reason}")
    elif meta_issues > 0:
        print(f"  [주의]  --  메타데이터 이상이 탐지되었습니다.")
        print(f"       메타데이터 이슈 : {meta_issues}건")
    else:
        print("  [안전]  --  분석 범위 내에서 위험 행위 조합이 탐지되지 않았습니다.")
        print("       단, 정적·동적 분석의 한계로 모든 위협을 보장하지는 않습니다.")
    div("=")


# ─── 메인 ────────────────────────────────────────────────────────────────────

def main() -> None:
    project_dir   = "../test_projects/sample-app"
    lockfile_path = f"{project_dir}/package-lock.json"
    npmrc_path    = f"{project_dir}/.npmrc"

    graph_output_path      = f"{project_dir}/dependency_graph.json"
    detection_output_path  = f"{project_dir}/detection_results.json"
    comparison_output_path = f"{project_dir}/comparison_results.json"

    print()
    div("=")
    print("  Node.js 패키지 보안 분석 시스템")
    print(f"  대상 프로젝트 : {project_dir}")
    div("=")

    # ── 1단계 ───────────────────────────────────────────────────────────────
    builder = DependencyGraphBuilder(lockfile_path)
    graph   = builder.build()

    install_results       = detect_install_scripts(graph)
    typo_results          = detect_typosquatting(graph)
    confusion_results     = detect_dependency_confusion(graph, npmrc_path=npmrc_path)

    print_step1(graph, install_results, typo_results, confusion_results)

    # ── 2단계 ───────────────────────────────────────────────────────────────
    ast_results = detect_ast_risks(project_dir)
    print_step2(ast_results)

    # ── 3단계 ───────────────────────────────────────────────────────────────
    dynamic_results = detect_dynamic_risks(project_dir)
    print_step3(dynamic_results)

    # ── 비교 ────────────────────────────────────────────────────────────────
    # [수정] install_script_results도 comparator에 전달
    comparison_results = compare(ast_results, dynamic_results, install_results)
    print_comparison(comparison_results)

    # ── 최종 판정 ───────────────────────────────────────────────────────────
    print_final_verdict(comparison_results, install_results, typo_results, confusion_results)

    # ── 저장 ────────────────────────────────────────────────────────────────
    detection_results = {
        "install_script_results":       install_results,
        "typosquatting_results":        typo_results,
        "dependency_confusion_results": confusion_results,
        "ast_results":                  ast_results,
        "dynamic_results":              dynamic_results,
        "comparison_results":           comparison_results
    }

    save_output(graph, graph_output_path)
    save_output(detection_results, detection_output_path)
    save_output(comparison_results, comparison_output_path)

    print(f"\n  상세 결과 저장 완료")
    print(f"  - {detection_output_path}")
    print(f"  - {comparison_output_path}")
    print()


if __name__ == "__main__":
    main()
