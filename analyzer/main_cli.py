"""
main_cli.py — 웹 UI에서 호출하는 분석 실행기
프로젝트 경로를 인자로 받아서 분석 실행 후 dashboard.html 생성
사용법: python3 main_cli.py <project_dir>
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict

from graph_builder import DependencyGraphBuilder
from detectors.install_script_detector import detect_install_scripts
from detectors.typosquatting_detector import detect_typosquatting
from detectors.dependency_confusion_detector import detect_dependency_confusion
from detectors.ast_detector import detect_ast_risks
from detectors.dynamic_analyzer import detect_dynamic_risks
from comparator import compare
from dashboard import generate_dashboard_html


def save_output(data: Any, output_path: str) -> None:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def div(char: str = "-", width: int = 52) -> None:
    print(char * width, flush=True)

def header(title: str) -> None:
    print(f"\n+{'-' * 50}+", flush=True)
    print(f"|  {title:<48}|", flush=True)
    print(f"+{'-' * 50}+", flush=True)

def ok(msg: str):   print(f"  [OK]  {msg}", flush=True)
def warn(msg: str): print(f"  [!!]  {msg}", flush=True)
def info(msg: str): print(f"  -  {msg}", flush=True)


def print_step1(graph, install_results, typo_results, confusion_results):
    header("1단계 · 메타데이터 분석")
    pkg_count = len([n for n in graph['nodes'].values() if n.get('path','') != ''])
    info(f"패키지 수  : {pkg_count}개  |  의존성 엣지 : {len(graph['edges'])}개")
    print(flush=True)
    if not install_results and not typo_results and not confusion_results:
        ok("Install Script / Typosquatting / Dependency Confusion — 이상 없음")
        return
    for item in install_results[:5]:
        warn(f"[Install Script]  {item['package']} @ {item['version']}  ->  {item['reason']}")
    for item in typo_results[:5]:
        warn(f"[Typosquatting]   {item['package']} @ {item['version']}  ->  {item['reason']}")
    for item in confusion_results[:5]:
        warn(f"[Dep Confusion]   {item['package']} @ {item['version']}  ->  {item['reason']}")


def print_step2(ast_results):
    header("2단계 · AST 정적 분석")
    total_findings = sum(len(p.get("findings", [])) for p in ast_results)
    pkgs_with = sorted([p for p in ast_results if p.get("findings")],
                       key=lambda p: len(p.get("findings", [])), reverse=True)
    info(f"분석 패키지  : {len(ast_results)}개")
    info(f"탐지 패키지  : {len(pkgs_with)}개  |  총 탐지 건수 : {total_findings}건")
    print(flush=True)
    if not pkgs_with:
        ok("정적 분석 — 위험 패턴 없음")
        return
    TYPE_KO = {
        "dynamic_execution": "동적 코드 실행",
        "system_command_execution": "시스템 명령 실행",
        "external_communication": "외부 통신",
        "system_info_access": "시스템 정보 접근",
        "obfuscation": "난독화 패턴",
    }
    type_counter: Dict[str, int] = {}
    for pkg in ast_results:
        for f in pkg.get("findings", []):
            t = f.get("type", "unknown")
            type_counter[t] = type_counter.get(t, 0) + 1
    for t, cnt in sorted(type_counter.items(), key=lambda x: -x[1]):
        warn(f"{TYPE_KO.get(t,t):<18} : {cnt}건")
    print(flush=True)
    info("주요 탐지 패키지 (상위 5개)")
    for pkg in pkgs_with[:5]:
        info(f"  {pkg['package']} @ {pkg['version']}  ->  {len(pkg.get('findings',[]))}건")
    if len(pkgs_with) > 5:
        info(f"  ... 외 {len(pkgs_with)-5}개")


def print_step3(dynamic_results):
    header("3단계 · 동적 분석")
    active = [p for p in dynamic_results if any(len(p.get(k,[])) > 0 for k in ["network","process_execution","env_access","filesystem"])]
    errors = [p for p in dynamic_results if any(e.get("type") == "analysis_error" for e in p.get("errors",[]))]
    info(f"분석 패키지  : {len(dynamic_results)}개")
    info(f"행위 발생    : {len(active)}개  |  분석 실패 : {len(errors)}개")
    print(flush=True)
    if not active:
        ok("동적 분석 — 실제 행위 없음")
        return
    cat_counter = {"network":0,"process_execution":0,"env_access":0,"filesystem":0}
    for pkg in active:
        for cat in cat_counter: cat_counter[cat] += len(pkg.get(cat,[]))
    CAT_KO = {"network":"네트워크 요청","process_execution":"프로세스 실행","env_access":"환경 변수 접근","filesystem":"파일 시스템 접근"}
    for cat, cnt in cat_counter.items():
        if cnt > 0: warn(f"{CAT_KO[cat]:<16} : {cnt}건")
    print(flush=True)
    active_sorted = sorted(active, key=lambda p: sum(len(p.get(k,[])) for k in ["network","process_execution","env_access","filesystem"]), reverse=True)
    info("실제 행위 발생 패키지 (상위 5개)")
    for pkg in active_sorted[:5]:
        name = pkg.get("metadata",{}).get("package","unknown")
        ver  = pkg.get("metadata",{}).get("version","unknown")
        acts = []
        if pkg.get("network"):           acts.append(f"네트워크 {len(pkg['network'])}건")
        if pkg.get("process_execution"): acts.append(f"프로세스 {len(pkg['process_execution'])}건")
        if pkg.get("env_access"):        acts.append(f"env {len(pkg['env_access'])}건")
        if pkg.get("filesystem"):        acts.append(f"파일 {len(pkg['filesystem'])}건")
        info(f"  {name} @ {ver}  ->  {', '.join(acts)}")
    if len(active) > 5:
        info(f"  ... 외 {len(active)-5}개")


def print_comparison(comparison_results):
    header("정적 vs 동적 비교")
    high    = [r for r in comparison_results if r.get("risk_level") == "HIGH"]
    medium  = [r for r in comparison_results if r.get("risk_level") == "MEDIUM"]
    low     = [r for r in comparison_results if r.get("risk_level") == "LOW"]
    unknown = [r for r in comparison_results if r.get("risk_level") == "UNKNOWN"]

    medium_both = [r for r in medium
                   if r.get("summary",{}).get("both_detected_count",0) > 0
                   or (r.get("summary",{}).get("static_only_count",0) > 0
                       and r.get("summary",{}).get("dynamic_only_count",0) > 0)]
    medium_static_only  = [r for r in medium
                           if r.get("summary",{}).get("static_only_count",0) > 0
                           and r.get("summary",{}).get("dynamic_only_count",0) == 0
                           and r.get("summary",{}).get("both_detected_count",0) == 0]
    medium_dynamic_only = [r for r in medium
                           if r.get("summary",{}).get("dynamic_only_count",0) > 0
                           and r.get("summary",{}).get("static_only_count",0) == 0
                           and r.get("summary",{}).get("both_detected_count",0) == 0]

    info(f"HIGH    : {len(high)}개   (행위 조합 기반 위험 탐지)")
    if medium_both:        info(f"MEDIUM  : {len(medium_both)}개   (정적·동적 모두 탐지)")
    if medium_static_only: info(f"MEDIUM  : {len(medium_static_only)}개   (정적에서만 탐지)")
    if medium_dynamic_only:info(f"MEDIUM  : {len(medium_dynamic_only)}개   (동적에서만 탐지)")
    info(f"LOW     : {len(low)}개   (탐지 없음)")
    info(f"UNKNOWN : {len(unknown)}개   (분석 실패)")
    print(flush=True)

    if high:
        info("-- 위험 탐지 패키지 --")
        for r in high[:5]:
            s = r.get("summary",{})
            warn(f"{r['package']} @ {r['version']}  (정적 {s.get('static_finding_count',0)}건 / 동적 {'발생' if s.get('dynamic_executed') else '없음'})")
            for reason in r.get("risk_reasons",[]):
                print(f"       근거: {reason}", flush=True)
        print(flush=True)


def print_final_verdict(comparison_results, install_results, typo_results, confusion_results):
    header("최종 판정")
    high = [r for r in comparison_results if r.get("risk_level") == "HIGH"]
    meta_issues = len(install_results) + len(typo_results) + len(confusion_results)
    div("=")
    if high:
        print("  [위험]  --  위험 행위 조합이 탐지된 패키지가 있습니다.", flush=True)
        print(f"       탐지 패키지 : {len(high)}개", flush=True)
        for r in high:
            print(f"         - {r['package']} @ {r['version']}", flush=True)
            for reason in r.get("risk_reasons",[]):
                print(f"             {reason}", flush=True)
    elif meta_issues > 0:
        print(f"  [주의]  --  메타데이터 이상이 탐지되었습니다.", flush=True)
        print(f"       메타데이터 이슈 : {meta_issues}건", flush=True)
    else:
        print("  [안전]  --  분석 범위 내에서 위험 행위 조합이 탐지되지 않았습니다.", flush=True)
    div("=")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 main_cli.py <project_dir>", flush=True)
        sys.exit(1)

    project_dir   = str(Path(sys.argv[1]).resolve())
    lockfile_path = f"{project_dir}/package-lock.json"
    npmrc_path    = f"{project_dir}/.npmrc"
    
    print(flush=True)
    div("=")
    print("  Node.js 패키지 보안 분석 시스템", flush=True)
    print(f"  대상 프로젝트 : {project_dir}", flush=True)
    div("=")

    # 1단계
    builder           = DependencyGraphBuilder(lockfile_path)
    graph             = builder.build()
    install_results   = detect_install_scripts(graph)
    typo_results      = detect_typosquatting(graph)
    confusion_results = detect_dependency_confusion(graph, npmrc_path=npmrc_path)
    print_step1(graph, install_results, typo_results, confusion_results)

    # 2단계
    ast_results = detect_ast_risks(project_dir)
    print_step2(ast_results)

    # 3단계
    dynamic_results = detect_dynamic_risks(project_dir)
    print_step3(dynamic_results)

    # 비교
    comparison_results = compare(ast_results, dynamic_results, install_results)
    print_comparison(comparison_results)

    # 최종 판정
    print_final_verdict(comparison_results, install_results, typo_results, confusion_results)

    # 저장
    detection_results = {
        "install_script_results":       install_results,
        "typosquatting_results":        typo_results,
        "dependency_confusion_results": confusion_results,
        "ast_results":                  ast_results,
        "dynamic_results":              dynamic_results,
        "comparison_results":           comparison_results
    }
    save_output(graph,             f"{project_dir}/dependency_graph.json")
    save_output(detection_results, f"{project_dir}/detection_results.json")
    save_output(comparison_results,f"{project_dir}/comparison_results.json")

    # 대시보드 HTML 생성 (서버 실행 없이)
    generate_dashboard_html(detection_results, comparison_results, graph, project_dir)
    print(f"\n  대시보드 생성 완료 : {project_dir}/dashboard.html", flush=True)


if __name__ == "__main__":
    main()
