"""
comparator.py

정적 분석(AST) 결과와 동적 분석 결과를 비교하여
'정적에서만 탐지', '동적에서만 탐지', '둘 다 탐지' 로 분류한다.

핵심 목적:
  - 정적 분석 오탐(False Positive) 식별
    → 정적에서 탐지됐지만 동적에서 아무 행위 없는 경우
  - 정적 분석 미탐(False Negative) 식별
    → 정적에서 못 잡았지만 동적에서 실제 행위가 발생한 경우

위험도 판정 기준 (행위 조합 기반):
  HIGH   - 아래 조건 중 하나 이상 충족
           1. env_access + network 조합 (정보 수집 후 외부 전송 의심)
           2. process_execution + network 조합 (명령 실행 후 외부 통신 의심)
           3. filesystem write/delete 발생 (파일 조작)
           4. install script 실행 중 network 발생
  MEDIUM - HIGH 조건 없이 정적 또는 동적 탐지만 있는 경우
  LOW    - 탐지 없음
  UNKNOWN- 동적 분석 실패
"""

from typing import Any, Dict, List


# ─── 정적 finding 타입 → 동적 카테고리 매핑 ──────────────────────────────────

STATIC_TO_DYNAMIC_CATEGORY = {
    "external_communication":   "network",
    "system_command_execution": "process_execution",
    "system_info_access":       "env_access",
    "dynamic_execution":        None,
    "obfuscation":              None,
}

# 파일 시스템 write/delete 액션 (read는 모듈 로드 시 정상 발생)
DANGEROUS_FS_ACTIONS = {"write", "append", "delete", "mkdir", "copy"}


# ─── 핵심 비교 함수 ───────────────────────────────────────────────────────────

def compare(
    static_results:  List[Dict[str, Any]],
    dynamic_results: List[Dict[str, Any]],
    install_script_results: List[Dict[str, Any]] = []
) -> List[Dict[str, Any]]:
    """
    정적 분석 결과와 동적 분석 결과를 패키지 단위로 비교한다.

    Args:
        static_results:         AST 정적 분석 결과 리스트
        dynamic_results:        동적 분석 결과 리스트
        install_script_results: 1단계 install script 탐지 결과

    Returns:
        패키지별 비교 결과 리스트
    """
    dynamic_map = _build_dynamic_map(dynamic_results)

    # install script가 있는 패키지 이름 집합
    install_script_pkgs = {r.get("package") for r in install_script_results}

    comparison_results = []

    for static_pkg in static_results:
        package_name    = static_pkg.get("package", "unknown")
        version         = static_pkg.get("version", "unknown")
        static_findings = static_pkg.get("findings", [])

        dynamic_pkg = dynamic_map.get(package_name, _empty_dynamic_result(package_name))

        result = _compare_package(
            package_name          = package_name,
            version               = version,
            static_findings       = static_findings,
            dynamic_pkg           = dynamic_pkg,
            has_install_script    = package_name in install_script_pkgs
        )

        comparison_results.append(result)

    return comparison_results


# ─── 패키지 단위 비교 ─────────────────────────────────────────────────────────

def _compare_package(
    package_name:       str,
    version:            str,
    static_findings:    List[Dict[str, Any]],
    dynamic_pkg:        Dict[str, Any],
    has_install_script: bool = False
) -> Dict[str, Any]:

    dynamic_network   = dynamic_pkg.get("network", [])
    dynamic_process   = dynamic_pkg.get("process_execution", [])
    dynamic_env       = dynamic_pkg.get("env_access", [])
    dynamic_fs        = dynamic_pkg.get("filesystem", [])

    dynamic_has_network   = len(dynamic_network) > 0
    dynamic_has_process   = len(dynamic_process) > 0
    dynamic_has_env       = len(dynamic_env) > 0
    dynamic_has_fs        = len(dynamic_fs) > 0
    dynamic_has_any       = dynamic_has_network or dynamic_has_process or dynamic_has_env or dynamic_has_fs

    # 파일 시스템 접근 중 위험 액션(write/delete 등)만 필터링
    dangerous_fs = [f for f in dynamic_fs if f.get("action") in DANGEROUS_FS_ACTIONS]

    # ── 정적 finding 분류 ─────────────────────────────────────────────────────
    static_only   = []
    both_detected = []

    for finding in static_findings:
        static_type      = finding.get("type", "")
        dynamic_category = STATIC_TO_DYNAMIC_CATEGORY.get(static_type)

        if dynamic_category is None:
            static_only.append(finding)
            continue

        dynamic_data = dynamic_pkg.get(dynamic_category, [])
        if len(dynamic_data) > 0:
            both_detected.append({
                "static_finding":   finding,
                "dynamic_evidence": dynamic_data
            })
        else:
            static_only.append(finding)

    # ── 동적에서만 탐지된 항목 ───────────────────────────────────────────────
    static_types_detected = set(f.get("type") for f in static_findings)
    dynamic_only = []

    if dynamic_has_network and "external_communication" not in static_types_detected:
        dynamic_only.append({
            "category":    "network",
            "evidence":    dynamic_network,
            "description": "정적 분석에서 탐지되지 않았으나 실행 시 네트워크 요청 발생"
        })

    if dynamic_has_process and "system_command_execution" not in static_types_detected:
        dynamic_only.append({
            "category":    "process_execution",
            "evidence":    dynamic_process,
            "description": "정적 분석에서 탐지되지 않았으나 실행 시 프로세스 실행 발생"
        })

    if dynamic_has_env and "system_info_access" not in static_types_detected:
        dynamic_only.append({
            "category":    "env_access",
            "evidence":    dynamic_env,
            "description": "정적 분석에서 탐지되지 않았으나 실행 시 환경 변수 접근 발생"
        })

    if dangerous_fs:
        dynamic_only.append({
            "category":    "filesystem",
            "evidence":    dangerous_fs,
            "description": "실행 시 파일 쓰기/삭제 등 파일 시스템 조작 발생"
        })

    # ── 위험도 판정 ───────────────────────────────────────────────────────────
    risk_level, risk_reasons = _assess_risk(
        dynamic_has_network   = dynamic_has_network,
        dynamic_has_process   = dynamic_has_process,
        dynamic_has_env       = dynamic_has_env,
        dangerous_fs          = dangerous_fs,
        has_install_script    = has_install_script,
        both_detected         = both_detected,
        dynamic_only          = dynamic_only,
        static_findings       = static_findings,
        dynamic_errors        = dynamic_pkg.get("errors", []),
        analysis_timeout      = dynamic_pkg.get("metadata", {}).get("analysis_timeout", False)
    )

    return {
        "package":          package_name,
        "version":          version,
        "risk_level":       risk_level,
        "risk_reasons":     risk_reasons,   # 판정 근거 목록
        "both_detected":    both_detected,
        "static_only":      static_only,
        "dynamic_only":     dynamic_only,
        "summary": _build_summary(
            static_findings = static_findings,
            both_detected   = both_detected,
            static_only     = static_only,
            dynamic_only    = dynamic_only,
            dynamic_has_any = dynamic_has_any
        ),
        "dynamic_metadata": dynamic_pkg.get("metadata", {}),
        "dynamic_errors":   dynamic_pkg.get("errors", [])
    }


# ─── 위험도 판정 ──────────────────────────────────────────────────────────────

def _assess_risk(
    dynamic_has_network:  bool,
    dynamic_has_process:  bool,
    dynamic_has_env:      bool,
    dangerous_fs:         List,
    has_install_script:   bool,
    both_detected:        List,
    dynamic_only:         List,
    static_findings:      List,
    dynamic_errors:       List,
    analysis_timeout:     bool
):
    """
    행위 조합 기반 위험도 판정.

    단일 행위만으로는 판단하지 않고 조합으로 판단한다.
    - env_access 단독: 정상 패키지도 흔하므로 위험으로 보지 않음
    - process_exec 단독: 빌드 도구도 쓰므로 위험으로 보지 않음
    - network 단독: API 호출도 있으므로 위험으로 보지 않음
    - 조합 발생 시 위험 판정
    """
    # 동적 분석 실패
    analysis_errors = [e for e in dynamic_errors if e.get("type") == "analysis_error"]
    if analysis_errors or analysis_timeout:
        return "UNKNOWN", ["동적 분석 실패 또는 타임아웃"]

    reasons = []

    # ── HIGH 판정 조건 ────────────────────────────────────────────────────────

    # 조건 1: env_access + network 조합
    # → 시스템 정보 수집 후 외부 전송 의심 (ua-parser-js 유형)
    if dynamic_has_env and dynamic_has_network:
        reasons.append("환경 변수 접근 + 네트워크 요청 조합 탐지 (정보 탈취 의심)")

    # 조건 2: process_execution + network 조합
    # → 명령 실행 후 외부 통신 의심
    if dynamic_has_process and dynamic_has_network:
        reasons.append("프로세스 실행 + 네트워크 요청 조합 탐지 (원격 제어 의심)")

    # 조건 3: 파일 시스템 write/delete 발생
    # → 파일 조작 행위 (node-ipc 유형)
    if dangerous_fs:
        actions = list(set(f.get("action") for f in dangerous_fs))
        reasons.append(f"파일 시스템 조작 탐지 ({', '.join(actions)})")

    # 조건 4: install script 있는 패키지에서 network 발생
    # → 설치 중 외부 통신 의심
    if has_install_script and dynamic_has_network:
        reasons.append("install script 실행 중 네트워크 요청 탐지")

    if reasons:
        return "HIGH", reasons

    # ── MEDIUM 판정 ───────────────────────────────────────────────────────────
    if len(both_detected) > 0 or len(dynamic_only) > 0 or len(static_findings) > 0:
        return "MEDIUM", []

    return "LOW", []


# ─── 요약 생성 ────────────────────────────────────────────────────────────────

def _build_summary(
    static_findings: List,
    both_detected:   List,
    static_only:     List,
    dynamic_only:    List,
    dynamic_has_any: bool
) -> Dict[str, Any]:

    notes = []

    if len(both_detected) > 0:
        notes.append(f"정적·동적 모두 탐지된 항목 {len(both_detected)}건")

    if len(static_only) > 0 and not dynamic_has_any:
        notes.append(f"정적 탐지 {len(static_only)}건, 동적 행위 없음 (오탐 가능성)")

    if len(dynamic_only) > 0:
        notes.append(f"동적에서만 탐지된 항목 {len(dynamic_only)}건 (정적 분석 한계)")

    if len(static_findings) == 0 and not dynamic_has_any:
        notes.append("정적·동적 모두 위험 행위 없음")

    return {
        "static_finding_count": len(static_findings),
        "both_detected_count":  len(both_detected),
        "static_only_count":    len(static_only),
        "dynamic_only_count":   len(dynamic_only),
        "dynamic_executed":     dynamic_has_any,
        "notes":                notes
    }


# ─── 내부 헬퍼 ───────────────────────────────────────────────────────────────

def _build_dynamic_map(dynamic_results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    result = {}
    for pkg in dynamic_results:
        name = pkg.get("metadata", {}).get("package") or pkg.get("package", "unknown")
        if name and name != "unknown":
            result[name] = pkg
    return result


def _empty_dynamic_result(package_name: str) -> Dict[str, Any]:
    return {
        "metadata":          {"package": package_name, "version": "unknown", "analysis_timeout": False},
        "network":           [],
        "filesystem":        [],
        "process_execution": [],
        "env_access":        [],
        "errors":            [{"type": "not_analyzed", "message": "동적 분석 미실행"}]
    }
