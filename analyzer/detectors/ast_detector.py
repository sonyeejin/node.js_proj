import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any


def detect_ast_risks(project_dir: str) -> List[Dict[str, Any]]:
    """
    Node.js 프로젝트의 node_modules를 AST 기반으로 정적 분석한다.
    내부적으로 babel_ast_detector.js를 subprocess로 실행하고 결과를 반환한다.

    Args:
        project_dir: 분석할 Node.js 프로젝트 루트 경로

    Returns:
        패키지별 분석 결과 리스트 (package, version, findings 포함)
    """
    script_path = Path(__file__).resolve().parent / "babel_ast_detector.js"

    # JS 분석기 파일 존재 여부 사전 확인
    if not script_path.exists():
        return [_error_result("babel_ast_detector.js 파일을 찾을 수 없습니다.")]

    # 프로젝트 디렉토리 존재 여부 사전 확인
    if not Path(project_dir).is_dir():
        return [_error_result(f"프로젝트 디렉토리를 찾을 수 없습니다: {project_dir}")]

    try:
        result = subprocess.run(
            ["node", str(script_path), project_dir],
            capture_output=True,
            text=True,
            timeout=120  # 대형 프로젝트 고려해 60 → 120초로 증가
        )
    except FileNotFoundError:
        return [_error_result("Node.js 실행 파일을 찾을 수 없습니다. Node.js가 설치되어 있는지 확인하세요.")]
    except subprocess.TimeoutExpired:
        return [_error_result("AST 분석 시간 초과 (120초). 프로젝트 규모가 너무 크거나 문제가 발생했습니다.")]
    except Exception as e:
        return [_error_result(f"예상치 못한 오류: {str(e)}")]

    # JS 프로세스가 비정상 종료된 경우
    if result.returncode != 0:
        error_message = _parse_stderr(result.stderr)
        return [_error_result(error_message)]

    stdout_text = result.stdout.strip()

    if not stdout_text:
        return [_error_result("분석기가 빈 결과를 반환했습니다.")]

    try:
        parsed = json.loads(stdout_text)
    except json.JSONDecodeError as e:
        return [_error_result(f"JSON 파싱 실패: {str(e)}")]

    if not isinstance(parsed, list):
        return [_error_result("분석기 출력 형식이 올바르지 않습니다 (list 형식이어야 합니다).")]

    # 빈 결과 (분석할 패키지가 없는 경우)
    if len(parsed) == 0:
        return []

    # 각 항목 유효성 검사 후 반환
    return [_normalize_package_result(item) for item in parsed]


# ─── 내부 헬퍼 함수 ──────────────────────────────────────────────────────────

def _error_result(message: str) -> Dict[str, Any]:
    """에러 결과 객체를 일관된 형식으로 생성한다."""
    return {
        "package": "unknown",
        "version": "unknown",
        "findings": [],
        "error": message
    }


def _parse_stderr(stderr: str) -> str:
    """
    JS 프로세스의 stderr를 파싱해 에러 메시지를 추출한다.
    JS 쪽에서 JSON 형태로 에러를 출력하는 경우와 일반 텍스트 모두 처리한다.
    """
    stderr_text = stderr.strip()
    if not stderr_text:
        return "알 수 없는 오류 (stderr 없음)"

    try:
        error_obj = json.loads(stderr_text)
        return error_obj.get("error", stderr_text)
    except (json.JSONDecodeError, AttributeError):
        return stderr_text


def _normalize_package_result(item: Any) -> Dict[str, Any]:
    """
    JS 분석기 결과 항목을 정규화한다.
    필수 필드가 없을 경우 기본값으로 채운다.
    """
    if not isinstance(item, dict):
        return _error_result("패키지 결과 항목이 올바른 형식이 아닙니다.")

    return {
        "package": item.get("package", "unknown"),
        "version": item.get("version", "unknown"),
        "findings": item.get("findings", []),
        # parse_errors, error 필드는 존재할 때만 포함
        **({ "parse_errors": item["parse_errors"] } if item.get("parse_errors") else {}),
        **({ "error": item["error"] } if item.get("error") else {})
    }
