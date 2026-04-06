import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional


# ─── 상수 ────────────────────────────────────────────────────────────────────

DOCKER_IMAGE_NAME = "npm-dynamic-analyzer"
DOCKER_FILE_DIR   = Path(__file__).resolve().parent.parent / "docker"

# 패키지당 분석 타임아웃 (초)
# dynamic_runner.js 내부 타임아웃 + Docker 강제 종료 여유
CONTAINER_TIMEOUT = 25

# [성능] 동시 실행할 컨테이너 수
# M2 맥북에어 기준 4개가 적정 (CPU/메모리 여유 고려)
# 컨테이너당 메모리 256m × 4 = 1GB 사용
MAX_WORKERS = 4


# ─── Docker 이미지 빌드 ───────────────────────────────────────────────────────

def ensure_docker_image() -> Optional[str]:
    """
    Docker 이미지가 없으면 빌드한다.
    이미 있으면 스킵 (매 분석마다 빌드하지 않음).
    반환값: 에러 메시지 (성공 시 None)
    """
    check = subprocess.run(
        ["docker", "image", "inspect", DOCKER_IMAGE_NAME],
        capture_output=True
    )
    if check.returncode == 0:
        return None

    build = subprocess.run(
        ["docker", "build", "-t", DOCKER_IMAGE_NAME, str(DOCKER_FILE_DIR)],
        capture_output=True,
        text=True,
        timeout=120
    )

    if build.returncode != 0:
        return f"Docker 이미지 빌드 실패: {build.stderr.strip()}"

    return None


# ─── 패키지 단위 분석 ─────────────────────────────────────────────────────────

def analyze_package(package_path: str, node_modules_path: str) -> Dict[str, Any]:
    """
    단일 패키지를 Docker 컨테이너에서 동적 분석한다.
    ThreadPoolExecutor에서 병렬로 호출된다.

    Args:
        package_path:      분석할 패키지의 절대 경로
        node_modules_path: 전체 node_modules 경로 (의존성 해결용)

    Returns:
        동적 분석 결과 딕셔너리
    """
    package_name = Path(package_path).name

    try:
        result = subprocess.run(
            [
                "docker", "run",
                "--rm",
                "--network=none",         # 실제 외부 통신 차단 (후킹으로 URL만 기록)
                "--memory=256m",
                "--cpus=0.5",
                "--read-only",
                "--tmpfs=/tmp:size=64m",
                "-v", f"{package_path}:/pkg:ro",
                "-v", f"{node_modules_path}:/node_modules:ro",
                DOCKER_IMAGE_NAME,
                "/pkg"
            ],
            capture_output=True,
            text=True,
            timeout=CONTAINER_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return _error_result(package_name, "컨테이너 실행 타임아웃")
    except FileNotFoundError:
        return _error_result(package_name, "Docker 실행 파일을 찾을 수 없습니다")
    except Exception as e:
        return _error_result(package_name, str(e))

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if not stdout:
        error_msg = stderr or "컨테이너가 빈 결과를 반환했습니다"
        return _error_result(package_name, error_msg)

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as e:
        return _error_result(package_name, f"JSON 파싱 실패: {str(e)}")

    if not isinstance(parsed, dict):
        return _error_result(package_name, "분석 결과 형식이 올바르지 않습니다")

    return parsed


# ─── 프로젝트 전체 분석 ───────────────────────────────────────────────────────

def detect_dynamic_risks(project_dir: str) -> List[Dict[str, Any]]:
    """
    Node.js 프로젝트의 node_modules 내 패키지를 동적 분석한다.
    [성능 개선] ThreadPoolExecutor로 MAX_WORKERS개 컨테이너를 병렬 실행한다.

    Args:
        project_dir: 분석할 Node.js 프로젝트 루트 경로

    Returns:
        패키지별 동적 분석 결과 리스트 (입력 순서 유지)
    """
    node_modules_path = Path(project_dir) / "node_modules"

    if not node_modules_path.is_dir():
        return [_error_result("unknown", f"node_modules 디렉토리를 찾을 수 없습니다: {node_modules_path}")]

    build_error = ensure_docker_image()
    if build_error:
        return [_error_result("unknown", build_error)]

    packages = _collect_packages(node_modules_path)
    if not packages:
        return []

    node_modules_str = str(node_modules_path)

    # [성능 개선] 병렬 실행
    # - futures 딕셔너리로 완료 순서와 무관하게 원래 순서 유지
    results: List[Optional[Dict[str, Any]]] = [None] * len(packages)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # index와 함께 submit해서 나중에 순서 복원
        future_to_index = {
            executor.submit(
                analyze_package,
                str(pkg_path),
                node_modules_str
            ): idx
            for idx, pkg_path in enumerate(packages)
        }

        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                pkg_name = packages[idx].name
                results[idx] = _error_result(pkg_name, str(e))

    # None 제거 (혹시 모를 누락 방어)
    return [r for r in results if r is not None]


# ─── 내부 헬퍼 ───────────────────────────────────────────────────────────────

def _collect_packages(node_modules_path: Path) -> List[Path]:
    """
    node_modules에서 분석 대상 패키지 경로 목록을 수집한다.
    scoped 패키지(@scope/name)도 처리한다.
    """
    packages = []

    for entry in sorted(node_modules_path.iterdir()):
        if not entry.is_dir():
            continue

        if entry.name.startswith("@"):
            for scoped_entry in sorted(entry.iterdir()):
                if scoped_entry.is_dir() and (scoped_entry / "package.json").exists():
                    packages.append(scoped_entry)
        else:
            if (entry / "package.json").exists():
                packages.append(entry)

    return packages


def _error_result(package_name: str, message: str) -> Dict[str, Any]:
    """에러 결과 객체를 일관된 형식으로 생성한다."""
    return {
        "metadata": {
            "package":          package_name,
            "version":          "unknown",
            "analysis_timeout": False
        },
        "network":           [],
        "filesystem":        [],
        "process_execution": [],
        "env_access":        [],
        "errors": [{"type": "analysis_error", "message": message}]
    }
