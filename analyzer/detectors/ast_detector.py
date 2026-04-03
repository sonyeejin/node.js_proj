import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any


def detect_ast_risks(project_dir: str) -> Dict[str, List[Dict[str, Any]]]:
    script_path = Path(__file__).resolve().parent / "babel_ast_detector.js"

    result = subprocess.run(
        ["node", str(script_path), project_dir],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        stderr_text = result.stderr.strip()

        try:
            error_obj = json.loads(stderr_text)
            error_message = error_obj.get("error", stderr_text)
        except Exception:
            error_message = stderr_text or "Unknown Babel AST detector error"

        return {
            "findings": [],
            "parse_errors": [
                {
                    "file": "N/A",
                    "type": "runtime_error",
                    "pattern": "babel_ast_detector_failed",
                    "description": error_message
                }
            ]
        }

    stdout_text = result.stdout.strip()

    try:
        parsed = json.loads(stdout_text)
    except json.JSONDecodeError:
        return {
            "findings": [],
            "parse_errors": [
                {
                    "file": "N/A",
                    "type": "runtime_error",
                    "pattern": "invalid_json_output",
                    "description": stdout_text[:500]
                }
            ]
        }

    return {
        "findings": parsed.get("findings", []),
        "parse_errors": parsed.get("parse_errors", [])
    }
