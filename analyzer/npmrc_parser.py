from pathlib import Path
from typing import Dict, Optional, Any


def parse_npmrc(npmrc_path: str) -> Dict[str, Any]:
    path = Path(npmrc_path)

    result = {
        "default_registry": None,
        "scope_registries": {}
    }

    if not path.exists():
        return result

    lines = path.read_text(encoding="utf-8").splitlines()

    for raw_line in lines:
        line = raw_line.strip()

        if not line or line.startswith("#") or line.startswith(";"):
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key == "registry":
            result["default_registry"] = value
            continue

        if key.endswith(":registry") and key.startswith("@"):
            scope = key.replace(":registry", "").strip()
            result["scope_registries"][scope] = value

    return result


def extract_registry_host(url: Optional[str]) -> Optional[str]:
    if not url:
        return None

    cleaned = url.strip()

    if cleaned.startswith("https://"):
        cleaned = cleaned[len("https://"):]
    elif cleaned.startswith("http://"):
        cleaned = cleaned[len("http://"):]

    return cleaned.split("/")[0] if cleaned else None
