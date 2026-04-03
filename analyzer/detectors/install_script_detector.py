from typing import Dict, Any, List


LIFECYCLE_SCRIPT_KEYS = ["preinstall", "install", "postinstall"]


def detect_install_scripts(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []
    nodes = graph.get("nodes", {})

    for node_id, node_info in nodes.items():
        if node_info.get("has_install_script", False):
            results.append({
                "type": "install_script",
                "node_id": node_id,
                "package": node_info.get("name"),
                "version": node_info.get("version"),
                "script_keys_checked": LIFECYCLE_SCRIPT_KEYS,
                "reason": "설치 시 자동 실행 가능한 lifecycle script 존재"
            })

    return results
