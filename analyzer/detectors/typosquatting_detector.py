from typing import Dict, Any, List


POPULAR_PACKAGES = [
    "lodash",
    "express",
    "axios",
    "react",
    "vue",
    "debug",
    "chalk",
    "commander",
    "mongoose",
    "body-parser"
]


def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0

    if len(a) < len(b):
        return levenshtein_distance(b, a)

    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_typosquatting(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []
    nodes = graph.get("nodes", {})

    for node_id, node_info in nodes.items():
        package_name = node_info.get("name", "")

        if not package_name:
            continue

        for popular_name in POPULAR_PACKAGES:
            if package_name == popular_name:
                continue

            distance = levenshtein_distance(package_name, popular_name)

            if distance in [1, 2]:
                results.append({
                    "type": "typosquatting",
                    "node_id": node_id,
                    "package": package_name,
                    "version": node_info.get("version"),
                    "similar_to": popular_name,
                    "distance": distance,
                    "reason": "정상 패키지와 유사한 이름 탐지"
                })
                break

    return results
