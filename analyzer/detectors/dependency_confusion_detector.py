from typing import Dict, Any, List, Optional
from npmrc_parser import parse_npmrc, extract_registry_host


INTERNAL_SCOPES = [
    "@company",
    "@internal",
    "@corp"
]

INTERNAL_NAME_PREFIXES = [
    "internal-",
    "corp-",
    "company-"
]

PUBLIC_REGISTRY_HOSTS = [
    "registry.npmjs.org",
    "registry.yarnpkg.com"
]


def is_internal_package(package_name: str) -> bool:
    if not package_name:
        return False

    for scope in INTERNAL_SCOPES:
        if package_name.startswith(scope + "/"):
            return True

    for prefix in INTERNAL_NAME_PREFIXES:
        if package_name.startswith(prefix):
            return True

    return False


def get_expected_registry(package_name: str, npmrc_config: Dict[str, Any]) -> Optional[str]:
    if not package_name:
        return npmrc_config.get("default_registry")

    if package_name.startswith("@"):
        scope = package_name.split("/")[0]
        scope_registry = npmrc_config.get("scope_registries", {}).get(scope)
        if scope_registry:
            return scope_registry

    return npmrc_config.get("default_registry")


def get_actual_registry(node_info: Dict[str, Any]) -> Optional[str]:
    return node_info.get("resolved")


def is_public_registry(url: Optional[str]) -> bool:
    host = extract_registry_host(url)
    if not host:
        return False

    return any(public_host in host for public_host in PUBLIC_REGISTRY_HOSTS)


def is_registry_mismatch(expected: Optional[str], actual: Optional[str]) -> bool:
    expected_host = extract_registry_host(expected)
    actual_host = extract_registry_host(actual)

    if not expected_host or not actual_host:
        return False

    return expected_host != actual_host


def detect_dependency_confusion(
    graph: Dict[str, Any],
    npmrc_path: str
) -> List[Dict[str, Any]]:
    results = []
    nodes = graph.get("nodes", {})
    npmrc_config = parse_npmrc(npmrc_path)

    root_name = graph.get("root_id", "").split("@")[0]

    for node_id, node_info in nodes.items():
        package_name = node_info.get("name", "")
        version = node_info.get("version")
        resolved = get_actual_registry(node_info)

        if not package_name or package_name == root_name:
            continue

        internal_candidate = is_internal_package(package_name)
        expected_registry = get_expected_registry(package_name, npmrc_config)

        reasons = []

        if internal_candidate and is_public_registry(resolved):
            reasons.append("internal-style package installed from public registry")

        if expected_registry and resolved and is_registry_mismatch(expected_registry, resolved):
            reasons.append("resolved registry does not match expected registry")

        if package_name.startswith("@") and internal_candidate:
            scope = package_name.split("/")[0]
            scope_registry = npmrc_config.get("scope_registries", {}).get(scope)
            if not scope_registry and is_public_registry(resolved):
                reasons.append("internal scoped package has no private scope registry configuration")

        if internal_candidate and resolved and "registry.npmjs.org" in resolved:
            reasons.append("package expected to be private appears to come from npm public registry")

        if reasons:
            results.append({
                "type": "dependency_confusion",
                "node_id": node_id,
                "package": package_name,
                "version": version,
                "expected_registry": expected_registry,
                "actual_registry": resolved,
                "reason": "; ".join(sorted(set(reasons)))
            })

    return results
