from typing import Optional


def make_node_id(name: str, version: Optional[str]) -> str:
    version = version or "unknown"
    return f"{name}@{version}"


def extract_name_from_path(package_path: str) -> str:
    """
    예:
    node_modules/express -> express
    node_modules/@babel/parser -> @babel/parser
    node_modules/a/node_modules/b -> b
    """
    if not package_path.startswith("node_modules/"):
        return package_path or "unknown"

    parts = package_path.split("node_modules/")[1:]
    last = parts[-1].strip("/")

    if last.startswith("@"):
        scope_parts = last.split("/")
        if len(scope_parts) >= 2:
            return f"{scope_parts[0]}/{scope_parts[1]}"
    return last
