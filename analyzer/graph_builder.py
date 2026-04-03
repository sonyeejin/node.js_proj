import json
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any, Set

from models import PackageNode, DependencyEdge
from utils import make_node_id, extract_name_from_path


class DependencyGraphBuilder:
    def __init__(self, lockfile_path: str):
        self.lockfile_path = Path(lockfile_path)
        self.lockfile: Dict[str, Any] = {}

        self.nodes: Dict[str, PackageNode] = {}
        self.children: Dict[str, List[str]] = defaultdict(list)
        self.parents: Dict[str, List[str]] = defaultdict(list)
        self.edges: List[DependencyEdge] = []

        self.root_id: Optional[str] = None

    def load_lockfile(self) -> None:
        if not self.lockfile_path.exists():
            raise FileNotFoundError(f"Lockfile not found: {self.lockfile_path}")

        with self.lockfile_path.open("r", encoding="utf-8") as f:
            self.lockfile = json.load(f)

    def build(self) -> Dict[str, Any]:
        self.load_lockfile()

        if "packages" in self.lockfile:
            self._build_from_packages_format()
        elif "dependencies" in self.lockfile:
            self._build_from_dependencies_format()
        else:
            raise ValueError("Unsupported package-lock.json format")

        return self.to_dict()

    def _add_node(
        self,
        node_id: str,
        name: str,
        version: Optional[str],
        path: str,
        raw_dependencies: Optional[Dict[str, str]] = None,
        has_install_script: bool = False,
        resolved: Optional[str] = None
    ) -> None:
        if node_id not in self.nodes:
            self.nodes[node_id] = PackageNode(
                id=node_id,
                name=name,
                version=version,
                path=path,
                raw_dependencies=raw_dependencies or {},
                has_install_script=has_install_script,
                resolved=resolved
            )

    def _add_edge(self, parent_id: str, child_id: str) -> None:
        if child_id not in self.children[parent_id]:
            self.children[parent_id].append(child_id)

        if parent_id not in self.parents[child_id]:
            self.parents[child_id].append(parent_id)

        edge = DependencyEdge(source=parent_id, target=child_id)
        if edge not in self.edges:
            self.edges.append(edge)

    def _has_install_script(self, package_info: Dict[str, Any]) -> bool:
        return bool(package_info.get("hasInstallScript", False))

    def _build_from_packages_format(self) -> None:
        packages = self.lockfile.get("packages", {})
        root_info = packages.get("", {})
        root_name = root_info.get("name", "root-project")
        root_version = root_info.get("version", "0.0.0")
        self.root_id = make_node_id(root_name, root_version)

        self._add_node(
            node_id=self.root_id,
            name=root_name,
            version=root_version,
            path="",
            raw_dependencies=root_info.get("dependencies", {}),
            has_install_script=False,
            resolved=None
        )

        for package_path, package_info in packages.items():
            if package_path == "":
                continue

            name = package_info.get("name") or extract_name_from_path(package_path)
            version = package_info.get("version")
            node_id = make_node_id(name, version)

            self._add_node(
                node_id=node_id,
                name=name,
                version=version,
                path=package_path,
                raw_dependencies=package_info.get("dependencies", {}),
                has_install_script=self._has_install_script(package_info),
                resolved=package_info.get("resolved")
            )

        root_deps = root_info.get("dependencies", {})
        for dep_name, dep_spec in root_deps.items():
            child_id = self._find_best_match_for_root_dependency(dep_name, dep_spec, packages)
            if child_id:
                self._add_edge(self.root_id, child_id)

        for package_path, package_info in packages.items():
            if package_path == "":
                continue

            parent_name = package_info.get("name") or extract_name_from_path(package_path)
            parent_version = package_info.get("version")
            parent_id = make_node_id(parent_name, parent_version)

            dependencies = package_info.get("dependencies", {})
            for dep_name in dependencies.keys():
                child_id = self._find_best_child_for_package(package_path, dep_name, packages)
                if child_id:
                    self._add_edge(parent_id, child_id)

    def _find_best_match_for_root_dependency(
        self,
        dep_name: str,
        dep_spec: str,
        packages: Dict[str, Any]
    ) -> Optional[str]:
        direct_path = f"node_modules/{dep_name}" # 1단계: 직접 경로로 바로 찾기

        info = packages.get(direct_path)
        if info:
            name = info.get("name") or extract_name_from_path(direct_path)
            version = info.get("version")
            return make_node_id(name, version)

        suffix = f"node_modules/{dep_name}"
        candidates = []

        for path, info in packages.items(): # 2단계: endswith로 후보 전부 수집
            if path.endswith(suffix):
                version = info.get("version")
                depth = path.count("node_modules")
                candidates.append((path, info, version, depth))

        if not candidates:
            return None

        matched = [ # 3단계: 버전 조건 맞는 것만 필터
            (path, info, version, depth)
            for path, info, version, depth in candidates
            if self._version_matches(dep_spec, version)
        ]

        pool = matched if matched else candidates # 4단계: 버전 맞는 게 없으면 전체 후보 사용
        pool.sort(key=lambda x: (x[3], x[0])) # 5단계: depth 기준 정렬 후 첫 번째 반환
        best_path, best_info, _, _ = pool[0]

        name = best_info.get("name") or extract_name_from_path(best_path)
        version = best_info.get("version")
        return make_node_id(name, version)
        #버전 조건 비교하는 함수
    def _version_matches(self, dep_spec: str, actual_version: Optional[str]) -> bool:
        if not dep_spec or not actual_version:
            return False

        dep_spec = dep_spec.strip()
        actual_version = actual_version.strip()

        if dep_spec == actual_version:
            return True

        for prefix in ["^", "~", ">=", "<=", ">", "<", "="]:
            if dep_spec.startswith(prefix):
                dep_spec = dep_spec[len(prefix):].strip()
                break

        return dep_spec == actual_version

    def _find_best_child_for_package(
        self,
        parent_path: str,
        dep_name: str,
        packages: Dict[str, Any]
    ) -> Optional[str]:
        candidate_paths = []
        current = parent_path

        while True:
            candidate_paths.append(f"{current}/node_modules/{dep_name}")
            idx = current.rfind("/node_modules/")
            if idx == -1:
                break
            current = current[:idx]

        candidate_paths.append(f"node_modules/{dep_name}")

        for candidate in candidate_paths:
            if candidate in packages:
                info = packages[candidate]
                name = info.get("name") or extract_name_from_path(candidate)
                version = info.get("version")
                return make_node_id(name, version)

        for path, info in packages.items():
            if path.endswith(f"node_modules/{dep_name}"):
                name = info.get("name") or extract_name_from_path(path)
                version = info.get("version")
                return make_node_id(name, version)

        return None

    def _build_from_dependencies_format(self) -> None:
        root_name = self.lockfile.get("name", "root-project")
        root_version = self.lockfile.get("version", "0.0.0")
        self.root_id = make_node_id(root_name, root_version)

        self._add_node(
            node_id=self.root_id,
            name=root_name,
            version=root_version,
            path="",
            raw_dependencies={},
            has_install_script=False,
            resolved=None
        )

        dependencies = self.lockfile.get("dependencies", {})
        self._walk_dependencies_recursive(self.root_id, dependencies, "")

    def _walk_dependencies_recursive(
        self,
        parent_id: str,
        dependencies: Dict[str, Any],
        parent_path: str
    ) -> None:
        for dep_name, dep_info in dependencies.items():
            version = dep_info.get("version")
            node_id = make_node_id(dep_name, version)
            path = f"{parent_path}/node_modules/{dep_name}" if parent_path else f"node_modules/{dep_name}"

            self._add_node(
                node_id=node_id,
                name=dep_name,
                version=version,
                path=path,
                raw_dependencies=dep_info.get("dependencies", {}),
                has_install_script=False,
                resolved=dep_info.get("resolved")
            )
            self._add_edge(parent_id, node_id)

            child_deps = dep_info.get("dependencies", {})
            if child_deps:
                self._walk_dependencies_recursive(node_id, child_deps, path)

    def trace_paths_to_root(self, target_node_id: str) -> List[List[str]]:
        if target_node_id not in self.nodes:
            return []

        results = []

        def dfs(current: str, path: List[str]) -> None:
            if current == self.root_id:
                results.append(path[::-1])
                return

            for parent in self.parents.get(current, []):
                dfs(parent, path + [parent])

        dfs(target_node_id, [target_node_id])
        return results

    def bfs_from_root(self) -> List[str]:
        if not self.root_id:
            return []

        visited: Set[str] = set()
        order: List[str] = []
        queue = deque([self.root_id])

        while queue:
            current = queue.popleft()
            if current in visited:
                continue

            visited.add(current)
            order.append(current)

            for child in self.children.get(current, []):
                if child not in visited:
                    queue.append(child)

        return order

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_id": self.root_id,
            "nodes": {node_id: vars(node) for node_id, node in self.nodes.items()},
            "children": dict(self.children),
            "parents": dict(self.parents),
            "edges": [
                {"from": edge.source, "to": edge.target}
                for edge in self.edges
            ]
        }
