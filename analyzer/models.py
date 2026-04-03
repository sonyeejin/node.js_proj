from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class PackageNode:
    id: str
    name: str
    version: Optional[str]
    path: str
    raw_dependencies: Dict[str, str] = field(default_factory=dict)
    has_install_script: bool = False
    resolved: Optional[str] = None


@dataclass
class DependencyEdge:
    source: str
    target: str
