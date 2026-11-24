"""Parsers for Python dependency manifest files (requirements.txt, pyproject.toml, Pipfile, poetry.lock, setup.py)."""

import ast
import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class DependencySpec:
    """Represents a declared dependency parsed from a manifest file."""
    package_name: str
    specifier: str
    raw_line: str
    line_number: int
    manifest_type: str


def normalize_package_name(name: str) -> str:
    """Normalizes package name according to PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def _parse_pep508_requirement(raw_entry: str) -> Optional[Tuple[str, str]]:
    """Parses a PEP 508 dependency declaration into (normalized_name, specifier_or_star).

    Supports extras (e.g., ``requests[security,socks]>=2.25.0``) and strips environment
    markers (e.g., ``; python_version < '3.11'``).
    """
    cleaned = raw_entry.split(";", 1)[0].strip()
    if not cleaned:
        return None
    # Strip PEP 508 extras before matching specifier
    match = re.match(
        r"^([a-zA-Z0-9_\-\.]+)(?:\[[a-zA-Z0-9_,\-\.\s]+\])?\s*([=><~^!].*)?$",
        cleaned,
    )
    if not match:
        return None
    pkg_name = normalize_package_name(match.group(1))
    spec = match.group(2).strip() if match.group(2) else "*"
    return pkg_name, spec


def parse_requirements_txt(content: str) -> List[DependencySpec]:
    """Parses standard requirements.txt content."""
    specs = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        # Skip empty lines, comments, and pip options (-r, -i, etc.)
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue

        # Strip inline comments
        if " #" in stripped:
            stripped = stripped.split(" #", 1)[0].strip()

        parsed = _parse_pep508_requirement(stripped)
        if parsed:
            pkg_name, spec = parsed
            specs.append(DependencySpec(
                package_name=pkg_name,
                specifier=spec,
                raw_line=line,
                line_number=idx,
                manifest_type="requirements.txt"
            ))

    return specs


def parse_pyproject_toml(content: str) -> List[DependencySpec]:
    """Parses pyproject.toml adhering to PEP 621 or Poetry schemas."""
    specs = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return specs

    # 1. PEP 621 project.dependencies
    pep621_deps = data.get("project", {}).get("dependencies", [])
    if isinstance(pep621_deps, list):
        for dep in pep621_deps:
            if not isinstance(dep, str):
                continue
            parsed = _parse_pep508_requirement(dep)
            if parsed:
                pkg_name, spec = parsed
                specs.append(DependencySpec(
                    package_name=pkg_name,
                    specifier=spec,
                    raw_line=dep,
                    line_number=0,
                    manifest_type="pyproject.toml"
                ))

    # 2. Poetry tool.poetry.dependencies
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for pkg, val in poetry_deps.items():
            if pkg.lower() == "python":
                continue
            pkg_name = normalize_package_name(pkg)
            if isinstance(val, str):
                spec = val
            elif isinstance(val, dict) and "version" in val:
                spec = str(val["version"])
            else:
                spec = "*"
            specs.append(DependencySpec(
                package_name=pkg_name,
                specifier=spec,
                raw_line=f"{pkg} = {val}",
                line_number=0,
                manifest_type="pyproject.toml"
            ))

    return specs


def parse_pipfile(content: str) -> List[DependencySpec]:
    """Parses Pipfile TOML sections."""
    specs = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return specs

    packages = data.get("packages", {})
    if isinstance(packages, dict):
        for pkg, val in packages.items():
            if isinstance(val, dict):
                spec = str(val.get("version", "*")).strip('"\'')
            else:
                spec = str(val).strip('"\'')
            specs.append(DependencySpec(
                package_name=normalize_package_name(pkg),
                specifier=spec or "*",
                raw_line=f"{pkg} = {val}",
                line_number=0,
                manifest_type="Pipfile"
            ))

    return specs


def parse_poetry_lock(content: str) -> List[DependencySpec]:
    """Parses poetry.lock TOML package declarations."""
    specs = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return specs

    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            specs.append(DependencySpec(
                package_name=normalize_package_name(name),
                specifier=f"=={version}",
                raw_line=f"name = {name}, version = {version}",
                line_number=0,
                manifest_type="poetry.lock"
            ))

    return specs


def _extract_string_list(node: ast.AST, env_lists: Dict[str, List[str]]) -> List[str]:
    """Safely extracts constant string lists from an AST node without executing code."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        out: List[str] = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                out.append(elt.value)
        return out
    if isinstance(node, ast.Name) and node.id in env_lists:
        return list(env_lists[node.id])
    return []


def parse_setup_py(content: str) -> List[DependencySpec]:
    """Statically parses install_requires declarations in setup.py using AST (no code execution)."""
    specs: List[DependencySpec] = []
    parsed_entries: List[Tuple[str, int]] = []

    try:
        tree = ast.parse(content)
        env_lists: Dict[str, List[str]] = {}
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                items = _extract_string_list(stmt.value, env_lists)
                if items:
                    env_lists[stmt.targets[0].id] = items

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                if func_name != "setup":
                    continue
                for kw in node.keywords:
                    if kw.arg == "install_requires":
                        if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                            for elt in kw.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    parsed_entries.append((elt.value, getattr(elt, "lineno", 0)))
                        else:
                            for val in _extract_string_list(kw.value, env_lists):
                                parsed_entries.append((val, getattr(kw.value, "lineno", 0)))
    except SyntaxError:
        match_block = re.search(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
        if match_block:
            for idx, val in enumerate(re.findall(r"['\"]([^'\"]+)['\"]", match_block.group(1)), start=1):
                parsed_entries.append((val, idx))

    for idx, (dep, lineno) in enumerate(parsed_entries, start=1):
        dep_clean = dep.strip()
        parsed = _parse_pep508_requirement(dep_clean)
        if parsed:
            pkg_name, spec = parsed
            specs.append(DependencySpec(
                package_name=pkg_name,
                specifier=spec,
                raw_line=dep_clean,
                line_number=lineno if lineno > 0 else idx,
                manifest_type="setup.py"
            ))

    return specs

