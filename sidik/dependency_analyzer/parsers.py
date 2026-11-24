"""Parsers for Python dependency manifest files (requirements.txt, pyproject.toml, Pipfile, poetry.lock, setup.py)."""

import ast
import json
import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from urllib.parse import unquote
from packaging.version import InvalidVersion, Version

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


_VCS_OR_URL_PREFIXES = ("git+", "hg+", "svn+", "bzr+", "http://", "https://")
_SHA_REF_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")


def _extract_version_from_ref(ref: Optional[str]) -> Optional[str]:
    """Extracts a dotted PEP 440 release version (e.g., v2.19.0 -> ==2.19.0) from a Git ref/tag."""
    if not ref:
        return None
    cleaned = ref.strip().strip("\"'")
    if not cleaned or _SHA_REF_RE.match(cleaned):
        return None
    m = re.search(
        r"(?:^|[-_/vV])([0-9]+\.[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc|post|dev)[0-9]+)?)$",
        cleaned,
    )
    if not m:
        return None
    ver_str = m.group(1)
    try:
        Version(ver_str)
    except InvalidVersion:
        return None
    return f"=={ver_str}"


def _extract_name_and_spec_from_url(
    raw_url: str,
    fallback_name: Optional[str] = None,
) -> Optional[Tuple[str, str]]:
    """Extracts (normalized_name, version_spec_or_star) from a VCS repo or archive/wheel URL."""
    url = raw_url.strip().strip("\"'")
    if not url:
        return None

    base_url, _, frag = url.partition("#")
    egg_name: Optional[str] = None
    if frag:
        m_egg = re.search(r"(?:^|&)egg=([^&\s]+)", frag)
        if m_egg:
            raw_egg = unquote(m_egg.group(1)).split("[", 1)[0].strip()
            if raw_egg:
                egg_name = raw_egg

    if "://" not in base_url:
        return None
    _, rest = base_url.split("://", 1)
    _, _, path_part = rest.partition("/")
    clean_path = path_part
    ref_part: Optional[str] = None
    if "@" in path_part:
        clean_path, ref_part = path_part.rsplit("@", 1)

    spec = _extract_version_from_ref(ref_part)
    segs = [unquote(s) for s in clean_path.split("/") if s]
    last_seg = segs[-1] if segs else ""
    pkg_from_url: Optional[str] = None

    if last_seg.endswith(".whl"):
        parts = last_seg[:-4].split("-")
        if len(parts) >= 2:
            pkg_from_url = parts[0]
            if not spec:
                try:
                    Version(parts[1])
                    spec = f"=={parts[1]}"
                except InvalidVersion:
                    pass
    else:
        stripped_seg = re.sub(r"\.(?:tar\.gz|tar\.bz2|tar\.xz|tgz|zip)$", "", last_seg, flags=re.IGNORECASE)
        is_archive = stripped_seg != last_seg
        if is_archive and "/archive/" in f"/{clean_path.lower()}/":
            # GitHub/GitLab tag archive e.g. /owner/repo/archive/refs/tags/v1.26.5.tar.gz
            if not spec:
                spec = _extract_version_from_ref(stripped_seg)
            try:
                arch_idx = [s.lower() for s in segs].index("archive")
                if arch_idx > 0:
                    pkg_from_url = segs[arch_idx - 1]
            except ValueError:
                pass
        elif is_archive:
            m_sdist = re.match(
                r"^([a-zA-Z0-9_.\-]+?)-([0-9]+\.[0-9]+(?:\.[0-9a-zA-Z]+)*)$",
                stripped_seg,
            )
            if m_sdist:
                pkg_from_url = m_sdist.group(1)
                if not spec:
                    spec = _extract_version_from_ref(m_sdist.group(2))
            else:
                pkg_from_url = stripped_seg
        elif last_seg:
            pkg_from_url = last_seg[:-4] if last_seg.endswith(".git") else last_seg

    chosen_name = fallback_name or egg_name or pkg_from_url
    if not chosen_name:
        return None
    return normalize_package_name(chosen_name), spec or "*"


def _parse_pep508_requirement(raw_entry: str) -> Optional[Tuple[str, str]]:
    """Parses a PEP 508 declaration, direct URL (pkg @ git+...), or VCS/archive URL.

    Supports extras (e.g., ``requests[security,socks]>=2.25.0``), strips environment
    markers (e.g., ``; python_version < '3.11'``), and resolves Git tag refs when present.
    """
    cleaned = raw_entry.split(";", 1)[0].strip()
    if not cleaned:
        return None

    m_direct = re.match(
        r"^([a-zA-Z0-9_\-\.]+)(?:\[[a-zA-Z0-9_,\-\.\s]+\])?\s*@\s*(\S+)$",
        cleaned,
    )
    if m_direct:
        return _extract_name_and_spec_from_url(m_direct.group(2), fallback_name=m_direct.group(1))

    if cleaned.lower().startswith(_VCS_OR_URL_PREFIXES):
        return _extract_name_and_spec_from_url(cleaned)

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
    """Parses standard requirements.txt content including VCS/Git and editable URLs."""
    specs = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Strip inline comments preceded by whitespace
        if " #" in stripped:
            stripped = stripped.split(" #", 1)[0].strip()

        m_edit = re.match(r"^(?:-e|--editable)(?:\s+|=)(\S+)$", stripped)
        if m_edit:
            target_url = m_edit.group(1).strip()
            if target_url.lower().startswith(_VCS_OR_URL_PREFIXES):
                stripped = target_url
            else:
                continue
        elif stripped.startswith("-"):
            continue

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
    """Parses pyproject.toml adhering to PEP 621, PEP 735 dependency-groups, or Poetry schemas."""
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

    # 2. PEP 621 project.optional-dependencies
    opt_deps = data.get("project", {}).get("optional-dependencies", {})
    if isinstance(opt_deps, dict):
        for _group, entries in opt_deps.items():
            if not isinstance(entries, list):
                continue
            for dep in entries:
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

    # 3. PEP 735 dependency-groups
    dep_groups = data.get("dependency-groups", {})
    if isinstance(dep_groups, dict):
        for _group, entries in dep_groups.items():
            if not isinstance(entries, list):
                continue
            for dep in entries:
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

    # 4. Poetry tool.poetry.dependencies, dev-dependencies, and groups
    def _collect_poetry_map(dep_map: object) -> None:
        if not isinstance(dep_map, dict):
            return
        for pkg, val in dep_map.items():
            if not isinstance(pkg, str) or pkg.lower() == "python":
                continue
            pkg_name = normalize_package_name(pkg)
            if isinstance(val, str):
                spec = val
            elif isinstance(val, dict):
                spec = _spec_from_manifest_dict(pkg_name, val)
            else:
                spec = "*"
            specs.append(DependencySpec(
                package_name=pkg_name,
                specifier=spec,
                raw_line=f"{pkg} = {val}",
                line_number=0,
                manifest_type="pyproject.toml"
            ))

    poetry_cfg = data.get("tool", {}).get("poetry", {})
    if isinstance(poetry_cfg, dict):
        _collect_poetry_map(poetry_cfg.get("dependencies"))
        _collect_poetry_map(poetry_cfg.get("dev-dependencies"))
        poetry_groups = poetry_cfg.get("group", {})
        if isinstance(poetry_groups, dict):
            for grp in poetry_groups.values():
                if isinstance(grp, dict):
                    _collect_poetry_map(grp.get("dependencies"))

    return specs


def parse_pipfile_lock(content: str) -> List[DependencySpec]:
    """Parses Pipfile.lock JSON package sections (default and develop)."""
    specs: List[DependencySpec] = []
    try:
        data = json.loads(content)
    except Exception:
        return specs
    if not isinstance(data, dict):
        return specs

    for section in ("default", "develop"):
        pkgs = data.get(section, {})
        if not isinstance(pkgs, dict):
            continue
        for pkg, meta in pkgs.items():
            if not isinstance(pkg, str) or not isinstance(meta, dict):
                continue
            ver = str(meta.get("version", "*")).strip() or "*"
            specs.append(DependencySpec(
                package_name=normalize_package_name(pkg),
                specifier=ver,
                raw_line=f"{pkg}{ver if ver != '*' else ''}",
                line_number=0,
                manifest_type="Pipfile.lock",
            ))
    return specs


def parse_uv_lock(content: str) -> List[DependencySpec]:
    """Parses uv.lock TOML package declarations."""
    specs: List[DependencySpec] = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return specs

    for pkg in data.get("package", []):
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            specs.append(DependencySpec(
                package_name=normalize_package_name(str(name)),
                specifier=f"=={version}",
                raw_line=f"name = {name}, version = {version}",
                line_number=0,
                manifest_type="uv.lock",
            ))
    return specs


def _spec_from_manifest_dict(pkg_name: str, meta: Dict[object, object]) -> str:
    """Resolves a version specifier from Poetry/Pipfile dict entries ({version, git, tag, ref, url})."""
    if "version" in meta:
        return str(meta["version"]).strip("\"'") or "*"
    for ref_key in ("tag", "ref", "rev"):
        if ref_key in meta and isinstance(meta[ref_key], str):
            v_ref = _extract_version_from_ref(meta[ref_key])
            if v_ref:
                return v_ref
    for url_key in ("url", "git", "file"):
        if url_key in meta and isinstance(meta[url_key], str):
            parsed = _extract_name_and_spec_from_url(meta[url_key], fallback_name=pkg_name)
            if parsed and parsed[1] != "*":
                return parsed[1]
    return "*"


def parse_pipfile(content: str) -> List[DependencySpec]:
    """Parses Pipfile [packages] and [dev-packages] TOML sections."""
    specs = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return specs

    for section in ("packages", "dev-packages"):
        packages = data.get(section, {})
        if not isinstance(packages, dict):
            continue
        for pkg, val in packages.items():
            if not isinstance(pkg, str):
                continue
            pkg_name = normalize_package_name(pkg)
            if isinstance(val, dict):
                spec = _spec_from_manifest_dict(pkg_name, val)
            else:
                spec = str(val).strip("\"'") or "*"
            specs.append(DependencySpec(
                package_name=pkg_name,
                specifier=spec,
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

