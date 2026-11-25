"""Parsers for Python and multi-ecosystem dependency manifest and lockfile formats."""

import ast
import json
import re
import xml.etree.ElementTree as ET
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
    ecosystem: str = "PyPI"


def normalize_package_name(name: str) -> str:
    """Normalizes Python package name according to PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def normalize_ecosystem_package_name(name: str, ecosystem: str = "PyPI") -> str:
    """Normalizes package names using ecosystem conventions (PEP 503 for PyPI, exact for Go/Maven, lowercase otherwise)."""
    eco = (ecosystem or "PyPI").strip().lower()
    if eco == "pypi":
        return normalize_package_name(name)
    if eco in ("go", "maven"):
        return name.strip()
    return name.strip().lower()


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


# ---------------------------------------------------------------------------
# Multi-Ecosystem Manifest & Lockfile Parsers (npm, Go, Rust, Maven, PHP, Ruby, .NET)
# ---------------------------------------------------------------------------

def _extract_git_semver(raw_spec: str) -> str:
    """Extracts a release tag like #v1.2.3 or @v1.2.3 as ==1.2.3, or '*'."""
    m = re.search(r"[#@](?:v|V)?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?)$", raw_spec.strip())
    if m:
        ver_core = m.group(1).split("+", 1)[0]
        return f"=={ver_core}"
    return "*"


def parse_package_json(content: str) -> List[DependencySpec]:
    """Parses npm package.json dependency sections."""
    specs: List[DependencySpec] = []
    try:
        data = json.loads(content)
    except Exception:
        return specs
    if not isinstance(data, dict):
        return specs

    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        sec_obj = data.get(section)
        if not isinstance(sec_obj, dict):
            continue
        for pkg, raw_ver in sec_obj.items():
            if not isinstance(pkg, str) or not isinstance(raw_ver, str):
                continue
            ver_s = raw_ver.strip()
            if ver_s.startswith(("workspace:", "file:", "link:", "portal:", "catalog:")):
                continue
            if ver_s.startswith(("git+", "http://", "https://", "git://")):
                spec = _extract_git_semver(ver_s)
            else:
                spec = ver_s or "*"
            specs.append(DependencySpec(
                package_name=normalize_ecosystem_package_name(pkg, "npm"),
                specifier=spec,
                raw_line=f'"{pkg}": "{raw_ver}"',
                line_number=0,
                manifest_type="package.json",
                ecosystem="npm",
            ))
    return specs


def _walk_npm_v1_deps(deps: Dict[str, object], out: List[DependencySpec], seen: set) -> None:
    for pkg, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        ver = meta.get("version")
        if isinstance(ver, str) and ver.strip():
            norm = normalize_ecosystem_package_name(pkg, "npm")
            ver_clean = ver.strip()
            if (norm, ver_clean) not in seen:
                seen.add((norm, ver_clean))
                out.append(DependencySpec(
                    package_name=norm,
                    specifier=f"=={ver_clean}",
                    raw_line=f'"{pkg}": "{ver_clean}"',
                    line_number=0,
                    manifest_type="package-lock.json",
                    ecosystem="npm",
                ))
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            _walk_npm_v1_deps(nested, out, seen)


def parse_package_lock_json(content: str) -> List[DependencySpec]:
    """Parses npm package-lock.json (lockfileVersion 1, 2, and 3)."""
    specs: List[DependencySpec] = []
    try:
        data = json.loads(content)
    except Exception:
        return specs
    if not isinstance(data, dict):
        return specs

    seen: set = set()
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, meta in packages.items():
            if not isinstance(pkg_path, str) or "node_modules/" not in pkg_path or not isinstance(meta, dict):
                continue
            pkg_name = pkg_path.rsplit("node_modules/", 1)[-1].strip()
            ver = meta.get("version")
            if pkg_name and isinstance(ver, str) and ver.strip():
                norm = normalize_ecosystem_package_name(pkg_name, "npm")
                ver_clean = ver.strip()
                if (norm, ver_clean) not in seen:
                    seen.add((norm, ver_clean))
                    specs.append(DependencySpec(
                        package_name=norm,
                        specifier=f"=={ver_clean}",
                        raw_line=f'"{pkg_path}": "{ver_clean}"',
                        line_number=0,
                        manifest_type="package-lock.json",
                        ecosystem="npm",
                    ))
        if specs:
            return specs

    deps = data.get("dependencies")
    if isinstance(deps, dict):
        _walk_npm_v1_deps(deps, specs, seen)
    return specs


def parse_yarn_lock(content: str) -> List[DependencySpec]:
    """Parses yarn.lock (Yarn Classic v1 and Yarn Berry) resolved package versions."""
    specs: List[DependencySpec] = []
    seen: set = set()
    current_names: List[str] = []
    header_pkg_re = re.compile(r"^((?:@[^/@\s]+/)?[^@\s:,\"']+)@")
    version_re = re.compile(r'^\s+version(?:\s*:\s*|\s+)"?([^"\s]+)"?')

    for idx, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            if not stripped:
                current_names = []
            continue
        if not raw_line[0].isspace() and stripped.endswith(":"):
            if stripped in ("__metadata:",):
                current_names = []
                continue
            names: List[str] = []
            for part in stripped[:-1].split(","):
                tok = part.strip().strip("\"'")
                m = header_pkg_re.match(tok)
                if m:
                    names.append(normalize_ecosystem_package_name(m.group(1), "npm"))
            current_names = names
        elif current_names:
            vm = version_re.match(raw_line)
            if vm:
                ver_clean = vm.group(1).strip()
                for name in current_names:
                    if (name, ver_clean) not in seen:
                        seen.add((name, ver_clean))
                        specs.append(DependencySpec(
                            package_name=name,
                            specifier=f"=={ver_clean}",
                            raw_line=f"{name}@{ver_clean}",
                            line_number=idx,
                            manifest_type="yarn.lock",
                            ecosystem="npm",
                        ))
                current_names = []
    return specs


def parse_pnpm_lock_yaml(content: str) -> List[DependencySpec]:
    """Parses pnpm-lock.yaml resolved package versions across v5-v9 formats."""
    specs: List[DependencySpec] = []
    seen: set = set()
    section: Optional[str] = None
    v6_plus_re = re.compile(r"^\s{2,4}['\"]?/?((?:@[^/@'\"]+/)?[^/@'\"\s]+)@([0-9][^\s('\":]+)")
    v5_re = re.compile(r"^\s{2,4}['\"]?/((?:@[^/@'\"]+/)?[^/@'\"]+)/([0-9][^_('\s\":]+)")

    for idx, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line[0].isspace() and stripped.endswith(":"):
            sec_name = stripped[:-1].lower()
            section = sec_name if sec_name in ("packages", "snapshots") else None
            continue
        if section not in ("packages", "snapshots"):
            continue

        m = v6_plus_re.match(line) or v5_re.match(line)
        if not m:
            continue
        pkg_name = normalize_ecosystem_package_name(m.group(1), "npm")
        ver_clean = m.group(2).split("(", 1)[0].split("_", 1)[0].strip()
        if pkg_name and ver_clean and (pkg_name, ver_clean) not in seen:
            seen.add((pkg_name, ver_clean))
            specs.append(DependencySpec(
                package_name=pkg_name,
                specifier=f"=={ver_clean}",
                raw_line=stripped,
                line_number=idx,
                manifest_type="pnpm-lock.yaml",
                ecosystem="npm",
            ))
    return specs


def parse_go_mod(content: str) -> List[DependencySpec]:
    """Parses Go go.mod module require declarations."""
    specs: List[DependencySpec] = []
    in_require = False
    req_entry_re = re.compile(r"^([^\s]+)\s+(v?[^\s]+)$")

    for idx, raw_line in enumerate(content.splitlines(), start=1):
        code = raw_line.split("//", 1)[0].strip()
        if not code:
            continue
        if in_require:
            if code == ")":
                in_require = False
                continue
            target = code
        elif code == "require (":
            in_require = True
            continue
        elif code.startswith("require ") and "(" not in code:
            target = code[len("require "):].strip()
        else:
            continue

        m = req_entry_re.match(target)
        if not m:
            continue
        mod_path = normalize_ecosystem_package_name(m.group(1), "Go")
        ver_raw = m.group(2).strip()
        ver_clean = ver_raw.lstrip("vV").split("+", 1)[0]
        if mod_path and ver_clean:
            specs.append(DependencySpec(
                package_name=mod_path,
                specifier=f"=={ver_clean}",
                raw_line=raw_line.strip(),
                line_number=idx,
                manifest_type="go.mod",
                ecosystem="Go",
            ))
    return specs


def parse_cargo_toml(content: str) -> List[DependencySpec]:
    """Parses Rust Cargo.toml dependency declarations."""
    specs: List[DependencySpec] = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return specs

    sections: List[Dict[str, object]] = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        if isinstance(data.get(key), dict):
            sections.append(data[key])
    ws = data.get("workspace")
    if isinstance(ws, dict) and isinstance(ws.get("dependencies"), dict):
        sections.append(ws["dependencies"])

    seen: set = set()
    for sec in sections:
        for crate_key, val in sec.items():
            crate_name = crate_key
            spec_str = "*"
            if isinstance(val, str):
                spec_str = val.strip() or "*"
            elif isinstance(val, dict):
                if isinstance(val.get("package"), str) and val["package"].strip():
                    crate_name = val["package"].strip()
                if isinstance(val.get("version"), str) and val["version"].strip():
                    spec_str = val["version"].strip()
                elif isinstance(val.get("tag"), str):
                    spec_str = _extract_git_semver("#" + val["tag"])
                elif isinstance(val.get("path"), str):
                    continue
            norm = normalize_ecosystem_package_name(crate_name, "crates.io")
            if norm and (norm, spec_str) not in seen:
                seen.add((norm, spec_str))
                specs.append(DependencySpec(
                    package_name=norm,
                    specifier=spec_str,
                    raw_line=f"{crate_key} = {val!r}",
                    line_number=0,
                    manifest_type="Cargo.toml",
                    ecosystem="crates.io",
                ))
    return specs


def parse_cargo_lock(content: str) -> List[DependencySpec]:
    """Parses Rust Cargo.lock resolved crate versions."""
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
        if isinstance(name, str) and isinstance(version, str) and name.strip() and version.strip():
            norm = normalize_ecosystem_package_name(name, "crates.io")
            specs.append(DependencySpec(
                package_name=norm,
                specifier=f"=={version.strip()}",
                raw_line=f"name = {name}, version = {version}",
                line_number=0,
                manifest_type="Cargo.lock",
                ecosystem="crates.io",
            ))
    return specs


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_pom_xml(content: str) -> List[DependencySpec]:
    """Parses Apache Maven pom.xml dependencies with property substitution."""
    specs: List[DependencySpec] = []
    try:
        root = ET.fromstring(content)
    except Exception:
        return specs

    props: Dict[str, str] = {}
    for child in root:
        lname = _xml_local_name(child.tag)
        if lname == "version" and child.text:
            props["project.version"] = child.text.strip()
        elif lname == "properties":
            for prop in child:
                if prop.text:
                    props[_xml_local_name(prop.tag)] = prop.text.strip()

    def _resolve_prop(raw: str) -> str:
        def _sub(m: re.Match) -> str:
            return props.get(m.group(1), m.group(0))
        return re.sub(r"\$\{([^}]+)\}", _sub, raw.strip())

    for elem in root.iter():
        if _xml_local_name(elem.tag) != "dependency":
            continue
        gid = ""
        aid = ""
        ver = ""
        for sub in elem:
            sname = _xml_local_name(sub.tag)
            text = (sub.text or "").strip()
            if sname == "groupId":
                gid = text
            elif sname == "artifactId":
                aid = text
            elif sname == "version":
                ver = _resolve_prop(text)
        if not (gid and aid):
            continue
        coord = normalize_ecosystem_package_name(f"{gid}:{aid}", "Maven")
        if not ver or "${" in ver:
            spec = "*"
        elif any(op in ver for op in ("[", "(", ",", "<", ">")):
            spec = ver
        else:
            spec = f"=={ver.lstrip('vV')}"
        specs.append(DependencySpec(
            package_name=coord,
            specifier=spec,
            raw_line=f"{coord}:{ver or '*'}",
            line_number=0,
            manifest_type="pom.xml",
            ecosystem="Maven",
        ))
    return specs


def parse_composer_json(content: str) -> List[DependencySpec]:
    """Parses PHP Packagist composer.json dependencies."""
    specs: List[DependencySpec] = []
    try:
        data = json.loads(content)
    except Exception:
        return specs
    if not isinstance(data, dict):
        return specs

    for section in ("require", "require-dev"):
        sec_obj = data.get(section)
        if not isinstance(sec_obj, dict):
            continue
        for pkg, raw_ver in sec_obj.items():
            if not isinstance(pkg, str) or not isinstance(raw_ver, str):
                continue
            pkg_low = pkg.strip().lower()
            if pkg_low in ("php", "php-64bit", "hhvm") or pkg_low.startswith(("ext-", "lib-", "composer-")):
                continue
            ver_clean = raw_ver.strip() or "*"
            specs.append(DependencySpec(
                package_name=normalize_ecosystem_package_name(pkg, "Packagist"),
                specifier=ver_clean,
                raw_line=f'"{pkg}": "{raw_ver}"',
                line_number=0,
                manifest_type="composer.json",
                ecosystem="Packagist",
            ))
    return specs


def parse_composer_lock(content: str) -> List[DependencySpec]:
    """Parses PHP Packagist composer.lock resolved package versions."""
    specs: List[DependencySpec] = []
    try:
        data = json.loads(content)
    except Exception:
        return specs
    if not isinstance(data, dict):
        return specs

    seen: set = set()
    for section in ("packages", "packages-dev"):
        arr = data.get(section)
        if not isinstance(arr, list):
            continue
        for pkg in arr:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            ver = pkg.get("version")
            if isinstance(name, str) and isinstance(ver, str) and name.strip() and ver.strip():
                norm = normalize_ecosystem_package_name(name, "Packagist")
                ver_clean = ver.strip().lstrip("vV")
                if (norm, ver_clean) not in seen:
                    seen.add((norm, ver_clean))
                    specs.append(DependencySpec(
                        package_name=norm,
                        specifier=f"=={ver_clean}",
                        raw_line=f"{name}@{ver_clean}",
                        line_number=0,
                        manifest_type="composer.lock",
                        ecosystem="Packagist",
                    ))
    return specs


def parse_gemfile_lock(content: str) -> List[DependencySpec]:
    """Parses RubyGems Gemfile.lock GEM specs section."""
    specs: List[DependencySpec] = []
    seen: set = set()
    in_gem = False
    in_specs = False
    gem_re = re.compile(r"^    ([A-Za-z0-9._-]+)\s+\(([^)]+)\)\s*$")

    for idx, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            in_specs = False
            continue
        if not line[0].isspace():
            in_gem = (line.strip() == "GEM")
            in_specs = False
            continue
        if not in_gem:
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        if not in_specs:
            continue

        m = gem_re.match(line)
        if not m:
            continue
        gem_name = normalize_ecosystem_package_name(m.group(1), "RubyGems")
        ver_tok = m.group(2).strip().split("-", 1)[0]
        if gem_name and ver_tok and (gem_name, ver_tok) not in seen:
            seen.add((gem_name, ver_tok))
            specs.append(DependencySpec(
                package_name=gem_name,
                specifier=f"=={ver_tok}",
                raw_line=line.strip(),
                line_number=idx,
                manifest_type="Gemfile.lock",
                ecosystem="RubyGems",
            ))
    return specs


def parse_csproj(content: str) -> List[DependencySpec]:
    """Parses .NET NuGet *.csproj <PackageReference> declarations."""
    specs: List[DependencySpec] = []
    try:
        root = ET.fromstring(content)
    except Exception:
        return specs

    for elem in root.iter():
        if _xml_local_name(elem.tag).lower() != "packagereference":
            continue
        include = elem.attrib.get("Include") or elem.attrib.get("include") or ""
        ver = elem.attrib.get("Version") or elem.attrib.get("version") or ""
        if not ver:
            for sub in elem:
                if _xml_local_name(sub.tag).lower() == "version" and sub.text:
                    ver = sub.text.strip()
                    break
        if not include.strip():
            continue
        pkg_norm = normalize_ecosystem_package_name(include, "NuGet")
        ver_clean = ver.strip()
        spec = f"=={ver_clean.lstrip('vV')}" if ver_clean and not any(c in ver_clean for c in "[(*,<>=~^") else (ver_clean or "*")
        specs.append(DependencySpec(
            package_name=pkg_norm,
            specifier=spec,
            raw_line=f'<PackageReference Include="{include}" Version="{ver_clean or "*"}" />',
            line_number=0,
            manifest_type=".csproj",
            ecosystem="NuGet",
        ))
    return specs

