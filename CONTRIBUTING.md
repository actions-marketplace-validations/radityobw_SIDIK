# Contributing to SIDIK

Thank you for contributing to **SIDIK** (*Secret Identification and Dependency Inspection Kit*). This guide covers local development, architectural boundaries, pre-flight verification, and the Single-Source-of-Truth (SSOT) release workflow.

---

## 1. Architectural Scope & Decoupling Rules

* **Core Deterministic Engine:** `SIDIK` must remain 100% functional **without** machine learning dependencies. Never add ML packages (`scikit-learn`, `scipy`, `skops`, `torch`, etc.) to core runtime dependencies.
* **Strict Plugin Boundary:** Extensions such as [`SIDIK-ML`](https://github.com/radityobw/SIDIK-ML) integrate strictly through the `sidik.plugins` entry-point group and the `SecretCandidate` contract (`schema_version = "1.0.0"`). Do not import or reference `sidik_ml` anywhere inside `sidik/`.
* **100% Offline Runtime & Zero Data Leakage:** Secret detection and OSV SCA must never perform implicit network calls or persist unmasked raw secrets in outputs or contracts.

---

## 2. Local Development Setup

```bash
git clone https://github.com/radityobw/SIDIK.git
cd SIDIK
python -m venv .venv

# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux / macOS:      source .venv/bin/activate

pip install --no-build-isolation --no-deps --config-settings editable_mode=compat -e ".[gui,dev]"
```

Run the full unit, contract, and decoupling suite after every change:

```bash
python -m unittest discover -s tests -v
```

Run SIDIK against its own source tree before committing:

```bash
python -m sidik --target sidik --mode all --fail-on high --quiet
```

---

## 3. Coding, Packaging, & Documentation Standards

1. **No Em-Dashes (`\u2014`):** Use standard hyphens (`-`), colons (`:`), or parentheses instead of `\u2014` across code, i18n strings, Markdown, and workflows.
2. **PEP 639 Licensing (`pyproject.toml`):** Keep `license = "MIT"` and `license-files = ["LICENSE"]`. Do not add legacy `License :: OSI Approved :: ...` classifiers (rejected by `setuptools>=77`).
3. **PyPI-Safe `README.md` Links:** All images and file links in `README.md` must use absolute `https://raw.githubusercontent.com/...` or `https://github.com/...` URLs so assets render properly on PyPI. Keep version badges dynamic via Shields.io (`img.shields.io/pypi/v/sidik`, `img.shields.io/github/v/release/...`) rather than hardcoding patch numbers.
4. **GitHub Marketplace Action Limit (`action.yml`):** Keep `description` strictly under **125 characters**.
5. **GUI & Secret Safety:** Verify high-DPI Tkinter layouts cleanly and avoid leaking real tokens or unmasked test fixtures.

---

## 4. Refreshing the Bundled OSV PyPI Snapshot (Optional)

When updating [`sidik/data/pypi_advisories.json`](sidik/data/pypi_advisories.json) ahead of a release:

```bash
python -m sidik.dependency_analyzer.osv_import --output sidik/data/pypi_advisories.json
```

`SIDIK/sidik/i18n.py` reads the active advisory and package counts dynamically from the DB header via `peek_db_summary_counts()`, so the GUI *About* tab updates automatically. If the scale changes significantly, update the `Offline OSV DB` badge in [`README.md`](README.md).

---

## 5. SSOT Release Checklist (`2` Files Only)

`SIDIK` uses `[tool.setuptools.dynamic]` reading from [`sidik/_version.py`](sidik/_version.py). For a routine version bump (`X.Y.Z`):

1. Update `__version__ = "X.Y.Z"` in [`sidik/_version.py`](sidik/_version.py).
   * Automatically syncs package metadata, `sidik.__version__`, `sidik/i18n.py` (`app_version`), SARIF driver version, and contract tests.
2. Prepend a `## [X.Y.Z] - YYYY-MM-DD` entry in [`CHANGELOG.md`](CHANGELOG.md) (verified automatically by `tests/test_v11_contract.py`).

### Pre-Flight Verification Gate

```bash
# Clean any stale repo-root .egg-info before editable reinstall
pip install --no-build-isolation --no-deps --config-settings editable_mode=compat -e .
python -m unittest discover -s tests -v
python -m sidik --target sidik --mode all --fail-on high --quiet
python -m build
python -m twine check dist/*
```

Verify the built `.whl` includes `sidik/_version.py`, `sidik/py.typed`, `sidik/data/pypi_advisories.json`, and `sidik/assets/SIDIK-nobg-purelogo-dark.png`.

---

## 6. Publishing Order & CI/CD Automation

Always publish **`SIDIK`** before releasing downstream plugins such as `SIDIK-ML`:

1. Tag and push:
   ```bash
   git add -A
   git commit -m "Release vX.Y.Z: <summary>"
   git tag -a vX.Y.Z -m "Release vX.Y.Z: <summary>"
   git push origin main vX.Y.Z
   ```
2. Create a GitHub Release on `vX.Y.Z` (via GitHub Web UI if updating GitHub Marketplace listing, or `gh release create vX.Y.Z --generate-notes`).
3. Publishing triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which automatically:
   * Runs `unittest`, builds wheel/sdist + `SHA256SUMS.txt`, validates via `twine check`, and attaches release assets.
   * Builds and pushes `ghcr.io/radityobw/sidik:latest` and `:X.Y.Z`.
   * Publishes to PyPI via OIDC Trusted Publishing when repository variable `ENABLE_PYPI_PUBLISH` is set to `true`.
4. Confirm `sidik==X.Y.Z` is live on PyPI before releasing downstream packages that depend on it.
