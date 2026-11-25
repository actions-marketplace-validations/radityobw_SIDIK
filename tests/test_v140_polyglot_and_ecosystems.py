"""Tests for SIDIK v1.4.0 polyglot SAST and 8-ecosystem multi-manifest SCA."""

import io
import json
import os
import tempfile
import unittest
import zipfile

from sidik.cli import run_cli_with_args
from sidik.core import SecurityScanner
from sidik.dependency_analyzer.analyzer import DependencyAnalyzer, get_manifest_parser
from sidik.dependency_analyzer.database import VulnerabilityDatabase, canonicalize_ecosystem, get_user_sqlite_db_path
from sidik.dependency_analyzer.matcher import is_version_vulnerable, normalize_version_specifier
from sidik.dependency_analyzer.osv_import import build_database, convert_osv_record, import_osv
from sidik.dependency_analyzer.parsers import (
    parse_cargo_lock,
    parse_cargo_toml,
    parse_composer_json,
    parse_composer_lock,
    parse_csproj,
    parse_gemfile_lock,
    parse_go_mod,
    parse_package_json,
    parse_package_lock_json,
    parse_pnpm_lock_yaml,
    parse_pom_xml,
    parse_yarn_lock,
)
from sidik.secret_detector.detector import SecretDetector


class TestV140PolyglotAndEcosystems(unittest.TestCase):
    """Verifies polyglot secret detection, 12 new manifest parsers, SemVer matching, and SQLite OSV import."""

    def test_polyglot_secret_scan_comments_env_and_lockfile_skip(self):
        det = SecretDetector()
        js_code = (
            "// mock_secret = 'AKIAJ2M4K8P9Q3R7W5T1'\n"
            "const apiKey = process.env.MY_KEY;\n"
            "const prodKey = 'AKIAJ2M4K8P9Q3R7W5T2';\n"
            "const ignoredKey = 'AKIAJ2M4K8P9Q3R7W5T3'; // nosec\n"
        )
        cands = det.extract_candidates(js_code, file_path="src/client.ts", include_filtered=True)
        by_line = {c.line_number: c for c in cands}
        self.assertTrue(by_line[1].lexical_context["is_comment"])
        self.assertTrue(by_line[3].deterministic_decision["passed_deterministic_filter"])
        self.assertFalse(by_line[4].deterministic_decision["passed_deterministic_filter"])

        go_cands = det.extract_candidates('k := os.Getenv("API_KEY")\ntoken := "AKIAJ2M4K8P9Q3R7W5T4"\n', "main.go")
        self.assertEqual(len(go_cands), 1)
        self.assertTrue(go_cands[0].deterministic_decision["passed_deterministic_filter"])

        rs_cands = det.extract_candidates('let s = env::var("DB_SECRET");\nlet aws = "AKIAJ2M4K8P9Q3R7W5T5";\n', "src/lib.rs")
        self.assertEqual(len(rs_cands), 1)

        with tempfile.TemporaryDirectory() as tmp:
            for fname, body in [
                ("Dockerfile", "ENV AWS_ACCESS_KEY_ID=AKIAJ2M4K8P9Q3R7W5T1\n"),
                ("App.java", 'String k = "AKIAJ2M4K8P9Q3R7W5T2";\n'),
                ("app.min.js", 'var a="AKIAJ2M4K8P9Q3R7W5T3";\n'),
                ("package-lock.json", '{"name":"demo","packages":{"node_modules/lodash":{"version":"4.17.19"}}}\n'),
            ]:
                with open(os.path.join(tmp, fname), "w", encoding="utf-8") as fh:
                    fh.write(body)
            report = SecurityScanner(enable_secret_scan=True, enable_dependency_scan=True).scan_path(tmp)
            sec_files = {os.path.basename(f.file_path) for f in report.findings if f.finding_type == "secret"}
            self.assertIn("Dockerfile", sec_files)
            self.assertIn("App.java", sec_files)
            self.assertNotIn("app.min.js", sec_files)
            self.assertNotIn("package-lock.json", sec_files)
            dep_cves = {f.metadata.get("cve") for f in report.findings if f.finding_type == "dependency"}
            self.assertIn("CVE-2020-8203", dep_cves)

    def test_twelve_new_manifest_and_lockfile_parsers(self):
        pkg_specs = parse_package_json(json.dumps({
            "dependencies": {"lodash": "^4.17.15", "localpkg": "workspace:*"},
            "devDependencies": {"axios": "0.21.1"},
        }))
        self.assertEqual([(s.package_name, s.specifier, s.ecosystem) for s in pkg_specs], [
            ("lodash", "^4.17.15", "npm"),
            ("axios", "0.21.1", "npm"),
        ])

        lock_specs = parse_package_lock_json(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo"},
                "node_modules/minimist": {"version": "1.2.5"},
                "node_modules/express/node_modules/@scope/pkg": {"version": "1.0.0"},
            },
        }))
        self.assertEqual({(s.package_name, s.specifier) for s in lock_specs}, {
            ("minimist", "==1.2.5"),
            ("@scope/pkg", "==1.0.0"),
        })

        yarn_specs = parse_yarn_lock('"lodash@^4.17.15":\n  version "4.17.19"\n\n"@scope/foo@npm:^2.0.0":\n  version: 2.1.0\n')
        self.assertEqual([(s.package_name, s.specifier) for s in yarn_specs], [
            ("lodash", "==4.17.19"),
            ("@scope/foo", "==2.1.0"),
        ])

        pnpm_specs = parse_pnpm_lock_yaml("packages:\n  /lodash@4.17.19:\n    resolution: {}\n  '@scope/bar@1.2.3':\n    resolution: {}\n")
        self.assertEqual([(s.package_name, s.specifier) for s in pnpm_specs], [
            ("lodash", "==4.17.19"),
            ("@scope/bar", "==1.2.3"),
        ])

        go_specs = parse_go_mod("module demo\n\nrequire (\n\tgolang.org/x/net v0.15.0\n\tgithub.com/gin-gonic/gin v1.9.0+incompatible // indirect\n)\n")
        self.assertEqual([(s.package_name, s.specifier, s.ecosystem) for s in go_specs], [
            ("golang.org/x/net", "==0.15.0", "Go"),
            ("github.com/gin-gonic/gin", "==1.9.0", "Go"),
        ])

        cargo_toml_specs = parse_cargo_toml('[dependencies]\nopenssl = "0.10.50"\nhyper = { version = "^1.1.0" }\n')
        self.assertEqual({(s.package_name, s.specifier, s.ecosystem) for s in cargo_toml_specs}, {
            ("openssl", "0.10.50", "crates.io"),
            ("hyper", "^1.1.0", "crates.io"),
        })

        cargo_lock_specs = parse_cargo_lock('[[package]]\nname = "openssl"\nversion = "0.10.50"\n')
        self.assertEqual((cargo_lock_specs[0].package_name, cargo_lock_specs[0].specifier), ("openssl", "==0.10.50"))

        pom_xml = """<project xmlns="http://maven.apache.org/POM/4.0.0">
          <properties><log4j.version>2.14.1</log4j.version></properties>
          <dependencies>
            <dependency>
              <groupId>org.apache.logging.log4j</groupId>
              <artifactId>log4j-core</artifactId>
              <version>${log4j.version}</version>
            </dependency>
          </dependencies>
        </project>"""
        pom_specs = parse_pom_xml(pom_xml)
        self.assertEqual((pom_specs[0].package_name, pom_specs[0].specifier, pom_specs[0].ecosystem), (
            "org.apache.logging.log4j:log4j-core", "==2.14.1", "Maven"
        ))

        comp_specs = parse_composer_json(json.dumps({"require": {"php": ">=8.1", "laravel/framework": "^8.40"}}))
        self.assertEqual([(s.package_name, s.specifier, s.ecosystem) for s in comp_specs], [
            ("laravel/framework", "^8.40", "Packagist"),
        ])

        comp_lock_specs = parse_composer_lock(json.dumps({"packages": [{"name": "laravel/framework", "version": "v8.70.0"}]}))
        self.assertEqual((comp_lock_specs[0].package_name, comp_lock_specs[0].specifier), ("laravel/framework", "==8.70.0"))

        gem_specs = parse_gemfile_lock("GEM\n  specs:\n    rails (7.0.4)\n    nokogiri (1.15.4-x86_64-linux)\n")
        self.assertEqual([(s.package_name, s.specifier, s.ecosystem) for s in gem_specs], [
            ("rails", "==7.0.4", "RubyGems"),
            ("nokogiri", "==1.15.4", "RubyGems"),
        ])

        csproj_specs = parse_csproj('<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.3" /></ItemGroup></Project>')
        self.assertEqual((csproj_specs[0].package_name, csproj_specs[0].specifier, csproj_specs[0].ecosystem), (
            "newtonsoft.json", "==12.0.3", "NuGet"
        ))
        self.assertIsNotNone(get_manifest_parser("MyService.csproj"))

    def test_semver_matcher_and_builtin_multi_ecosystem_cves(self):
        self.assertEqual(normalize_version_specifier("1.2.x"), ">=1.2.0,<1.3.0")
        self.assertEqual(normalize_version_specifier("1.0.0 - 1.5.0"), ">=1.0.0,<=1.5.0")
        self.assertEqual(normalize_version_specifier(">=1.2.0 <2.0.0"), ">=1.2.0,<2.0.0")
        self.assertTrue(is_version_vulnerable("^1.1.0 || ^4.17.15", "<4.17.20", ecosystem="npm")[0])
        self.assertFalse(is_version_vulnerable(">=4.17.21 <5.0.0", "<4.17.20", ecosystem="npm")[0])

        with tempfile.TemporaryDirectory() as tmp:
            files = {
                "package.json": json.dumps({"dependencies": {"lodash": "^4.17.15"}}),
                "go.mod": "module demo\nrequire golang.org/x/net v0.15.0\n",
                "Cargo.toml": '[dependencies]\nopenssl = "0.10.50"\n',
                "pom.xml": "<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>",
                "composer.json": json.dumps({"require": {"laravel/framework": "^8.50"}}),
                "Gemfile.lock": "GEM\n  specs:\n    rails (7.0.4)\n",
                "App.csproj": '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.3" /></ItemGroup></Project>',
            }
            for fn, content in files.items():
                with open(os.path.join(tmp, fn), "w", encoding="utf-8") as fh:
                    fh.write(content)

            findings = DependencyAnalyzer().scan_directory(tmp)
            cves = {f.metadata.get("cve"): f for f in findings}
            for expected_cve in (
                "CVE-2020-8203",
                "CVE-2023-44487",
                "CVE-2023-3817",
                "CVE-2021-44228",
                "CVE-2021-43824",
                "CVE-2023-22795",
                "CVE-2024-21907",
            ):
                self.assertIn(expected_cve, cves)

            self.assertIn("npm install", cves["CVE-2020-8203"].remediation or "")
            self.assertIn("go get", cves["CVE-2023-44487"].remediation or "")
            self.assertIn("cargo update", cves["CVE-2023-3817"].remediation or "")
            self.assertIn("dotnet add package", cves["CVE-2024-21907"].remediation or "")

    def test_osv_semver_import_and_sqlite_ecosystem_isolation(self):
        self.assertEqual(canonicalize_ecosystem("golang"), "Go")
        self.assertEqual(canonicalize_ecosystem("rust"), "crates.io")

        npm_rec = {
            "id": "GHSA-test-npm-1",
            "aliases": ["CVE-2099-1234"],
            "summary": "Demo npm collision test",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "requests"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }],
        }
        advs, _ = convert_osv_record(npm_rec, ecosystem="npm")
        self.assertEqual(len(advs), 1)
        self.assertEqual(advs[0]["ecosystem"], "npm")
        self.assertEqual(advs[0]["vulnerable_specifier"], "<2.0.0")
        db_built = build_database([npm_rec], "unit", "deadbeef", ecosystem="npm")
        self.assertEqual(db_built["metadata"]["ecosystem"], "npm")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("GHSA-test-npm-1.json", json.dumps(npm_rec))

        with tempfile.TemporaryDirectory() as tmp:
            zip_path = os.path.join(tmp, "npm_all.zip")
            with open(zip_path, "wb") as zfh:
                zfh.write(buf.getvalue())

            old_cache = os.environ.get("SIDIK_CACHE_DIR")
            os.environ["SIDIK_CACHE_DIR"] = tmp
            try:
                meta = import_osv(input_zip=zip_path, ecosystem="npm")
                self.assertEqual(meta["advisory_count"], 1)
                self.assertTrue(os.path.isfile(get_user_sqlite_db_path()))

                db = VulnerabilityDatabase()
                npm_hits = db.get_advisories("requests", ecosystem="npm")
                self.assertTrue(any(h["cve"] == "CVE-2099-1234" for h in npm_hits))
                # Ensure npm CVE does not pollute PyPI namespace for identically named package
                pypi_hits = db.get_advisories("requests", ecosystem="PyPI")
                self.assertFalse(any(h["cve"] == "CVE-2099-1234" for h in pypi_hits))
                synced = db.get_synced_ecosystems()
                self.assertEqual(len(synced), 1)
                self.assertEqual(synced[0]["ecosystem"], "npm")

                rc = run_cli_with_args(["--db-info"], exit_on_finish=False)
                self.assertEqual(rc, 0)
            finally:
                if old_cache is None:
                    os.environ.pop("SIDIK_CACHE_DIR", None)
                else:
                    os.environ["SIDIK_CACHE_DIR"] = old_cache


if __name__ == "__main__":
    unittest.main()
