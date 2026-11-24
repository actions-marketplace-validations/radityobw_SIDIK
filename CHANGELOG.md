# Changelog

Seluruh perubahan penting pada paket `sidik` (sebelumnya `sidik-security`) didokumentasikan pada berkas ini.

## [1.3.8] - 2026-11-25

### Ditingkatkan (Dukungan Dependensi URL Repositori Git/VCS & *Archive* di Mesin SCA)
- **Parser URL Git/VCS & *Direct Archive* ([`parsers.py`](sidik/dependency_analyzer/parsers.py)):** Menambahkan penguraian dependensi berbasis URL repositori Git/VCS dan tautan arsip/wheel langsung (`pkg @ git+https://...@vX.Y.Z`, `git+ssh://git@...@tag#egg=pkg`, `-e git+...`, `archive/refs/tags/vX.Y.Z.tar.gz`, serta `*.whl`) pada `requirements*.txt`, `pyproject.toml` (PEP 621, PEP 735, Poetry `{git, tag/url}`), `setup.py`, dan `Pipfile` (`[packages]` & `[dev-packages]` `{git, ref}`).
- **Ekstraksi *Tag* Versi Aman ([`_extract_version_from_ref()`](sidik/dependency_analyzer/parsers.py)):** Mengonversi *tag* rilis PEP 440 (`v2.19.0`, `1.26.5`, `release-1.26.5`) menjadi pin eksak `==<versi>` agar CVE terdeteksi akurat sekaligus menghindari *false positive* pada *tag* versi aman, sementara cabang/*commit* non-semver tetap ditandai sebagai dependensi belum dipin (`*`).

## [1.3.7] - 2026-11-25

### Ditingkatkan (Arsitektur *Zero Version Drift* & *Live Metadata*)
- ***Single Source of Truth* (`sidik/_version.py`):** Menyatukan sumber versi pada `sidik/_version.py` dan konfigurasi `[tool.setuptools.dynamic]` di [`pyproject.toml`](pyproject.toml), sehingga `sidik.__version__`, metadata paket, GUI/i18n (`app_version`), serta *unit test* selalu sinkron otomatis.
- **Tab *About* GUI & `action.yml` Dinamis ([`database.py`](sidik/dependency_analyzer/database.py), [`i18n.py`](sidik/i18n.py), [`action.yml`](action.yml)):** Menambahkan `peek_db_summary_counts()` agar tab *About* GUI membaca jumlah aktual advisori dan paket OSV secara *live* (`35.304` advisori / `13.734` paket pada rilis ini), sekaligus memperbarui deskripsi menjadi `7` format manifes/*lockfile* dan `30` fitur statis `SIDIK-ML`.
- ***Live* PyPI/*Release*/CI *Badges* (`README.md`) & Uji Sinkronisasi:** Mengganti angka versi/statis lintas repo di [`README.md`](README.md) dengan *badge* dinamis PyPI, *GitHub Release*, dan CI, serta menambahkan asersi sinkronisasi versi/`CHANGELOG.md`/`i18n` di [`test_v11_contract.py`](tests/test_v11_contract.py).

## [1.3.6] - 2026-11-25

### Ditingkatkan (Cakupan CVE OSV PyPI & Akurasi *Severity*)
- **Dukungan `affected[].versions` Eksplisit ([`osv_import.py`](sidik/dependency_analyzer/osv_import.py), [`matcher.py`](sidik/dependency_analyzer/matcher.py), [`analyzer.py`](sidik/dependency_analyzer/analyzer.py)):** Mengurai daftar versi eksplisit (`vulnerable_versions`) pada rekaman OSV yang tidak menyertakan blok `ECOSYSTEM` *range*, memangkas rekaman terlewati (`skipped_record_count`) dari `6.268` menjadi `679`.
- **Skoring *CVSS v4.0*, *CVSS v2.0*, & Klasifikasi *Malicious Package* (`MAL-*`):** Menambahkan `cvss4_severity()`, `cvss2_base_score()`, pembacaan *severity* tingkat `affected[]`, serta penetapan `CRITICAL` otomatis untuk advisori paket berbahaya `MAL-*`, menurunkan *fallback* `default: MEDIUM` dari `12.191` menjadi `5.224`.
- **Pembaruan *Snapshot* OSV PyPI Luring (`pypi_advisories.json`):** Diperbarui ke *snapshot* `2026-11-24T17:47:00Z` dengan total **`35.304` advisori** (`35.292` OSV + `12` bawaan; **`6.841` CVE unik**) lintas **`13.734` paket PyPI** (`+70,9%` cakupan paket vs `8.038` sebelumnya).

## [1.3.5] - 2026-11-25

### Diperbaiki
- **Bug *Search Placeholder* saat Ganti Bahasa di GUI ([`sidik/gui.py`](sidik/gui.py)):** Memperbaiki `_set_search_placeholder()` dan `_apply_filters()` agar teks *placeholder* pencarian bahasa sebelumnya tidak dianggap sebagai kata kunci filter aktif ketika pengguna mengganti bahasa (`ID <-> EN`), yang sebelumnya menyembunyikan seluruh baris tabel (`Showing 0 of N findings`).
- **Pesan Kosong Akurat saat Filter Aktif ([`sidik/i18n.py`](sidik/i18n.py)):** Menambahkan `msg_no_filter_match` sehingga tabel kosong akibat pencarian/filter menampilkan petunjuk `Reset Filter` dengan jumlah total temuan, bukan pesan `Clean!`.
- **Tata Letak Baris *Preset* GUI:** Merapikan *padding* dan pengelompokan tombol *preset* agar tidak terpotong di sebelah kanan pada resolusi 1280px.

## [1.3.4] - 2026-11-25

### Ditambahkan & Ditingkatkan (PyPI Global DX & Hardening)
- **Penyimpanan *User Cache* untuk DB OSV & Grafik GUI:** `sidik --update-db` (`sidik/dependency_analyzer/osv_import.py`) dan `VulnerabilityDatabase` (`sidik/dependency_analyzer/database.py`) kini menyimpan serta memprioritaskan basis data OSV di direktori *cache* pengguna (`~/.cache/sidik` / `%LOCALAPPDATA%\sidik` / `SIDIK_CACHE_DIR`), dilengkapi fungsi `snapshot_age_days()` dan pengingat kesegaran data pada `--db-info` tanpa menulis ke `site-packages/`.
- **Cakupan Deteksi *Secret* & SCA Diperluas:** Pindai direktori kini mendukung `.env.*` dan berkas konfigurasi (`.yaml`, `.yml`, `.toml`, `.ini`, `.cfg`), melewati berkas *lockfile*, berkas >5 MB, serta berkas biner (NUL-*byte*). Mesin SCA kini mendukung `Pipfile.lock`, `uv.lock`, `requirements-*.txt`, `requirements/*.txt`, `[project.optional-dependencies]`, dan PEP 735 `[dependency-groups]`.
- **Ekstraksi Sekali Jalan (*Single-Pass*):** `SecretDetector.scan_and_extract_content()` dan `SecurityScanner` mengekstrak `SecretCandidate` dalam satu kali pembacaan berkas saat *plugin* aktif, serta mendukung pemindaian multi-target `scan_paths()`.
- **Fitur CLI & Konfigurasi Proyek:** Menambahkan `--extensions`, `--exclude`, `--baseline`, `--write-baseline`, `--sarif-output` (satu kali pindai untuk *annotations* + SARIF), `--no-step-summary`, dukungan `[tool.sidik]` pada `pyproject.toml`, *entry point* `sidik-gui` berbasis `argparse` (`--help`/`--version`), serta diagnosa ramah saat `tkinter` tidak tersedia.
- **Kesiapan GUI Global & Integritas Ilmiah Grafik:** *Default target* GUI dan *preset* awal kini mengarah ke `os.getcwd()`, *preset* korpus riset hanya tampil pada *source checkout*, tombol *Simpan Grafik* memulihkan status beserta petunjuk `pip install "sidik[gui]"` jika `matplotlib` tidak terpasang, dan bundel grafik non-*benchmark* menampilkan hitungan serta profil performa faktual tanpa metrik *ground-truth* buatan.
- **Keamanan *GitHub Action*, SARIF & *Pre-Commit*:** Memindahkan seluruh input [`action.yml`](action.yml) ke `env:` untuk mencegah *script injection* dalam pemindaian tunggal, menormalkan URI SARIF relatif terhadap *repo root*, memperbarui `.pre-commit-hooks.yaml`, menambahkan penanda PEP 561 `sidik/py.typed` ke dalam *wheel*, *PyPI classifiers*, dan URL absolut pada `README.md`.

## [1.3.3] - 2026-11-24

### Diubah
- Mengubah nama distribusi PyPI paket dari `sidik-security` menjadi **`sidik`** (`pip install sidik` / `pip install "sidik[gui]"`) agar selaras dengan konfigurasi *PyPI Trusted Publishing* (`https://pypi.org/p/sidik`) dan memutakhirkan versi rilis ke `v1.3.3`.

## [1.3.2] - 2026-11-24

### Diubah & Ditambahkan
- Mempersingkat `description` pada [`action.yml`](action.yml) (`116` karakter `< 125` batas *GitHub Marketplace*) agar dapat dipublikasikan langsung melalui halaman *Release Action*.
- Menambahkan [`Dockerfile`](Dockerfile), [`.dockerignore`](.dockerignore), serta *workflow* [`.github/workflows/release.yml`](.github/workflows/release.yml) untuk otomasi unggah aset `.whl`/`.tar.gz`/`SHA256SUMS.txt` ke *GitHub Releases*, *container image* `ghcr.io/radityobw/sidik`, serta *PyPI Trusted Publishing* OIDC (*gated*).

## [1.3.1] - 2026-11-24

### Diubah & Diperbaiki
- Penyelarasan argumen CLI simetris (`--gui`, subperintah `gui`, `interactive`, `cli`, `tui`) pada [`sidik/cli.py`](sidik/cli.py) serta pembaruan peluncur [`run_sidik.bat`](run_sidik.bat), [`run_sidik_cli.bat`](run_sidik_cli.bat), dan [`run_sidik.sh`](run_sidik.sh) agar memprioritaskan interpreter `.venv` lokal.
- Pengalihan tema visual **SIDIK-ML (*Explainable Non-ANN ML Edition*)** ke **Amber Orange (`#f59e0b` / `#ea580c`)** lintas *Desktop GUI* ([`sidik/gui.py`](sidik/gui.py)), *Interactive CLI* TUI, dan laporan konsol serta HTML ([`sidik/reporting/formatter.py`](sidik/reporting/formatter.py)), disertai penjagaan regresi bebas label `"Research Edition"` (`63/63` *unit test*).

## [1.3.0] - 2026-11-24

### Diubah & Ditambahkan
- Pemisahan identitas visual tegas antara **SIDIK (*Deterministic Edition*, tema *Ocean Blue* `#3b82f6`)** dan **SIDIK-ML (*Explainable Non-ANN ML Edition*, tema *Amber Orange* `#f59e0b` / `#ea580c`)** lintas *Desktop GUI*, *Interactive CLI* (TUI), serta pelaporan konsol, Markdown, dan dasbor HTML.
- *Desktop GUI* (`sidik/gui.py`): Penambahan bilah aksen 3px, *pill badge* `NON-ANN ML`, lencana versi dinamis (`v1.3.0 Deterministic Edition` vs `SIDIK-ML v0.5.0 | Core v1.3.0`), sorotan panel kontrol `ML TRIAGE`, label tombol khusus `Mulai Pemindaian Hybrid ML` / `Start Hybrid ML Scan`, serta ringkasan arsitektur *Non-ANN* di tab *About* saat diluncurkan oleh `sidik-ml gui` atau dengan mode ML aktif.
- *Interactive CLI* (`sidik/cli.py`): *Banner* kuning-oranye ANSI dan *prompt* interaktif `sidik-ml>` dengan indikator model `.skops` & ambang probabilitas aktif saat berjalan dalam mode ML (`sidik-ml interactive` / `--enable-ml`), berbanding terbalik dengan konsol biru/cyan `sidik>` pada mode deterministik.
- Pelaporan & SARIF (`sidik/reporting/formatter.py`): Menghilangkan *hardcoded* `1.0.0` pada keluaran `to_sarif()` (`driver.version`) dan subjudul `to_html()` agar mengikuti `sidik.__version__` (`1.3.0`), serta otomatis menerapkan aksen kuning-oranye, tajuk `SIDIK-ML Hybrid`, dan lencana `NON-ANN ML TRIAGE` apabila laporan memuat metadata `ml_triage`.
- Lokalisasi (`sidik/i18n.py`): Menambahkan kunci dwibahasa `app_title_ml`, `app_subtitle_ml`, `btn_scan_ml`, dan `about_ml_features_text` serta memperbarui `app_version` ke `v1.3.0 (Deterministic Edition)`.

## [1.2.0] - 2026-11-24

### Ditambahkan
- Antarmuka *plugin* pasca-pemindaian terdekupel ([`sidik/plugins.py`](sidik/plugins.py)) berbasis standar `importlib.metadata.entry_points(group="sidik.plugins")` (`PostScanPlugin`, `discover_plugins()`, `get_plugin()`, `apply_post_scan_plugins()`), tanpa menambahkan dependensi ML di `SIDIK`.
- Dukungan parameter opsional `post_scan_plugins` dan `plugin_options` pada `SecurityScanner`.
- Dukungan CLI (`--list-plugins`, `--enable-ml`, `--plugin`, `--ml-model`, `--ml-sha256`, `--ml-threshold`, `--ml-suppress-fp`), menu pengaturan *Interactive CLI*, kontrol opsional di *Desktop GUI*, serta pelaporan `ml_triage` pada `ReportFormatter` (Konsol, Markdown, HTML, SARIF, JSON, dan CSV) saat ekstensi eksternal seperti `sidik-ml` terpasang.

## [1.1.0] - 2026-11-24

### Ditambahkan
- Kontrak data terstruktur berversi `SecretCandidate` (`CANDIDATE_SCHEMA_VERSION = "1.0.0"`) beserta `compute_stable_id()` di `sidik.models` (diekspor ulang di `sidik`) untuk integrasi aman menuju `SIDIK-ML` tanpa menyimpan nilai rahasia mentah (`value_sha256` + `masked_value`).
- Metode `SecretDetector.extract_candidates()`, `SecretDetector.extract_candidates_from_file()`, dan `SecurityScanner.extract_secret_candidates()` yang menyediakan fitur statistik string, entropi, bukti aturan, konteks leksikal, konteks kode, dan konteks path untuk seluruh kandidat (lolos maupun terfilter).
- Berkas `LICENSE` (MIT), `sidik/data/__init__.py`, `sidik/assets/__init__.py`, dan penyertaan aset merek di dalam paket (`sidik/assets/`) agar distribusi *wheel* bersifat mandiri.
- Berkas `.sidikignore` tingkat *repository* dan `dataset/external/.sidikignore` menggantikan pengecualian riset yang sebelumnya tertanam di `core.py`.
- Penjaga batas ukuran dekompresi arsip ZIP (`512 MB`) dan validasi skema HTTPS pada `sidik.dependency_analyzer.osv_import`.

### Diperbaiki
- Menghapus duplikasi metode mati `ReportFormatter.to_html()` dan menyelaraskan dasbor HTML baru (`47ff8dc`) agar memuat aset logo dari paket `sidik.assets`, menyertakan fungsi salin cepat (`copyToClipboard`) dan alias `filterFindings()`, serta memulihkan seluruh 51+ *unit test*.
- Menyelaraskan `_FAST_LINE_PRECHECK` di `sidik/secret_detector/detector.py` agar menangkap kata kunci `token`, `auth`, dan `credential` sesuai aturan `SEC012`.
- Memuat basis data OSV (`pypi_advisories.json`) melalui `importlib.resources` dengan peringatan eksplisit apabila tidak ditemukan.
- Menjadikan `tracemalloc` bersifat opsional (`measure_memory=False` secara *default* pada `SecurityScanner`) agar tidak mengganggu state global pemanggil pustaka.
- Mengganti seluruh ID berbasis `hash()` acak menjadi SHA-256 deterministik lintas proses (`compute_stable_id`).
- Menambahkan *fallback* `tomli` untuk Python `<3.11`, dukungan *PEP 508 extras* & *environment markers* di `parsers.py`, penguraian `Pipfile` bertipe *dict*, penguraian AST statis aman pada `setup.py`, normalisasi *caret* Poetry `^0.x.y`, serta evaluasi irisan rentang batas atas (`<`, `<=`) dan `>` di `matcher.py`.
- Menghapus efek samping `sys.path.insert` dan pemanggilan DPI Windows saat *import* di `sidik/gui.py`, serta melokalisasi prompt dialog pembuka dasbor HTML melalui `i18n.py`.
- Menghapus direktori uji sisa `dataset/secrets/test1/`.

## [1.0.0] - 2026-11-01

### Rilis Awal Publikasi Riset
- Pemindai deterministik 3 lapis (12 aturan regex `SEC001`-`SEC012`, entropi Shannon, filter konteks leksikal).
- Subsistem *Offline SCA* untuk 5 format manifes Python dengan indeks lokal Google OSV (`29.196` advisori + `12` bawaan).
- Antarmuka *One-Shot CLI*, *Interactive CLI Menu* (TUI), *Desktop GUI High-DPI* dwibahasa (ID/EN), serta ekspor 7 format laporan termasuk OASIS SARIF v2.1.0 dan *GitHub Actions* (`action.yml`).
