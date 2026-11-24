# Changelog

Seluruh perubahan penting pada paket `sidik-security` didokumentasikan pada berkas ini.

## [1.3.0] - 2026-11-24

### Diubah & Ditambahkan
- Pemisahan identitas visual tegas antara **SIDIK (*Deterministic Edition*, tema *Ocean Blue* `#3b82f6`)** dan **SIDIK-ML (*Explainable Non-ANN ML Edition*, tema *Electric Violet* `#8b5cf6`)** lintas *Desktop GUI*, *Interactive CLI* (TUI), serta pelaporan konsol, Markdown, dan dasbor HTML.
- *Desktop GUI* (`sidik/gui.py`): Penambahan bilah aksen 3px, *pill badge* `NON-ANN ML`, lencana versi dinamis (`v1.3.0 Deterministic Edition` vs `SIDIK-ML v0.5.0 | Core v1.3.0`), sorotan panel kontrol `ML TRIAGE`, label tombol khusus `Mulai Pemindaian Hybrid ML` / `Start Hybrid ML Scan`, serta ringkasan arsitektur *Non-ANN* di tab *About* saat diluncurkan oleh `sidik-ml gui` atau dengan mode ML aktif.
- *Interactive CLI* (`sidik/cli.py`): *Banner* ungu ANSI dan *prompt* interaktif `sidik-ml>` dengan indikator model `.skops` & ambang probabilitas aktif saat berjalan dalam mode ML (`sidik-ml interactive` / `--enable-ml`), berbanding terbalik dengan konsol biru/cyan `sidik>` pada mode deterministik.
- Pelaporan & SARIF (`sidik/reporting/formatter.py`): Menghilangkan *hardcoded* `1.0.0` pada keluaran `to_sarif()` (`driver.version`) dan subjudul `to_html()` agar mengikuti `sidik.__version__` (`1.3.0`), serta otomatis menerapkan aksen ungu, tajuk `SIDIK-ML Hybrid`, dan lencana `NON-ANN ML TRIAGE` apabila laporan memuat metadata `ml_triage`.
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
