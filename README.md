# IOCYRA

**Discord security bot for quick malware and threat-intelligence triage.**

> 🚧 **In development** — IOCYRA is currently released for portfolio and development purposes. Features and analysis capabilities are still evolving.

IOCYRA is a Discord-based security analysis tool designed to make basic malware and threat-intelligence triage accessible without requiring users to install or execute analysis tools locally.

It can analyze suspicious **URLs, files, and archives** and present the results directly through Discord. Uploaded files are analyzed statically and are **never executed by IOCYRA**.

The project is primarily focused on lightweight analysis and triage rather than replacing dedicated malware-analysis platforms.

## Current Features

* 🔗 **URL analysis**

  * URL parsing and normalization
  * Basic reputation and indicator analysis
  * Optional VirusTotal information

* 📁 **File analysis**

  * SHA-256 hashing
  * File metadata
  * PE format detection
  * PE architecture and entry-point information
  * PE section information
  * Import analysis
  * Embedded string analysis
  * Static behavioral indicators
  * PowerShell-related string analysis
  * Basic behavioral combination detection
  * Triage scoring

* 📦 **Archive analysis**

  * ZIP archive inspection
  * Archive metadata
  * Safe extraction
  * PE candidate identification
  * Static analysis of PE files contained within archives
  * Archive size and extraction limits
  * Unsafe archive path detection

* 🤖 **Discord integration**

  * Slash-command analysis
  * Message context-menu analysis
  * Direct file attachment analysis
  * Private analysis results

## Architecture

IOCYRA separates analysis logic from the Discord interface:

```text
Discord
   │
   ├── URL
   │     └── url_analyzer.py
   │
   ├── File
   │     └── file_analyzer.py
   │
   └── Archive
         └── archive_analyzer.py
                └── file_analyzer.py
```

The Discord bot acts primarily as a **router and presentation layer**, while the individual analysis modules handle the actual inspection.

## Project Structure

```text
IOCYRA/
├── iocyra.py
├── url_analyzer.py
├── file_analyzer.py
├── archive_analyzer.py
└── .venv/
```

## Planned Development

The project is still evolving. Possible future additions include:

* Expanded VirusTotal integration
* Additional file formats and archive types
* Improved PE analysis
* Magic-byte based file identification
* More YARA integration
* Additional IOC extraction
* More detailed Discord analysis results
* Improved nested archive handling
* Additional static analysis techniques

## Security Considerations

IOCYRA is designed around **static analysis**.

Uploaded files are saved temporarily for analysis and are not executed by the bot. Archive extraction is performed with size, file-count, and path-safety restrictions to reduce the risk of malicious archives abusing the analysis process.

Analysis results should be treated as **triage information**, not definitive proof that a file is malicious or safe.

## License

IOCYRA is released under the **MIT License**.

See [`LICENSE`](LICENSE) for the full license text.

---
