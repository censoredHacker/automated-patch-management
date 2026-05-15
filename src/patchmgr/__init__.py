"""patchmgr — cross-platform automated patch management CLI.

This package is organised into small, focused sub-packages so that each
layer can be reasoned about and tested independently:

    cli            — command line parsing and entrypoint
    config         — pydantic settings and inventory schemas
    credentials    — parsing and safe handling of IP:user:pass strings
    logging_setup  — JSON + console logging configuration
    transport      — SSH / WinRM connection abstractions
    vulnsource     — pluggable CVE feed clients (NVD, local file, ...)
    handlers       — per-OS discovery and remediation logic
    engine         — orchestration (discovery, prioritise, patch, reboot)
    reporting      — JSON and HTML report writers
    utils          — small reusable helpers (retry, shell quoting, ...)

Public version string is exposed for `--version` and report metadata.
"""

__version__ = "0.1.0"
