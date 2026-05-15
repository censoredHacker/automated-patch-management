"""Persist a :class:`HostReport` as JSON + HTML files."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterable

from jinja2 import Environment, FileSystemLoader, select_autoescape

from patchmgr.reporting.models import HostReport


logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def write_reports(
    report: HostReport,
    *,
    output_dir: Path,
    formats: Iterable[str] = ("json", "html"),
) -> dict[str, Path]:
    """Write *report* under ``<output_dir>/<run_id>/``.

    Returns a mapping ``{format: path}`` of files actually written so
    the CLI can surface them to the operator.
    """
    run_dir = output_dir / report.metadata.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    if "json" in formats:
        path = run_dir / "report.json"
        path.write_text(
            json.dumps(report.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        written["json"] = path
        logger.info("wrote JSON report: %s", path)

    if "html" in formats:
        env = _jinja_env()
        template = env.get_template("report.html.j2")
        path = run_dir / "report.html"
        path.write_text(
            template.render(report=report.to_dict()),
            encoding="utf-8",
        )
        written["html"] = path
        logger.info("wrote HTML report: %s", path)

    return written


def write_aggregate(
    reports: list[HostReport],
    *,
    output_dir: Path,
    aggregate_id: str,
) -> Path:
    """Write a multi-host summary JSON for batch runs."""
    run_dir = output_dir / f"batch-{aggregate_id}"
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "summary.json"
    payload = {
        "aggregate_id": aggregate_id,
        "host_count": len(reports),
        "hosts": [r.to_dict() for r in reports],
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    logger.info("wrote batch summary: %s", path)
    return path
