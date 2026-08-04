"""Render :class:`OperationResult` objects into report files.

Supported formats: ``json``, ``csv``, ``txt`` and ``html`` out of the box, plus
``pdf`` when ``reportlab`` is installed (it degrades to an informative error
otherwise). Every write goes through :func:`utils.security.validate_output_path`
so a report can never be written outside the configured roots.
"""

from __future__ import annotations

import csv
import dataclasses
import html
import io
import json
from pathlib import Path
from typing import Sequence

from core.base import OperationResult
from utils.exceptions import DependencyError, ToolError
from utils.formatting import human_duration, utc_now_iso, utc_stamp
from utils.security import redact, redact_data, redact_iter, validate_output_path

SUPPORTED_FORMATS: tuple[str, ...] = ("json", "csv", "txt", "html", "pdf")


def generate_report(
    results: Sequence[OperationResult],
    *,
    fmt: str = "json",
    output_dir: str | Path = "reports",
    allowed_roots: Sequence[str] | None = None,
    title: str = "DevOps Toolkit Report",
) -> Path:
    """Write *results* to ``output_dir`` in *fmt*; return the file path."""
    fmt = fmt.lower()
    if fmt not in SUPPORTED_FORMATS:
        raise ToolError(f"Unsupported report format: {fmt!r} (choose {SUPPORTED_FORMATS})")

    out_dir = validate_output_path(output_dir, allowed_roots=allowed_roots)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = validate_output_path(out_dir / f"report_{utc_stamp()}.{fmt}", allowed_roots=allowed_roots)

    # Redact secrets from every result before it is written to disk.
    results = [_redacted(r) for r in results]

    renderer = {
        "json": _render_json,
        "csv": _render_csv,
        "txt": _render_txt,
        "html": _render_html,
        "pdf": _render_pdf,
    }[fmt]
    payload = renderer(results, title)
    if fmt == "pdf":
        path.write_bytes(payload)  # type: ignore[arg-type]
    else:
        path.write_text(payload, encoding="utf-8")  # type: ignore[arg-type]
    return path


def _redacted(r: OperationResult) -> OperationResult:
    """Return a copy of *r* with secrets masked in its exported fields."""
    return dataclasses.replace(
        r,
        message=redact(r.message),
        data=redact_data(r.data),
        errors=redact_iter(r.errors),
        warnings=redact_iter(r.warnings),
    )


def _summary(results: Sequence[OperationResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status.value] = counts.get(r.status.value, 0) + 1
    return counts


def _render_json(results: Sequence[OperationResult], title: str) -> str:
    document = {
        "title": title,
        "generated_at": utc_now_iso(),
        "summary": _summary(results),
        "results": [r.as_dict() for r in results],
    }
    return json.dumps(document, indent=2, default=str)


def _render_csv(results: Sequence[OperationResult], title: str) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["tool", "action", "status", "duration_ms", "message", "errors"])
    for r in results:
        writer.writerow(
            [r.tool, r.action, r.status.value, r.duration_ms, r.message, "; ".join(r.errors)]
        )
    return buffer.getvalue()


def _render_txt(results: Sequence[OperationResult], title: str) -> str:
    lines = [title, "=" * len(title), f"Generated: {utc_now_iso()}", ""]
    for r in results:
        lines.append(f"[{r.status.value.upper()}] {r.tool}.{r.action} "
                     f"({human_duration(r.duration_ms / 1000)})")
        if r.message:
            lines.append(f"    {r.message}")
        for err in r.errors:
            lines.append(f"    ! {err}")
    lines.append("")
    lines.append("Summary: " + ", ".join(f"{k}={v}" for k, v in _summary(results).items()))
    return "\n".join(lines)


def _render_html(results: Sequence[OperationResult], title: str) -> str:
    rows = []
    for r in results:
        colour = {"success": "#1a7f37", "dry_run": "#0969da", "partial": "#9a6700",
                  "skipped": "#57606a", "failure": "#cf222e"}.get(r.status.value, "#57606a")
        rows.append(
            "<tr>"
            f"<td>{html.escape(r.tool)}</td>"
            f"<td>{html.escape(r.action)}</td>"
            f"<td style='color:{colour};font-weight:600'>{r.status.value}</td>"
            f"<td>{r.duration_ms} ms</td>"
            f"<td>{html.escape(r.message)}</td>"
            "</tr>"
        )
    summary = ", ".join(f"{k}: {v}" for k, v in _summary(results).items())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #24292f; }}
  h1 {{ font-size: 1.4rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #d0d7de; }}
  th {{ background: #f6f8fa; }}
  .meta {{ color: #57606a; font-size: .9rem; }}
</style></head><body>
<h1>{html.escape(title)}</h1>
<p class="meta">Generated {utc_now_iso()} &middot; {html.escape(summary)}</p>
<table><thead><tr><th>Tool</th><th>Action</th><th>Status</th><th>Duration</th><th>Message</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</body></html>"""


def _render_pdf(results: Sequence[OperationResult], title: str) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.pdfgen import canvas
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise DependencyError(
            "PDF reports require 'reportlab' (pip install reportlab)"
        ) from exc

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 2 * cm
    pdf.setFont("Helvetica-Bold", 15)
    pdf.drawString(2 * cm, y, title)
    y -= 0.7 * cm
    pdf.setFont("Helvetica", 9)
    pdf.drawString(2 * cm, y, f"Generated {utc_now_iso()}")
    y -= 0.8 * cm
    for r in results:
        if y < 2 * cm:
            pdf.showPage()
            y = height - 2 * cm
            pdf.setFont("Helvetica", 9)
        pdf.drawString(2 * cm, y, f"[{r.status.value.upper()}] {r.tool}.{r.action} — {r.message[:80]}")
        y -= 0.55 * cm
    pdf.showPage()
    pdf.save()
    return buffer.getvalue()
