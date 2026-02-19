"""Render scan results as a PDF report.

Converts markdown to HTML, then HTML to PDF via weasyprint.
Requires: weasyprint (optional dependency, installed via `pip install la-analyzer[pdf]`).
"""

from __future__ import annotations

from pathlib import Path

from la_analyzer.render.markdown import render_markdown
from la_analyzer.scanner import ScanResult

# Minimal CSS for clean PDF output
_CSS = """\
body {
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.5;
    color: #1a1a1a;
    max-width: 800px;
    margin: 0 auto;
    padding: 40px;
}
h1 { font-size: 22pt; border-bottom: 2px solid #333; padding-bottom: 8px; }
h2 { font-size: 16pt; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 28px; }
h3 { font-size: 13pt; margin-top: 20px; }
h4 { font-size: 11pt; margin-top: 16px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 10pt; }
th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; }
th { background: #f5f5f5; font-weight: 600; }
code { background: #f4f4f4; padding: 1px 4px; border-radius: 3px; font-size: 10pt; }
pre { background: #f4f4f4; padding: 12px; border-radius: 4px; overflow-x: auto; }
blockquote { border-left: 4px solid #e74c3c; padding: 8px 16px; margin: 12px 0; background: #fdf2f2; }
hr { border: none; border-top: 1px solid #ddd; margin: 24px 0; }
ul { padding-left: 20px; }
"""


def render_pdf(result: ScanResult, output_path: Path) -> None:
    """Render the scan result to a PDF file.

    Requires weasyprint. Install via: pip install la-analyzer[pdf]
    """
    try:
        import markdown as md_lib
    except ImportError:
        raise ImportError(
            "PDF output requires the 'markdown' package. "
            "Install it with: pip install la-analyzer[pdf]"
        )

    try:
        from weasyprint import HTML, CSS
    except ImportError:
        raise ImportError(
            "PDF output requires 'weasyprint'. "
            "Install it with: pip install la-analyzer[pdf]"
        )

    # Render markdown
    md_text = render_markdown(result)

    # Convert to HTML
    html_body = md_lib.markdown(
        md_text,
        extensions=["tables", "fenced_code"],
    )
    html_doc = f"""\
<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body>{html_body}</body></html>
"""

    # Convert to PDF
    html = HTML(string=html_doc)
    css = CSS(string=_CSS)
    html.write_pdf(output_path, stylesheets=[css])
