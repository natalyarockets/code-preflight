"""CLI entry point for la-analyzer."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click

from la_analyzer import __version__
from la_analyzer.scanner import scan


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "-f", "--format", "fmt",
    type=click.Choice(["md", "pdf", "json"], case_sensitive=False),
    default="md",
    help="Output format (default: md).",
)
@click.option(
    "-o", "--output",
    type=click.Path(resolve_path=True),
    default=None,
    help="Output file path. Defaults to stdout for md/json, or report.pdf for pdf.",
)
@click.option(
    "--no-security", is_flag=True, default=False,
    help="Skip security scanners (analysis only).",
)
@click.option(
    "--json-dir",
    type=click.Path(resolve_path=True),
    default=None,
    help="Directory for raw JSON reports. Defaults to <path>/.la-analyzer/.",
)
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbose logging.")
@click.version_option(version=__version__)
def main(
    path: str,
    fmt: str,
    output: str | None,
    no_security: bool,
    json_dir: str | None,
    verbose: bool,
) -> None:
    """Scan a Python project for structure, dependencies, security issues, and more."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(name)s %(levelname)s: %(message)s",
    )

    project_path = Path(path)
    output_dir = Path(json_dir) if json_dir else None

    result = scan(
        project_path,
        output_dir=output_dir,
        run_security=not no_security,
    )

    if fmt == "json":
        _output_json(result, output)
    elif fmt == "pdf":
        _output_pdf(result, output)
    else:
        _output_md(result, output)


def _output_md(result, output: str | None) -> None:
    from la_analyzer.render.markdown import render_markdown
    md = render_markdown(result)
    if output:
        Path(output).write_text(md)
        click.echo(f"Report written to {output}")
    else:
        click.echo(md)


def _output_pdf(result, output: str | None) -> None:
    from la_analyzer.render.pdf import render_pdf
    dest = Path(output) if output else Path("report.pdf")
    render_pdf(result, dest)
    click.echo(f"PDF report written to {dest}")


def _output_json(result, output: str | None) -> None:
    data = {
        "analysis": result.analysis.model_dump(),
    }
    if result.security:
        data["security"] = result.security.model_dump()
    if result.projection:
        data["projection"] = result.projection.model_dump()

    text = json.dumps(data, indent=2)
    if output:
        Path(output).write_text(text)
        click.echo(f"JSON report written to {output}")
    else:
        click.echo(text)


if __name__ == "__main__":
    main()
