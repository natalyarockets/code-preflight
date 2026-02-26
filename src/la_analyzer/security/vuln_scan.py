"""Check dependencies for known vulnerabilities and typosquatting risks."""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from la_analyzer.security.models import Evidence, SecurityFinding

log = logging.getLogger(__name__)

# Well-known popular packages for typosquat detection
_POPULAR_PACKAGES = {
    "requests", "flask", "django", "numpy", "pandas", "scipy",
    "matplotlib", "pillow", "sqlalchemy", "fastapi", "pydantic",
    "boto3", "openai", "anthropic", "httpx", "aiohttp", "celery",
    "redis", "psycopg2", "pymongo", "cryptography", "paramiko",
    "scikit-learn", "tensorflow", "pytorch", "torch", "transformers",
    "beautifulsoup4", "selenium", "scrapy", "pytest", "black",
    "mypy", "ruff", "uvicorn", "gunicorn", "jinja2", "click",
    "typer", "rich", "pyyaml", "toml", "python-dotenv",
}


def scan_vulnerabilities(
    workspace: Path,
    requirements: list[str],
) -> list[SecurityFinding]:
    """Scan dependencies for vulnerabilities. MVP: pip-audit + typosquat check."""
    findings: list[SecurityFinding] = []

    # Try pip-audit if available
    findings.extend(_pip_audit_scan(workspace, requirements))

    # Typosquat detection
    findings.extend(_typosquat_check(requirements))

    return findings


def _pip_audit_scan(workspace: Path, requirements: list[str]) -> list[SecurityFinding]:
    """Run pip-audit against requirements if the tool is available."""
    findings: list[SecurityFinding] = []

    if not requirements:
        return findings

    # Write temporary requirements file outside the workspace
    tmp_dir = tempfile.mkdtemp(prefix="la_audit_")
    req_path = Path(tmp_dir) / "requirements.txt"
    try:
        req_path.write_text("\n".join(requirements) + "\n")
    except Exception as e:
        log.warning("Failed to write temp requirements: %s", e)
        return findings

    try:
        result = subprocess.run(
            ["pip-audit", "--requirement", str(req_path), "--format", "json",
             "--desc", "--no-deps"],
            capture_output=True, text=True, timeout=60,
        )
        if result.stdout:
            data = json.loads(result.stdout)
            for vuln in data.get("dependencies", []):
                pkg_name = vuln.get("name", "unknown")
                version = vuln.get("version", "unknown")
                for v in vuln.get("vulns", []):
                    vuln_id = v.get("id", "unknown")
                    desc = v.get("description", "")[:200]
                    fix_versions = v.get("fix_versions", [])
                    fix_str = f"Upgrade to {', '.join(fix_versions)}" if fix_versions else "No fix available"

                    findings.append(SecurityFinding(
                        category="deps",
                        severity="high" if "critical" in desc.lower() else "medium",
                        title=f"{vuln_id}: {pkg_name}=={version}",
                        description=desc or f"Known vulnerability in {pkg_name}",
                        evidence=[Evidence(
                            file="requirements.txt", line=1,
                            snippet=f"{pkg_name}=={version}",
                        )],
                        recommendation=fix_str,
                    ))
    except FileNotFoundError:
        log.info("pip-audit not installed, skipping vulnerability scan")
    except subprocess.TimeoutExpired:
        log.warning("pip-audit timed out")
    except Exception as e:
        log.warning("pip-audit failed: %s", e)
    finally:
        import shutil
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

    return findings


def _typosquat_check(requirements: list[str]) -> list[SecurityFinding]:
    """Check for potential typosquatting packages (edit distance to popular names)."""
    findings: list[SecurityFinding] = []

    for req in requirements:
        # Extract package name from requirement spec
        pkg = req.split(">=")[0].split("==")[0].split("<")[0].split("[")[0].strip().lower()
        if not pkg or pkg in _POPULAR_PACKAGES:
            continue

        # Check edit distance against popular packages
        for popular in _POPULAR_PACKAGES:
            dist = _edit_distance(pkg, popular)
            if 0 < dist <= 2 and len(pkg) >= 4:
                findings.append(SecurityFinding(
                    category="deps",
                    severity="high",
                    title=f"Possible typosquat: '{pkg}' (similar to '{popular}')",
                    description=f"Package '{pkg}' has edit distance {dist} from popular package '{popular}'. "
                                f"This could be a typosquatting attack.",
                    evidence=[Evidence(
                        file="requirements.txt", line=1,
                        snippet=req,
                    )],
                    recommendation=f"Verify this is the intended package, not '{popular}'.",
                ))

    return findings


def _edit_distance(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[j] + 1,
                prev[j + 1] + 1,
                prev[j] + cost,
            ))
        prev = curr

    return prev[len(b)]
