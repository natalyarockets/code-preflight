"""Infer what kind of data an app processes based on code patterns."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from la_analyzer.security.models import Evidence, DataClassification
from la_analyzer.utils import snippet

# ── PII field name patterns ──────────────────────────────────────────────────

_PII_FIELDS = re.compile(
    r"(?:(?<=_)|\b)(email|e_mail|phone|phone_number|mobile|ssn|social_security|"
    r"date_of_birth|dob|birth_date|address|street|zip_code|postal|"
    r"first_name|last_name|full_name|surname|maiden_name|"
    r"contact_name|contact_email|contact_phone|"
    r"driver_license|passport|national_id|tax_id|"
    r"ip_address|user_agent|device_id|mac_address|"
    r"gender|ethnicity|race|nationality|religion)(?=_|\b)",
    re.IGNORECASE,
)

_FINANCIAL_FIELDS = re.compile(
    r"(?:(?<=_)|\b)(salary|income|revenue|price|amount|balance|"
    r"account_number|routing_number|credit_card|card_number|cvv|"
    r"bank|payment|transaction|invoice|iban|swift|"
    r"net_worth|profit|loss|tax|deduction|"
    r"deal_value|deal_size|deal_amount|contract_value|opportunity_value|"
    r"quota|commission|discount|annual_revenue|mrr|arr)(?=_|\b)",
    re.IGNORECASE,
)

_HEALTH_FIELDS = re.compile(
    r"(?:(?<=_)|\b)(patient|diagnosis|treatment|medication|prescription|"
    r"blood_type|blood_pressure|heart_rate|bmi|weight|height|"
    r"symptom|allergy|vaccine|immunization|"
    r"medical_record|health_record|icd_code|npi|"
    r"insurance_id|policy_number|copay|deductible)(?=_|\b)",
    re.IGNORECASE,
)

_CREDENTIAL_FIELDS = re.compile(
    r"(?:(?<=_)|\b)(password|passwd|secret|token|api_key|access_key|"
    r"private_key|client_secret|bearer|credential|auth_token|"
    r"session_id|cookie|jwt|oauth)(?=_|\b)",
    re.IGNORECASE,
)

# Suffixes that indicate config/toggle variables, not actual data fields.
# e.g. email_env, phone_retry, ssn_format should NOT be classified as PII.
_CONFIG_SUFFIXES = {
    "_env", "_config", "_flag", "_setting", "_mode", "_enabled", "_disabled",
    "_type", "_format", "_pattern", "_regex", "_template", "_prefix", "_suffix",
    "_count", "_max", "_min", "_limit", "_timeout", "_retry", "_interval",
    "_provider", "_service", "_handler", "_factory", "_class", "_module",
    "_column", "_field", "_key", "_name", "_label", "_header", "_var",
}

# PII-detecting regex patterns in code (e.g. re.compile(r"\d{3}-\d{2}-\d{4}"))
_PII_REGEX_PATTERNS = [
    (re.compile(r"\\d\{3\}-\\d\{2\}-\\d\{4\}"), "SSN pattern"),
    (re.compile(r"\\d\{5\}(?:-\\d\{4\})?"), "ZIP code pattern"),
    (re.compile(r"\[a-zA-Z0-9.*@"), "Email pattern"),
    (re.compile(r"\\d\{3\}[-)\\s]?\\d\{3\}"), "Phone number pattern"),
    (re.compile(r"\\d\{4\}[- ]?\\d\{4\}[- ]?\\d\{4\}[- ]?\\d\{4\}"), "Credit card pattern"),
]

# File name patterns suggesting data types
_FILE_NAME_PATTERNS = [
    (re.compile(r"patient|medical|health|diagnos", re.I), "health"),
    (re.compile(r"transaction|payment|invoice|billing|financial", re.I), "financial"),
    (re.compile(r"customer|user|employee|person|contact|member", re.I), "pii"),
    (re.compile(r"credential|password|secret|key", re.I), "credential"),
]


def classify_data(workspace: Path, py_files: list[Path]) -> list[DataClassification]:
    """Analyze code to infer data classification categories."""
    # Accumulate evidence per category
    categories: dict[str, list[tuple[list[str], list[Evidence]]]] = {
        "pii": [],
        "financial": [],
        "health": [],
        "credential": [],
    }

    hashing_evidence: list[Evidence] = []

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            # Regex fallback for unparseable files
            _regex_classify(source, rel, categories)
            continue

        # Track hashlib/bcrypt imports separately
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("hashlib", "bcrypt"):
                        hashing_evidence.append(
                            Evidence(file=rel, line=node.lineno, snippet=snippet(source, node.lineno))
                        )
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module in ("hashlib", "bcrypt"):
                    hashing_evidence.append(
                        Evidence(file=rel, line=node.lineno, snippet=snippet(source, node.lineno))
                    )

        _ast_classify(tree, source, rel, categories)
        _regex_classify(source, rel, categories)

    # Only add hashing signal if real PII fields were already detected
    if hashing_evidence and categories["pii"]:
        categories["pii"].append(
            (["hashing_detected (positive signal)"], hashing_evidence)
        )

    # Build results
    results: list[DataClassification] = []
    for cat, entries in categories.items():
        if not entries:
            continue
        all_fields: list[str] = []
        all_evidence: list[Evidence] = []
        for fields, evs in entries:
            all_fields.extend(fields)
            all_evidence.extend(evs)

        # Deduplicate fields
        unique_fields = sorted(set(all_fields))
        # Confidence based on evidence count
        confidence = min(0.95, 0.4 + 0.1 * len(unique_fields))

        results.append(DataClassification(
            category=cat,
            confidence=round(confidence, 2),
            evidence=all_evidence[:20],  # Cap evidence list
            fields_detected=unique_fields[:30],
        ))

    return results


def _ast_classify(
    tree: ast.Module,
    source: str,
    rel: str,
    categories: dict[str, list[tuple[list[str], list[Evidence]]]],
) -> None:
    """Walk AST for string constants, dict keys, column names, etc."""
    for node in ast.walk(tree):
        strings_to_check: list[tuple[str, int]] = []

        # NOTE: We intentionally do NOT scan all ast.Constant strings here.
        # Bare string literals include prompts, log messages, and docstrings
        # which match field-name regexes but are not actual data fields.
        # We only check strings in structured contexts (dict keys, subscripts,
        # column keyword args) plus variable/function/class names.

        # Dict keys
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    strings_to_check.append((key.value, key.lineno))

        # Subscript string keys: df["email"], row["ssn"]
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                strings_to_check.append((node.slice.value, node.lineno))

        # .get() dict access: row.get("email"), a.get("annual_revenue")
        # Excludes os.environ.get() — reading env vars is not a data field.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (node.func.attr == "get"
                    and node.args
                    and not (isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "environ")):
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    strings_to_check.append((arg.value, node.lineno))

        # Variable names that hint at data types.
        # Skip function/class definition names — they describe operations
        # (generate_email, PatientValidator), not data fields.
        # Skip ALL_CAPS names — they're constants/config (EMAIL_PROVIDER),
        # not data fields.
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and not target.id.isupper():
                    strings_to_check.append((target.id, node.lineno))
        # Annotated assignments: email: str, patient_id: int (Pydantic/dataclass fields)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if not node.target.id.isupper():
                strings_to_check.append((node.target.id, node.lineno))

        # Keyword arguments (e.g., columns=["email", "ssn"])
        if isinstance(node, ast.keyword) and node.arg:
            if node.arg in ("columns", "names", "fields", "schema"):
                if isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            strings_to_check.append((elt.value, node.value.lineno))

        for val, lineno in strings_to_check:
            ev = Evidence(file=rel, line=lineno, snippet=snippet(source, lineno))
            _check_field(val, ev, categories)

        # Check for PII regex patterns in re.compile() args
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in ("compile", "match", "search", "findall"):
                arg = _first_str_arg(node)
                if arg:
                    ev = Evidence(file=rel, line=node.lineno, snippet=snippet(source, node.lineno))
                    for pat, label in _PII_REGEX_PATTERNS:
                        if pat.search(arg):
                            categories["pii"].append(
                                ([label], [ev])
                            )
                            break


def _regex_classify(
    source: str,
    rel: str,
    categories: dict[str, list[tuple[list[str], list[Evidence]]]],
) -> None:
    """Infer data category from the file's own path/name."""
    # Only check the file path itself — scanning every source line for words
    # like "user" or "contact" produces massive false positives from comments,
    # prompts, and log messages.
    for pat, cat in _FILE_NAME_PATTERNS:
        if pat.search(rel):
            ev = Evidence(file=rel, line=0, snippet=rel)
            match_text = pat.search(rel)
            if match_text:
                categories[cat].append(([f"filename:{match_text.group()}"], [ev]))


def _check_field(
    value: str,
    ev: Evidence,
    categories: dict[str, list[tuple[list[str], list[Evidence]]]],
) -> None:
    """Check a string value against field name patterns."""
    if len(value) < 2 or len(value) > 60:
        return
    # Skip values that look like sentences/prose — real field names
    # are short identifiers, not multi-word messages or prompts.
    if value.count(" ") >= 3:
        return

    # Normalize to lowercase for suffix check
    lower = value.lower()

    if _PII_FIELDS.search(value) and not _has_config_suffix(lower):
        categories["pii"].append(([value], [ev]))
    if _FINANCIAL_FIELDS.search(value) and not _has_config_suffix(lower):
        categories["financial"].append(([value], [ev]))
    if _HEALTH_FIELDS.search(value) and not _has_config_suffix(lower):
        categories["health"].append(([value], [ev]))
    if _CREDENTIAL_FIELDS.search(value):
        categories["credential"].append(([value], [ev]))


def _has_config_suffix(lower_value: str) -> bool:
    """Check if a lowercase field name ends with a config/toggle suffix."""
    return any(lower_value.endswith(suffix) for suffix in _CONFIG_SUFFIXES)


def _first_str_arg(node: ast.Call) -> str | None:
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


