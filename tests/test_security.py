"""Tests for the pre-deploy security review scanners."""

import tempfile
from pathlib import Path

from la_analyzer.security.code_scan import scan_code
from la_analyzer.security.data_classify import classify_data
from la_analyzer.security.data_flow import scan_data_flow
from la_analyzer.security.credential_leak import scan_credential_leaks
from la_analyzer.security.vuln_scan import _typosquat_check, _edit_distance
from la_analyzer.security.resource_score import scan_resource_abuse
from la_analyzer.security import run_security_review


def _write(tmpdir: Path, name: str, content: str) -> Path:
    p = tmpdir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


# -- Code Injection Scanner ---------------------------------------------------


def test_detects_exec_eval():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "app.py", '''
data = input("code: ")
exec(data)
result = eval("1+1")
''')
        findings = scan_code(ws, [f])
        titles = [f.title for f in findings]
        assert any("exec()" in t for t in titles)
        assert any("eval()" in t for t in titles)


def test_detects_subprocess():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "app.py", '''
import subprocess
subprocess.run(["ls", "-la"])
subprocess.Popen("rm -rf /", shell=True)
''')
        findings = scan_code(ws, [f])
        assert any("subprocess" in f.title for f in findings)
        assert any(f.severity == "critical" for f in findings)


def test_detects_os_system():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "app.py", '''
import os
os.system("rm -rf /tmp/data")
''')
        findings = scan_code(ws, [f])
        assert any("os.system" in f.title for f in findings)
        assert any(f.severity == "critical" for f in findings)


def test_detects_dynamic_import():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "app.py", '''
mod = __import__("openai")
import importlib
importlib.import_module("anthropic")
''')
        findings = scan_code(ws, [f])
        assert any("import" in f.title.lower() for f in findings)


def test_detects_ctypes():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "native.py", '''
import ctypes
libc = ctypes.CDLL("libc.so.6")
''')
        findings = scan_code(ws, [f])
        assert any("ctypes" in f.title for f in findings)


def test_detects_unsafe_yaml():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "loader.py", '''
import yaml
data = yaml.load(open("config.yaml"))
''')
        findings = scan_code(ws, [f])
        assert any("YAML" in f.title for f in findings)


def test_safe_yaml_no_finding():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "loader.py", '''
import yaml
data = yaml.safe_load(open("config.yaml"))
''')
        findings = scan_code(ws, [f])
        assert not any("YAML" in f.title for f in findings)


def test_detects_pickle():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "app.py", '''
import pickle
obj = pickle.loads(data)
''')
        findings = scan_code(ws, [f])
        assert any("pickle" in f.title.lower() for f in findings)


def test_json_loads_not_flagged():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "app.py", '''
import json
data = json.loads('{"key": "value"}')
''')
        findings = scan_code(ws, [f])
        assert not any("deserialization" in f.title.lower() for f in findings)


# -- PII / Data Classifier ----------------------------------------------------


def test_detects_pii_fields():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "process.py", '''
import pandas as pd
df = pd.read_csv("users.csv")
emails = df["email"]
phones = df["phone_number"]
ssns = df["ssn"]
''')
        classifications = classify_data(ws, [f])
        cats = [c.category for c in classifications]
        assert "pii" in cats
        pii = next(c for c in classifications if c.category == "pii")
        assert any("email" in f for f in pii.fields_detected)
        assert any("ssn" in f for f in pii.fields_detected)


def test_detects_financial_fields():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "process.py", '''
data = {"salary": 100000, "account_number": "12345", "balance": 500}
''')
        classifications = classify_data(ws, [f])
        cats = [c.category for c in classifications]
        assert "financial" in cats


def test_detects_health_fields():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "medical.py", '''
patient_records = [
    {"patient": "Jane", "diagnosis": "flu", "medication": "tamiflu"}
]
''')
        classifications = classify_data(ws, [f])
        cats = [c.category for c in classifications]
        assert "health" in cats


def test_no_classification_for_clean_code():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "math.py", '''
def add(a, b):
    return a + b

result = add(1, 2)
''')
        classifications = classify_data(ws, [f])
        assert len(classifications) == 0


def test_function_names_not_classified_as_pii():
    """Function names like generate_email should not be flagged as PII."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "outreach.py", '''
def generate_email(contact):
    return f"Hello {contact}"

def validate_address(addr):
    return bool(addr)

def send_email(msg):
    pass
''')
        classifications = classify_data(ws, [f])
        pii = [c for c in classifications if c.category == "pii"]
        # Function names should not trigger PII classification
        pii_fields = []
        for c in pii:
            pii_fields.extend(c.fields_detected)
        assert "generate_email" not in pii_fields
        assert "validate_address" not in pii_fields
        assert "send_email" not in pii_fields


def test_allcaps_constants_not_classified_as_pii():
    """ALL_CAPS constants like EMAIL_PROVIDER should not be flagged as PII."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "config.py", '''
EMAIL_PROVIDER = "gmail"
EMAIL_TEMPLATE = "template.html"
PATIENT_SYSTEM = "epic"
''')
        classifications = classify_data(ws, [f])
        all_fields = []
        for c in classifications:
            all_fields.extend(c.fields_detected)
        assert "EMAIL_PROVIDER" not in all_fields
        assert "EMAIL_TEMPLATE" not in all_fields
        assert "PATIENT_SYSTEM" not in all_fields


# -- LLM Data Flow Scanner ----------------------------------------------------


def test_detects_file_data_to_llm():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "analyze.py", '''
import openai
import pandas as pd

client = openai.OpenAI()
data = pd.read_csv("customers.csv")

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": str(data)}],
)
''')
        risks = scan_data_flow(ws, [f])
        assert len(risks) >= 1
        assert any(r.severity in ("high", "critical") for r in risks)


def test_detects_pii_in_llm_prompt():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "analyze.py", '''
import openai

client = openai.OpenAI()
email = "test@example.com"

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": f"Process this email: {email}"}],
)
''')
        risks = scan_data_flow(ws, [f])
        assert len(risks) >= 1


def test_csv_dictreader_taint_propagation():
    """csv.DictReader data should be tainted as file data."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "reader.py", '''
import csv
import openai

client = openai.OpenAI()

with open("accounts.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        prompt = f"Analyze: {row}"
        client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
        )
''')
        risks = scan_data_flow(ws, [f])
        llm_risks = [r for r in risks if "LLM" in r.data_sink]
        assert len(llm_risks) >= 1


def test_file_source_attribution():
    """File path should be attributed in data_source, not 'unknown'."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "analyze.py", '''
import openai
import pandas as pd

client = openai.OpenAI()
data = pd.read_csv("customers.csv")

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": str(data)}],
)
''')
        risks = scan_data_flow(ws, [f])
        llm_risks = [r for r in risks if "LLM" in r.data_sink]
        assert len(llm_risks) >= 1
        assert any("customers.csv" in r.data_source for r in llm_risks)


def test_no_llm_risk_without_llm():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "process.py", '''
import pandas as pd

data = pd.read_csv("data.csv")
data.to_csv("output.csv")
''')
        risks = scan_data_flow(ws, [f])
        llm_risks = [r for r in risks if "LLM" in r.data_sink]
        assert len(llm_risks) == 0


# -- Credential Leak Scanner --------------------------------------------------


def test_detects_secret_in_print():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "debug.py", '''
import os
api_key = os.environ.get("API_KEY")
print(f"Using key: {api_key}")
''')
        risks = scan_credential_leaks(ws, [f])
        assert len(risks) >= 1
        assert any(r.leak_target == "log_output" for r in risks)


def test_detects_secret_in_llm_call():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "bad.py", '''
password = "my_secret_123"

def create(messages):
    return {"content": str(messages)}

create(messages=[{"role": "user", "content": f"Use password: {password}"}])
''')
        risks = scan_credential_leaks(ws, [f])
        assert len(risks) >= 1


def test_detects_environ_dump():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "debug.py", '''
import os
for key, val in os.environ.items():
    print(f"{key}={val}")
''')
        risks = scan_credential_leaks(ws, [f])
        assert any(r.credential_name == "os.environ" for r in risks)


def test_no_leak_for_safe_code():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "safe.py", '''
import os
api_key = os.environ.get("API_KEY")
# Key is used internally, not logged or sent
result = do_work(api_key)
''')
        risks = scan_credential_leaks(ws, [f])
        # do_work is not a known leak target
        assert len(risks) == 0


# -- Vulnerability / Typosquat Scanner ----------------------------------------


def test_edit_distance():
    assert _edit_distance("requests", "requests") == 0
    assert _edit_distance("requets", "requests") == 1
    assert _edit_distance("reqeusts", "requests") == 2
    assert _edit_distance("abc", "xyz") == 3


def test_typosquat_detection():
    findings = _typosquat_check(["requets", "pandas", "numpyy"])
    assert len(findings) >= 1
    assert any("requets" in f.title for f in findings)


def test_legit_packages_not_flagged():
    findings = _typosquat_check(["pandas", "numpy", "requests", "flask"])
    assert len(findings) == 0


# -- Resource Abuse Scanner ----------------------------------------------------


def test_detects_infinite_loop():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "loop.py", '''
while True:
    do_work()
''')
        findings = scan_resource_abuse(ws, [f])
        assert any("infinite loop" in f.title.lower() for f in findings)


def test_while_true_with_break_ok():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "loop.py", '''
while True:
    data = get_data()
    if data is None:
        break
    process(data)
''')
        findings = scan_resource_abuse(ws, [f])
        assert not any("infinite loop" in f.title.lower() for f in findings)


def test_detects_os_fork():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "spawn.py", '''
import os
pid = os.fork()
''')
        findings = scan_resource_abuse(ws, [f])
        assert any("fork" in f.title.lower() for f in findings)


def test_detects_multiprocessing():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "parallel.py", '''
import multiprocessing
pool = multiprocessing.Pool(16)
''')
        findings = scan_resource_abuse(ws, [f])
        assert any("multiprocessing" in f.title.lower() for f in findings)


def test_dict_get_in_loop_not_flagged():
    """dict.get() inside a loop should NOT be flagged as a network call."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "process.py", '''
data = [{"city": "NYC", "temp": 72}, {"city": "LA", "temp": 85}]
for row in data:
    city = row.get("city")
    temp = row.get("temp")
    print(f"{city}: {temp}")
''')
        findings = scan_resource_abuse(ws, [f])
        network_findings = [f for f in findings if "network" in f.title.lower()]
        assert len(network_findings) == 0


def test_http_get_in_loop_flagged():
    """requests.get() inside a loop SHOULD be flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "fetcher.py", '''
import requests
urls = ["http://api.example.com/1", "http://api.example.com/2"]
for url in urls:
    resp = requests.get(url)
    print(resp.status_code)
''')
        findings = scan_resource_abuse(ws, [f])
        network_findings = [f for f in findings if "network" in f.title.lower()]
        assert len(network_findings) == 1


# -- Data Flow: HTTP & File Sinks ---------------------------------------------


def test_detects_http_data_sink():
    """File data passed to requests.post() should be flagged as HTTP sink."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "uploader.py", '''
import requests
import pandas as pd

data = pd.read_csv("accounts.csv")
requests.post("https://api.example.com/upload", json=data.to_dict())
''')
        risks = scan_data_flow(ws, [f])
        http_risks = [r for r in risks if r.data_sink == "HTTP API call"]
        assert len(http_risks) >= 1


def test_detects_output_file_sink():
    """PII data written to output file should be flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "exporter.py", '''
import pandas as pd

df = pd.read_csv("customers.csv")
emails = df["email"]
df.to_csv("output/results.csv")
''')
        risks = scan_data_flow(ws, [f])
        file_risks = [r for r in risks if r.data_sink == "output file"]
        assert len(file_risks) >= 1


def test_cross_function_parameter_flow():
    """File data flowing via parameter to LLM-calling function should be detected."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "pipeline.py", '''
import openai
import pandas as pd

client = openai.OpenAI()

def load_data():
    return pd.read_csv("accounts.csv")

def analyze(data):
    prompt = f"Analyze: {data}"
    client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )

def main():
    accounts = load_data()
    analyze(accounts)

main()
''')
        risks = scan_data_flow(ws, [f])
        cross_func_risks = [r for r in risks if "parameter" in r.data_source.lower()
                           or "via" in r.data_source.lower()]
        assert len(cross_func_risks) >= 1


# -- Orchestrator Integration --------------------------------------------------


def test_full_security_review():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "main.py", '''
import os
import subprocess
import pandas as pd

api_key = os.environ.get("API_KEY")
print(f"Key: {api_key}")

data = pd.read_csv("patients.csv")
email = data["email"]

subprocess.run(["echo", "hello"])

while True:
    pass
''')
        report = run_security_review(
            workspace_dir=ws,
            requirements=["pandas", "requets"],  # typosquat
        )

        # Should have findings
        assert report.critical_count > 0  # subprocess
        assert report.deploy_blocked is True

        # Should detect PII
        assert len(report.data_classifications) > 0

        # Should detect credential leak
        assert len(report.credential_leak_risks) > 0

        # Should detect typosquat
        assert any("requets" in f.title for f in report.findings)

        # Basic checks
        assert report.created_at


def test_clean_app_passes():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "main.py", '''
def add(a, b):
    return a + b

if __name__ == "__main__":
    result = add(1, 2)
    print(result)
''')
        report = run_security_review(
            workspace_dir=ws,
        )
        assert report.deploy_blocked is False
        assert report.critical_count == 0
        assert report.high_count == 0


def test_security_report_written_to_disk():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        report_dir = Path(d) / "reports"
        _write(ws, "app.py", '''
import os
key = os.system("echo test")
''')
        report = run_security_review(
            workspace_dir=ws,
            report_dir=report_dir,
        )
        report_file = report_dir / "security_report.json"
        assert report_file.exists()

        import json
        data = json.loads(report_file.read_text())
        assert data["created_at"]
        assert len(data["findings"]) > 0
