"""Tests for FastAPI route/signature detection."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.api_scan import scan_api


def _write_py(tmpdir: Path, name: str, code: str) -> Path:
    p = tmpdir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code)
    return p


# -- Upload detection ----------------------------------------------------------

def test_detects_upload_file():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI, UploadFile
app = FastAPI()

@app.post("/upload")
async def upload_image(image: UploadFile):
    return {"ok": True}
''')
        inputs, outputs, routes = scan_api(ws, [f])
        assert len(inputs) == 1
        assert inputs[0].kind == "upload"
        assert inputs[0].label == "Image Upload"
        assert inputs[0].confidence == 0.85


# -- Pydantic body detection --------------------------------------------------

def test_detects_pydantic_body():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI
app = FastAPI()

@app.post("/items")
async def create_item(body: ItemCreate):
    return body
''')
        inputs, outputs, routes = scan_api(ws, [f])
        assert len(inputs) == 1
        assert inputs[0].kind == "json_body"
        assert inputs[0].format == "json"
        assert inputs[0].label == "Item Create"
        assert inputs[0].confidence == 0.85


# -- Query param detection -----------------------------------------------------

def test_detects_query_param():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/items")
async def list_items(household_id: str):
    return []
''')
        inputs, outputs, routes = scan_api(ws, [f])
        assert len(inputs) == 1
        assert inputs[0].kind == "query_param"
        assert inputs[0].label == "Household Id"
        assert inputs[0].confidence == 0.7


# -- Path param detection ------------------------------------------------------

def test_detects_path_param():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/items/{item_id}")
async def get_item(item_id: str):
    return {}
''')
        inputs, outputs, routes = scan_api(ws, [f])
        assert len(inputs) == 1
        assert inputs[0].kind == "path_param"
        assert inputs[0].label == "Item Id"


# -- response_model kwarg detection --------------------------------------------

def test_detects_response_model_kwarg():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/items", response_model=ItemList)
async def list_items():
    return []
''')
        inputs, outputs, routes = scan_api(ws, [f])
        assert len(outputs) == 1
        assert outputs[0].kind == "response_model"
        assert outputs[0].format == "json"
        assert outputs[0].label == "Item List"
        assert outputs[0].confidence == 0.8


# -- Return type annotation detection -----------------------------------------

def test_detects_return_type_annotation():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/items")
async def list_items() -> ItemResponse:
    return ItemResponse()
''')
        inputs, outputs, routes = scan_api(ws, [f])
        assert len(outputs) == 1
        assert outputs[0].kind == "response_model"
        assert outputs[0].label == "Item Response"


# -- APIRouter support ---------------------------------------------------------

def test_works_with_api_router():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "router.py", '''
from fastapi import APIRouter
router = APIRouter(prefix="/api")

@router.get("/health")
async def health():
    return {"status": "ok"}
''')
        inputs, outputs, routes = scan_api(ws, [f])
        assert len(routes) == 1
        assert routes[0].method == "GET"
        assert routes[0].path == "/api/health"
        assert routes[0].handler == "health"


# -- Depends() params are skipped ----------------------------------------------

def test_skips_depends_params():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI, Depends
app = FastAPI()

@app.get("/items")
async def list_items(db=Depends(get_db), household_id: str = None):
    return []
''')
        inputs, outputs, routes = scan_api(ws, [f])
        # db should be skipped (Depends), household_id should be detected
        assert len(inputs) == 1
        assert inputs[0].kind == "query_param"
        assert inputs[0].label == "Household Id"


# -- Framework params are skipped ----------------------------------------------

def test_skips_framework_params():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI, Request
app = FastAPI()

@app.post("/webhook")
async def webhook(request: Request, payload: WebhookPayload):
    return {"ok": True}
''')
        inputs, outputs, routes = scan_api(ws, [f])
        # request should be skipped, payload should be detected
        assert len(inputs) == 1
        assert inputs[0].kind == "json_body"
        assert inputs[0].label == "Webhook Payload"


# -- APIRoute metadata --------------------------------------------------------

def test_api_route_metadata():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI, UploadFile
app = FastAPI()

@app.post("/detect", response_model=DetectResponse)
async def detect(image: UploadFile):
    pass
''')
        inputs, outputs, routes = scan_api(ws, [f])
        assert len(routes) == 1
        r = routes[0]
        assert r.method == "POST"
        assert r.path == "/detect"
        assert r.handler == "detect"
        assert r.file == "main.py"
        assert len(r.input_ids) == 1
        assert r.input_ids[0] == "api_input_0"
        assert len(r.output_ids) == 1
        assert r.output_ids[0] == "api_output_0"


# -- No false positives on batch code ------------------------------------------

def test_no_false_positives_on_batch():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "batch.py", '''
import pandas as pd

def main():
    df = pd.read_csv("input.csv")
    df.to_csv("output.csv")

if __name__ == "__main__":
    main()
''')
        inputs, outputs, routes = scan_api(ws, [f])
        assert inputs == []
        assert outputs == []
        assert routes == []


# -- Multiple routes in one file -----------------------------------------------

def test_multiple_routes():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI, UploadFile
app = FastAPI()

@app.post("/detect")
async def detect(image: UploadFile):
    pass

@app.get("/appliances/{appliance_id}")
async def get_appliance(appliance_id: str):
    pass

@app.post("/appliances", response_model=ApplianceResponse)
async def create_appliance(body: ApplianceCreate):
    pass
''')
        inputs, outputs, routes = scan_api(ws, [f])
        assert len(routes) == 3
        assert len(inputs) == 3  # image upload, appliance_id path, body
        assert len(outputs) == 1  # response_model
        # Verify route methods
        methods = {r.method for r in routes}
        assert methods == {"POST", "GET"}


# -- File() default detection --------------------------------------------------

def test_detects_file_default():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI, File
app = FastAPI()

@app.post("/upload")
async def upload(data: bytes = File(...)):
    return {"ok": True}
''')
        inputs, outputs, routes = scan_api(ws, [f])
        assert len(inputs) == 1
        assert inputs[0].kind == "upload"
