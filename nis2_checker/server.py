from fastapi import FastAPI, Request, Form, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import json
import os
from typing import List
from datetime import datetime

from nis2_checker.config import load_config
from nis2_checker.scanner_logic import ScannerLogic
from nis2_checker.models import TargetScanResult

app = FastAPI(title="NIS2 Enterprise Platform")

# Setup Templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# In-memory storage for demo purposes (replace with SQLite/Redis in production)
SCAN_HISTORY: List[TargetScanResult] = []

def run_scan_task(target_url: str):
    """Background task to run the scan."""
    config = load_config('config.yaml')
    scanner = ScannerLogic(config)
    
    target = {"url": target_url, "name": target_url, "type": "generic"}
    results = scanner.scan_target(target)
    
    # Store results
    SCAN_HISTORY.extend(results)
    
    # Save to JSON file for persistence (simple version)
    with open('scan_history.json', 'w') as f:
        json.dump([r.model_dump(mode='json') for r in SCAN_HISTORY], f, indent=2)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "history": SCAN_HISTORY})

@app.post("/scan")
async def trigger_scan(background_tasks: BackgroundTasks, target: str = Form(...)):
    background_tasks.add_task(run_scan_task, target)
    return JSONResponse(content={"message": f"Scan started for {target}", "status": "queued"})

@app.get("/api/history")
async def get_history():
    return [r.model_dump(mode='json') for r in SCAN_HISTORY]

@app.get("/governance", response_class=HTMLResponse)
async def governance_checklist(request: Request):
    # Load checklist from markdown or a structured file
    # For now, rendering a placeholder or the markdown content
    return templates.TemplateResponse("governance.html", {"request": request})

if __name__ == "__main__":
    # Load history on startup
    if os.path.exists('scan_history.json'):
        try:
            with open('scan_history.json', 'r') as f:
                data = json.load(f)
                # Reconstruct objects (simplified)
                # In a real app, use Pydantic's parse_obj_as
                pass 
        except:
            pass
            
    uvicorn.run(app, host="0.0.0.0", port=8000)
