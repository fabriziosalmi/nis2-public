from fastapi import FastAPI, Request, Form, BackgroundTasks, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select
import uvicorn
import json
import os
import re
from typing import List, Dict
from datetime import datetime

from nis2_checker.config import load_config
from nis2_checker.scanner_logic import ScannerLogic
from nis2_checker.models import TargetScanResult, Target, ScanHistory, GovernanceChecklist, Severity
from nis2_checker.database import create_db_and_tables, get_session, engine

app = FastAPI(title="NIS2 Enterprise Platform")

# Setup Templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

def parse_governance_checklist():
    """Parses the governance_checklist.md file and returns a list of items."""
    checklist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'governance_checklist.md')
    if not os.path.exists(checklist_path):
        return []

    items = []
    current_category = "General"
    
    with open(checklist_path, 'r') as f:
        lines = f.readlines()
        
    for line in lines:
        line = line.strip()
        if "Critical Priority" in line:
            current_category = "Critical"
        elif "High Priority" in line:
            current_category = "High"
        elif "Medium Priority" in line:
            current_category = "Medium"
            
        # Match checklist items like "- [ ] **1. Title**: Description"
        match = re.match(r'- \[.\] \*\*(.*?)\*\*: (.*)', line)
        if match:
            title = match.group(1)
            description = match.group(2)
            # Extract ID from title if possible (e.g., "1. Title" -> "1")
            item_id = title.split('.')[0] if '.' in title else title
            
            items.append({
                "item_id": item_id,
                "category": current_category,
                "description": f"**{title}**: {description}",
                "status": "Not Started"
            })
    return items

def init_governance_data(session: Session):
    """Populates the DB with governance items if empty."""
    existing = session.exec(select(GovernanceChecklist)).first()
    if not existing:
        items = parse_governance_checklist()
        for item in items:
            db_item = GovernanceChecklist(**item)
            session.add(db_item)
        session.commit()
        print(f"Initialized {len(items)} governance items.")

@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    with Session(engine) as session:
        init_governance_data(session)

def run_scan_task(target_url: str):
    """Background task to run the scan and save to DB."""
    config = load_config('config.yaml')
    scanner = ScannerLogic(config)
    
    # Create or Get Target
    with Session(engine) as session:
        target = session.exec(select(Target).where(Target.url == target_url)).first()
        if not target:
            target = Target(url=target_url, name=target_url)
            session.add(target)
            session.commit()
            session.refresh(target)
        
        scan_target_dict = {"url": target.url, "name": target.name, "type": target.type}
        results = scanner.scan_target(scan_target_dict)
        
        for res in results:
            # Save Scan History
            scan_history = ScanHistory(
                target_id=target.id,
                compliance_score=res.compliance_score,
                details=res.model_dump(mode='json')
            )
            session.add(scan_history)
        session.commit()

@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request, session: Session = Depends(get_session)):
    # Fetch recent scans
    history = session.exec(select(ScanHistory).order_by(ScanHistory.timestamp.desc()).limit(50)).all()
    
    # Enrich history with target names (lazy loading or join)
    # For simplicity in template, we can access scan.target.name if relationship is loaded
    
    return templates.TemplateResponse("index.html", {"request": request, "history": history})

@app.post("/scan")
async def trigger_scan(background_tasks: BackgroundTasks, target: str = Form(...)):
    background_tasks.add_task(run_scan_task, target)
    return JSONResponse(content={"message": f"Scan started for {target}", "status": "queued"})

@app.get("/governance", response_class=HTMLResponse)
async def governance_page(request: Request, session: Session = Depends(get_session)):
    items = session.exec(select(GovernanceChecklist)).all()
    
    # Group by category
    grouped = {"Critical": [], "High": [], "Medium": []}
    for item in items:
        if item.category in grouped:
            grouped[item.category].append(item)
        else:
            # Fallback
            if "General" not in grouped: grouped["General"] = []
            grouped["General"].append(item)
            
    return templates.TemplateResponse("governance.html", {"request": request, "grouped_items": grouped})

@app.post("/governance/update/{item_id}")
async def update_governance_item(item_id: int, status: str = Form(...), notes: str = Form(None), session: Session = Depends(get_session)):
    item = session.get(GovernanceChecklist, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    
    item.status = status
    if notes is not None:
        item.notes = notes
    item.last_updated = datetime.now()
    session.add(item)
    session.commit()
    
    # Return a small HTML snippet or status for HTMX
    return HTMLResponse(content=f"<span class='text-green-400'>Saved</span>")

# --- API Endpoints ---

@app.post("/api/v1/scan/trigger")
async def api_trigger_scan(background_tasks: BackgroundTasks, target: str = Form(...)):
    """Trigger a scan via API (CI/CD integration)."""
    background_tasks.add_task(run_scan_task, target)
    return {"message": f"Scan started for {target}", "status": "queued"}

@app.get("/api/v1/compliance/status")
async def api_compliance_status(session: Session = Depends(get_session)):
    """Get overall compliance status."""
    # Calculate average technical score
    scans = session.exec(select(ScanHistory)).all()
    if not scans:
        tech_score = 0.0
    else:
        # Get latest scan for each target
        latest_scans = {}
        for scan in scans:
            if scan.target_id not in latest_scans or scan.timestamp > latest_scans[scan.target_id].timestamp:
                latest_scans[scan.target_id] = scan
        
        if not latest_scans:
            tech_score = 0.0
        else:
            tech_score = sum(s.compliance_score for s in latest_scans.values()) / len(latest_scans)

    # Calculate governance score
    gov_items = session.exec(select(GovernanceChecklist)).all()
    
    from nis2_checker.models import calculate_hybrid_score
    hybrid_score = calculate_hybrid_score(tech_score, gov_items)
    
    return {
        "compliance_score": hybrid_score,
        "technical_score": round(tech_score, 2),
        "governance_items_total": len(gov_items),
        "governance_items_done": sum(1 for i in gov_items if i.status == "Done"),
        "status": "Compliant" if hybrid_score == 100 else "Non-Compliant"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
