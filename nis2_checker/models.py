from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime
from sqlmodel import SQLModel, Field, Relationship, JSON

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class NIS2Article(BaseModel):
    article: str
    description: str

class CheckResult(SQLModel):
    check_id: str
    name: str
    status: str  # PASS, FAIL, WARNING, SKIPPED
    details: str
    severity: Severity
    nis2_article: Optional[str] = None
    remediation: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None

class TargetScanResult(SQLModel):
    target: str
    name: str
    timestamp: datetime = Field(default_factory=datetime.now)
    compliance_score: float = 0.0
    results: List[CheckResult] = []
    
    def calculate_score(self):
        if not self.results:
            return 0.0
        
        total_weight = 0
        earned_weight = 0
        
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0
        }
        
        for res in self.results:
            weight = weights.get(res.severity, 0)
            total_weight += weight
            if res.status == "PASS":
                earned_weight += weight
                
        if total_weight == 0:
            return 100.0
            
        self.compliance_score = round((earned_weight / total_weight) * 100, 2)
        return self.compliance_score

def calculate_hybrid_score(technical_score: float, governance_items: List[GovernanceChecklist]) -> float:
    """Calculates a hybrid compliance score (50% Technical, 50% Governance)."""
    if not governance_items:
        return round(technical_score * 0.5, 2)
        
    total_gov = len(governance_items)
    done_gov = sum(1 for item in governance_items if item.status == "Done")
    gov_score = (done_gov / total_gov) * 100
    
    return round((technical_score * 0.5) + (gov_score * 0.5), 2)

# --- Database Models ---

class Target(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(index=True)
    name: Optional[str] = None
    type: str = Field(default="generic")
    created_at: datetime = Field(default_factory=datetime.now)
    
    scans: List["ScanHistory"] = Relationship(back_populates="target")

class ScanHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: Optional[int] = Field(default=None, foreign_key="target.id")
    timestamp: datetime = Field(default_factory=datetime.now)
    compliance_score: float
    details: Dict = Field(default={}, sa_type=JSON) # Stores the full TargetScanResult as JSON
    
    target: Optional[Target] = Relationship(back_populates="scans")

class GovernanceChecklist(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    item_id: str = Field(unique=True, index=True)
    category: str # Critical, High, Medium
    description: str
    status: str = Field(default="Not Started") # Not Started, In Progress, Done
    notes: Optional[str] = None
    evidence_link: Optional[str] = None
    last_updated: datetime = Field(default_factory=datetime.now)
