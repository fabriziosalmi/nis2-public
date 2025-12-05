from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class NIS2Article(BaseModel):
    article: str
    description: str

class CheckResult(BaseModel):
    check_id: str
    name: str
    status: str  # PASS, FAIL, WARNING, SKIPPED
    details: str
    severity: Severity
    nis2_article: Optional[str] = None
    remediation: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None

class TargetScanResult(BaseModel):
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
