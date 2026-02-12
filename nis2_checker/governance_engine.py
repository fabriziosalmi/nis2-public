import os
import re
from typing import List, Dict, Any
from nis2_checker.models import GovernanceChecklist

class GovernanceEngine:
    def __init__(self, checklist_path: str = "governance_checklist.md"):
        self.checklist_path = checklist_path

    def parse_checklist(self) -> List[GovernanceChecklist]:
        """Parses the markdown checklist into DB-ready models."""
        if not os.path.exists(self.checklist_path):
             return []
             
        items = []
        with open(self.checklist_path, 'r') as f:
            content = f.read()
            
        # Regex to find tasks like: - [ ] G-01: Risk Management Policy
        pattern = r"- \[([ xX])\] ([G]-[0-9]+):\s*(.*)"
        matches = re.finditer(pattern, content)
        
        for match in matches:
            status_char = match.group(1).lower()
            item_id = match.group(2)
            description = match.group(3)
            
            status = "Done" if status_char == "x" else "Not Started"
            
            items.append(GovernanceChecklist(
                item_id=item_id,
                category="Governance",
                description=description,
                status=status
            ))
            
        return items

    def sync_technical_results(self, technical_results: Any):
        """Optionally update governance items based on technical findings."""
        # TODO: Link G-XX with technical check_id (e.g., G-05 'Encryption' -> ssl_tls)
        pass
