from abc import ABC, abstractmethod
from typing import Dict, Any, List
from nis2_checker.models import CheckResult, TargetScanResult

class ScannerPlugin(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__

    @abstractmethod
    async def scan(self, target: Dict[str, Any], context: Dict[str, Any]) -> List[CheckResult]:
        """Perform the scan and return results."""
        pass
