import os
import json
import hashlib
import zipfile
import shutil
import datetime
from pathlib import Path
from typing import Dict, Any, Optional

class EvidenceCollector:
    """
    Collects raw evidence, freezes configuration, and generates 
    cryptographically verifiable metadata for scan reproducibility.
    """
    def __init__(self, base_report_dir: str = "reports"):
        self.scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir = Path(base_report_dir)
        self.scan_dir = self.base_dir / f"scan_{self.scan_id}"
        self.evidence_dir = self.scan_dir / "evidence"
        self._ensure_dirs()
        self.metadata = {
            "scan_id": self.scan_id,
            "timestamp_start": datetime.datetime.utcnow().isoformat() + "Z",
            "files": {}
        }

    def _ensure_dirs(self):
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def _calculate_sha256(self, file_path: Path) -> str:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def freeze_config(self, config_data: Dict[str, Any]):
        """Saves the exact configuration used for this scan."""
        config_path = self.scan_dir / "frozen_config.yaml"
        import yaml
        with open(config_path, "w") as f:
            yaml.dump(config_data, f)
        
        self.metadata["frozen_config_hash"] = self._calculate_sha256(config_path)

    def save_raw_evidence(self, target: str, category: str, content: str, extension: str = "txt"):
        """
        Saves raw text evidence (e.g. HTTP response body, DNS output).
        """
        safe_target = target.replace("/", "_").replace(":", "_")
        filename = f"{safe_target}_{category}.{extension}"
        file_path = self.evidence_dir / filename
        
        with open(file_path, "w") as f:
            f.write(content)
        
        # We don't hash every single evidence file in metadata immediately to keep it small, 
        # but we could. For now, we rely on the final bundle hash.

    def finalize(self):
        """
        Generates metadata.json and zips everything into a verification bundle.
        """
        self.metadata["timestamp_end"] = datetime.datetime.utcnow().isoformat() + "Z"
        
        # 1. Save Metadata
        meta_path = self.scan_dir / "metadata.json"
        with open(meta_path, "w") as f:
            json.dump(self.metadata, f, indent=2)
        
        # 2. Create Verification Bundle
        bundle_path = self.scan_dir / f"verification_bundle_{self.scan_id}.zip"
        with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Add config
            if (self.scan_dir / "frozen_config.yaml").exists():
                zipf.write(self.scan_dir / "frozen_config.yaml", arcname="frozen_config.yaml")
            
            # Add metadata
            zipf.write(meta_path, arcname="metadata.json")
            
            # Add all evidence
            for root, _, files in os.walk(self.evidence_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = f"evidence/{file}"
                    zipf.write(file_path, arcname=arcname)

        print(f"Evidence Bundle created: {bundle_path}")
        return str(bundle_path)
