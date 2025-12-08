"""
File watcher for monitoring reports directory and auto-regenerating homepage.
"""
import os
import time
import logging
from threading import Timer
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)


class ReportWatcher(FileSystemEventHandler):
    """Watches for new JSON report files and triggers homepage regeneration."""
    
    def __init__(self, reports_dir, generate_callback, debounce_seconds=2):
        """
        Initialize the watcher.
        
        Args:
            reports_dir: Path to reports directory to monitor
            generate_callback: Function to call when regeneration is needed
            debounce_seconds: Seconds to wait before triggering (debounce multiple events)
        """
        self.reports_dir = reports_dir
        self.generate_callback = generate_callback
        self.debounce_seconds = debounce_seconds
        self._timer = None
        
    def on_created(self, event):
        """Handle file creation events."""
        if event.is_directory:
            return
            
        # Only trigger on JSON report files
        if event.src_path.endswith('.json') and 'nis2_report_' in os.path.basename(event.src_path):
            logger.info(f"New report detected: {os.path.basename(event.src_path)}")
            self._debounced_regenerate()
    
    def _debounced_regenerate(self):
        """Debounce multiple rapid changes to avoid excessive regeneration."""
        # Cancel existing timer if any
        if self._timer:
            self._timer.cancel()
        
        # Schedule new regeneration
        self._timer = Timer(self.debounce_seconds, self._regenerate)
        self._timer.start()
    
    def _regenerate(self):
        """Execute the homepage regeneration."""
        try:
            logger.info("Regenerating homepage...")
            self.generate_callback(self.reports_dir)
            logger.info("Homepage regenerated successfully")
        except Exception as e:
            logger.error(f"Failed to regenerate homepage: {e}")


def start_watcher(reports_dir, generate_callback):
    """
    Start watching the reports directory.
    
    Args:
        reports_dir: Path to reports directory
        generate_callback: Function to call for homepage regeneration
        
    Returns:
        Observer instance (must be stopped when done)
    """
    # Ensure reports directory exists
    os.makedirs(reports_dir, exist_ok=True)
    
    # Create and start observer
    event_handler = ReportWatcher(reports_dir, generate_callback)
    observer = Observer()
    observer.schedule(event_handler, reports_dir, recursive=False)
    observer.start()
    
    logger.info(f"Started watching {reports_dir} for new reports")
    return observer
