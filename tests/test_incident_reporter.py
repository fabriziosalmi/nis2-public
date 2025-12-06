import pytest
import os
import json
from unittest.mock import patch
from nis2_checker.incident_reporter import IncidentReporter

@pytest.fixture
def reporter():
    return IncidentReporter()

def test_prompt_input(reporter):
    with patch('builtins.input', return_value="Test Input"):
        result = reporter._prompt("Question")
        assert result == "Test Input"

def test_prompt_options(reporter):
    with patch('builtins.input', return_value="1"):
        options = ["Option A", "Option B"]
        result = reporter._prompt("Select", options)
        assert result == "Option A"

@patch('builtins.input')
@patch('builtins.print') # Suppress print
def test_full_run_interactive_mock(mock_print, mock_input, reporter, tmp_path):
    # Mock inputs for the wizard sequence
    mock_input.side_effect = [
        "MyEntity", # Name
        "Energy",   # Sector
        "admin@example.com", # Email
        "Ransomware Attack", # Title
        "2", # Type: Malware
        "2", # Severity: Significant
        "1", # Status: Ongoing
        "", # Date (default now)
        "Encrypted servers", # Description
        "100", # Users
        "1", # Cross-border: Yes
        "" # Exit
    ]
    
    # Change CWD to tmp_path so report is saved there
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    
    try:
        reporter.run_interactive()
        
        # Verify file creation
        files = list(tmp_path.glob("incident_report_*.json"))
        assert len(files) == 1
        
        with open(files[0]) as f:
            data = json.load(f)
            assert data['entity']['name'] == "MyEntity"
            assert data['incident']['type'] == "Malware/Ransomware"
            assert data['impact']['cross_border'] == True
            
    finally:
        os.chdir(original_cwd)
