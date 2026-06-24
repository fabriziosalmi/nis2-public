# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public

import os
import uuid
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import create_app
from app.dependencies import get_current_org
from app.tasks import report_tasks


class FakeUser:
    pass


class FakeMembership:
    def __init__(self, organization_id):
        self.organization_id = organization_id
        self.role = "admin"


@pytest.fixture
def test_app_and_client():
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    return app, client


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    d = tmp_path / "nis2-reports"
    d.mkdir()
    monkeypatch.setattr(report_tasks, "REPORTS_DIR", str(d))
    return d


class MockAsyncResult:
    def __init__(self, status, result):
        self.status = status
        self.result = result


def test_download_report_success(test_app_and_client, reports_dir):
    app, client = test_app_and_client
    org_id = uuid.uuid4()
    
    # Override auth dependency
    app.dependency_overrides[get_current_org] = lambda: (FakeUser(), FakeMembership(org_id))
    
    # Create org subdirectory and a mock report file
    org_dir = reports_dir / str(org_id)
    org_dir.mkdir()
    report_file = org_dir / "report_123.pdf"
    report_file.write_bytes(b"pdf-content")
    
    task_id = "task-success-id"
    result_payload = {
        "file_path": str(report_file),
        "filename": "report_123.pdf",
        "content_type": "application/pdf",
        "org_id": str(org_id),
    }
    
    with patch("app.tasks.celery_app.celery_app.AsyncResult") as mock_async:
        mock_async.return_value = MockAsyncResult("SUCCESS", result_payload)
        
        resp = client.get(f"/api/v1/reports/download/{task_id}")
        assert resp.status_code == 200
        assert resp.content == b"pdf-content"
        assert resp.headers["content-disposition"] == 'attachment; filename="report_123.pdf"'


def test_download_report_cross_tenant_blocked(test_app_and_client, reports_dir):
    app, client = test_app_and_client
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    
    # Caller is org_a
    app.dependency_overrides[get_current_org] = lambda: (FakeUser(), FakeMembership(org_a))
    
    # Report belongs to org_b
    org_b_dir = reports_dir / str(org_b)
    org_b_dir.mkdir()
    report_file = org_b_dir / "report_123.pdf"
    report_file.write_bytes(b"sensitive-content")
    
    task_id = "task-cross-tenant-id"
    result_payload = {
        "file_path": str(report_file),
        "filename": "report_123.pdf",
        "content_type": "application/pdf",
        "org_id": str(org_b),  # different org!
    }
    
    with patch("app.tasks.celery_app.celery_app.AsyncResult") as mock_async:
        mock_async.return_value = MockAsyncResult("SUCCESS", result_payload)
        
        resp = client.get(f"/api/v1/reports/download/{task_id}")
        assert resp.status_code == 404


def test_download_report_path_traversal_blocked(test_app_and_client, reports_dir, tmp_path):
    app, client = test_app_and_client
    org_id = uuid.uuid4()
    
    app.dependency_overrides[get_current_org] = lambda: (FakeUser(), FakeMembership(org_id))
    
    # Write a file outside REPORTS_DIR
    outside_file = tmp_path / "secret.env"
    outside_file.write_bytes(b"SECRET_KEY=123456")
    
    task_id = "task-traversal-id"
    result_payload = {
        "file_path": str(outside_file),
        "filename": "secret.env",
        "content_type": "text/plain",
        "org_id": str(org_id),
    }
    
    with patch("app.tasks.celery_app.celery_app.AsyncResult") as mock_async:
        mock_async.return_value = MockAsyncResult("SUCCESS", result_payload)
        
        resp = client.get(f"/api/v1/reports/download/{task_id}")
        assert resp.status_code == 404


def test_download_report_symlink_file_blocked(test_app_and_client, reports_dir, tmp_path):
    app, client = test_app_and_client
    org_id = uuid.uuid4()
    
    app.dependency_overrides[get_current_org] = lambda: (FakeUser(), FakeMembership(org_id))
    
    # Create org directory
    org_dir = reports_dir / str(org_id)
    org_dir.mkdir()
    
    # Secret file outside
    outside_file = tmp_path / "secret.env"
    outside_file.write_bytes(b"SECRET_KEY=123456")
    
    # Create a symlink under org_dir pointing to the outside file
    symlink_file = org_dir / "evil.pdf"
    os.symlink(str(outside_file), str(symlink_file))
    
    task_id = "task-symlink-id"
    result_payload = {
        "file_path": str(symlink_file),
        "filename": "evil.pdf",
        "content_type": "application/pdf",
        "org_id": str(org_id),
    }
    
    with patch("app.tasks.celery_app.celery_app.AsyncResult") as mock_async:
        mock_async.return_value = MockAsyncResult("SUCCESS", result_payload)
        
        resp = client.get(f"/api/v1/reports/download/{task_id}")
        assert resp.status_code == 404


def test_download_report_symlink_org_dir_blocked(test_app_and_client, reports_dir, tmp_path):
    app, client = test_app_and_client
    org_id = uuid.uuid4()
    
    app.dependency_overrides[get_current_org] = lambda: (FakeUser(), FakeMembership(org_id))
    
    # Target directory with files
    target_dir = tmp_path / "target_dir"
    target_dir.mkdir()
    target_file = target_dir / "sensitive.txt"
    target_file.write_bytes(b"sensitive-target-content")
    
    # Symlink the org_id folder to target_dir
    org_symlink = reports_dir / str(org_id)
    os.symlink(str(target_dir), str(org_symlink))
    
    task_id = "task-symlink-dir-id"
    result_payload = {
        "file_path": os.path.join(str(org_symlink), "sensitive.txt"),
        "filename": "sensitive.txt",
        "content_type": "text/plain",
        "org_id": str(org_id),
    }
    
    with patch("app.tasks.celery_app.celery_app.AsyncResult") as mock_async:
        mock_async.return_value = MockAsyncResult("SUCCESS", result_payload)
        
        resp = client.get(f"/api/v1/reports/download/{task_id}")
        assert resp.status_code == 404
