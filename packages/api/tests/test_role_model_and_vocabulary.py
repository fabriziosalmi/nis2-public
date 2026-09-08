# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Tier B of the repository audit: the same family of defects, three more times.

Each is a case where a value or a capability was believed to exist and did not,
or existed and was not constrained.
"""

from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from app.models.incident import (
    CLOSED_STATUSES,
    INCIDENT_SEVERITIES,
    INCIDENT_STATUSES,
    INCIDENT_TYPES,
)
from app.routers.incident_monitor import IncidentCreateRequest, IncidentPatchRequest


def _valid(**overrides) -> dict:
    base = dict(
        title="Ransomware on the file servers",
        incident_type="ransomware",
        severity="high",
        description="Encrypted shares",
    )
    base.update(overrides)
    return base


class TestTheArt23VocabularyIsConstrained:
    """`incident_type`, `severity` and `status` were unconstrained strings.

    Six other enumerations in this codebase carry a regex pattern; the Art. 23
    lifecycle — the one whose status decides whether statutory deadline alerts
    fire — did not. That is the ground the `eradicated` divergence grew on, and
    it left a sharper hole: because `is_open` is membership in a set, any value
    outside it made an incident permanently open, its deadlines reported as
    breached for ever and unclearable through the API.
    """

    def test_a_valid_incident_is_accepted(self):
        assert IncidentCreateRequest(**_valid()).severity == "high"

    @pytest.mark.parametrize(
        "field,bad",
        [
            ("status", "Closed"),        # capital C — the permanent-open typo
            ("status", "nonsense"),
            ("severity", "HIGH"),
            ("severity", "catastrophic"),
            ("incident_type", "Ransomware"),
            ("incident_type", "unknown"),  # what the Red Button used to write
        ],
    )
    def test_a_value_outside_the_vocabulary_is_refused(self, field: str, bad: str):
        with pytest.raises(ValidationError):
            IncidentCreateRequest(**_valid(**{field: bad}))

    def test_the_patch_path_is_constrained_too(self):
        """A create that validates and a patch that does not is no constraint at
        all — the second request would just undo the first."""
        with pytest.raises(ValidationError):
            IncidentPatchRequest(status="Closed")
        assert IncidentPatchRequest(status="eradicated").status == "eradicated"

    def test_eradicated_is_a_settable_status(self):
        """It stopped the clock in the alerting task while being offered by
        neither the API vocabulary nor the UI form."""
        assert "eradicated" in INCIDENT_STATUSES
        assert IncidentCreateRequest(**_valid(status="eradicated")).status == "eradicated"

    def test_every_closing_status_can_actually_be_set(self):
        """A status that stops the clock but cannot be assigned is unreachable
        and silently dead — which is how `eradicated` came to mean two things."""
        assert CLOSED_STATUSES <= set(INCIDENT_STATUSES)

    def test_the_red_button_writes_values_the_wire_accepts(self):
        """It wrote incident_type="unknown", which the vocabulary does not
        contain — so the incident it created could not afterwards be patched
        without changing its type first."""
        from app.routers import acn

        source = inspect.getsource(acn.csirt_emergency_payload)
        for field, allowed in (
            ("incident_type", INCIDENT_TYPES),
            ("severity", INCIDENT_SEVERITIES),
            ("status", INCIDENT_STATUSES),
        ):
            written = source.split(f"{field}=\"")[1].split('"')[0]
            assert written in allowed, f"{field}={written!r} is not in the vocabulary"


class TestTheRoleModelIsThreeTiers:
    """The README advertised owner/admin/auditor/viewer.

    Nothing ever assigned `owner`: registration creates an `admin` membership and
    both the invite and role-change schemas constrain the value to admin, auditor
    or viewer. The one place that referenced it — the deadline-alert recipient
    filter — carried a clause that could never match.
    """

    def test_the_recipient_filter_no_longer_matches_on_a_phantom_role(self):
        from app.tasks import incident_tasks

        source = inspect.getsource(incident_tasks._check_deadlines)
        # The clause itself, not any mention of the word — the comment above it
        # deliberately explains what was removed and why.
        assert 'Membership.role.in_(("admin", "owner"))' not in source
        assert 'Membership.role == "admin"' in source

    def test_the_wire_schemas_agree_on_three_roles(self):
        from app.schemas.organization import InviteMemberRequest, RoleUpdateRequest

        for model in (InviteMemberRequest, RoleUpdateRequest):
            pattern = model.model_fields["role"].metadata[0].pattern
            assert "owner" not in pattern
            for role in ("admin", "auditor", "viewer"):
                assert role in pattern

    def test_the_model_is_documented_where_the_check_lives(self):
        """It was inferable only by reading forty-six call sites."""
        from app import dependencies

        source = inspect.getsource(dependencies)
        assert "The role model, stated once" in source
        assert "compliance operator, not a reviewer" in source


class TestTheWorkerPoolModeIsDerived:
    """NullPool was selected by an environment variable only the compose files set.

    run_scan_task calls asyncio.run per task, minting a fresh event loop; with the
    pooled engine the asyncpg connection carried over from the previous task is
    bound to a closed loop and the next query raises. A worker started any other
    way — systemd, Kubernetes, a plain `celery ... worker` on a VM — reproduced
    that documented failure with no startup warning.
    """

    @pytest.mark.parametrize(
        "argv,expected",
        [
            (["/usr/local/bin/celery", "-A", "app.tasks.celery_app", "worker"], True),
            (["/usr/local/bin/celery", "-A", "app.tasks.celery_app", "beat"], True),
            (["celery", "-A", "x", "worker", "--concurrency=4"], True),
            # python -m celery: Python rewrites argv[0] to the module path, so
            # the basename is "__main__.py" and only the directory identifies it.
            (["/usr/lib/site-packages/celery/__main__.py", "-A", "x", "worker"], True),
            (["/usr/local/bin/gunicorn", "app.main:app", "-w", "4"], False),
            (["/usr/local/bin/uvicorn", "app.main:app", "--reload"], False),
            (["/usr/local/bin/pytest", "tests/"], False),
            # celery, but not a worker: an inspect call must not switch pools.
            (["/usr/local/bin/celery", "-A", "x", "inspect", "ping"], False),
            ([], False),
        ],
    )
    def test_the_process_recognises_itself(self, argv: list, expected: bool, monkeypatch):
        import sys

        from app.database import _running_under_celery

        monkeypatch.setattr(sys, "argv", argv)
        assert _running_under_celery() is expected

    def test_the_environment_variable_still_works_as_an_override(self):
        from app import database

        source = inspect.getsource(database)
        assert 'os.environ.get("CELERY_WORKER") == "1"' in source
        assert "or _running_under_celery()" in source
