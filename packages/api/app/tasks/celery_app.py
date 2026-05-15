# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
from celery import Celery

from app.config import settings

celery_app = Celery(
    "nis2",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=600,
    task_soft_time_limit=540,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)

celery_app.conf.beat_schedule = {
    "check-scheduled-scans": {
        "task": "app.tasks.scan_tasks.check_scheduled_scans",
        "schedule": 60.0,
    },
    # v2.4.20 audit reports-005: sweep stale report files from
    # /tmp/nis2-reports once a day. The cutoff comes from
    # `settings.report_ttl_days` at task-execution time so a config
    # bump doesn't require restarting beat. 86400s = 24h; we don't
    # use crontab() here to avoid pulling in the timezone dance —
    # any time-of-day is fine for a janitor that's idempotent.
    "cleanup-old-reports": {
        "task": "app.tasks.report_tasks.cleanup_old_reports",
        "schedule": 86400.0,
    },
    # v2.5.1 GDPR Art. 5(1)(e) storage limitation. Prune `revoked_tokens`
    # and `password_reset_tokens` rows whose `expires_at` is already in
    # the past. Hourly cadence is enough — JTI replay-protection is
    # only useful until the token's own `exp` fires, after which
    # decode_token() rejects regardless of the revocation list.
    "cleanup-expired-auth-records": {
        "task": "app.tasks.cleanup_tasks.cleanup_expired_auth_records",
        "schedule": 3600.0,
    },
    # NIS2 Art. 23 deadline monitor. Checks every 15 minutes whether any
    # open incident is approaching or past its early-warning (24h),
    # notification (72h) or final-report (1 month) deadline and dispatches
    # alerts via the org's configured notification channels.  Redis-backed
    # dedup prevents re-alerting on every tick for the same deadline.
    "check-incident-deadlines": {
        "task": "app.tasks.incident_tasks.check_incident_deadlines",
        "schedule": 900.0,  # 15 minutes
    },
}

# v2.4.19 hotfix: explicitly import the task modules so their
# @celery_app.task decorators run and register the tasks against
# this Celery app at worker startup.
#
# Without these imports the worker logs `[tasks]` empty and beat's
# `check-scheduled-scans` job — plus every scan-create / report-
# generate task — gets `KeyError: ... unregistered task` and is
# silently discarded. The visible symptom: a scan submitted from
# the UI sits in `pending` forever because the worker never picks
# it up.
#
# The `noqa` markers below silence flake8/ruff's "imported but
# unused" — these imports exist purely for the side-effect of
# running the @task decorators against celery_app.
# Imports live AT THE BOTTOM of this file (not the top) so that
# scan_tasks / report_tasks can `from app.tasks.celery_app import
# celery_app` without hitting a circular import — celery_app must
# be fully constructed before the task modules try to decorate
# against it.
from app.tasks import scan_tasks  # noqa: E402,F401
from app.tasks import report_tasks  # noqa: E402,F401
from app.tasks import cleanup_tasks  # noqa: E402,F401
from app.tasks import incident_tasks  # noqa: E402,F401
