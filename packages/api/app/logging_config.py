# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Logging configuration: put the request id on every record.

There was no logging configuration at all, so records went out at whatever the
framework defaulted to and carried nothing tying them to an operation. Production
runs four gunicorn workers writing to one stream and a Celery worker writing
asynchronously to another; relating the records of a single request was possible
only by timestamp and guesswork.

Deliberately small. This does not introduce structured JSON logging — that is a
larger change with its own trade-offs, and the value here is almost entirely in
the correlation identifier rather than in the format. A filter that injects the
contextvar is enough to make `grep <id>` work across every line an operation
produced.
"""

from __future__ import annotations

import logging
import os

from app.middleware.identity import request_id


class RequestIdFilter(logging.Filter):
    """Attach the current request id to every record.

    A filter rather than a formatter so it applies to records emitted by
    libraries too — SQLAlchemy, Celery and uvicorn all log through the standard
    hierarchy and none of them knows about our contextvars.

    Records emitted outside a request — startup, beat tasks, the scanner running
    in a worker — get "-", which is honest: they belong to no request.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id.get() or "-"
        return True


LOG_FORMAT = "%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s"


def configure_logging() -> None:
    """Install the filter and format on the root handler.

    Idempotent: called from the application factory, and safe if the host has
    already configured logging (gunicorn does), because it adds the filter to
    whatever handlers exist rather than replacing them.
    """
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    root = logging.getLogger()

    if not root.handlers:
        logging.basicConfig(level=level, format=LOG_FORMAT)

    filt = RequestIdFilter()
    for handler in root.handlers:
        # A formatter referencing %(request_id)s would raise on any record that
        # never passed through the filter, so the two are installed together.
        if not any(isinstance(f, RequestIdFilter) for f in handler.filters):
            handler.addFilter(filt)
        handler.setFormatter(logging.Formatter(LOG_FORMAT))

    root.setLevel(level)
