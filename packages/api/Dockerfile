# Pinned to the immutable manifest digest of python:3.12.7-slim-bookworm.
# Refresh with: docker pull python:3.12.7-slim-bookworm && \
#               docker inspect --format='{{index .RepoDigests 0}}' python:3.12.7-slim-bookworm
FROM python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# v2.4.19: WeasyPrint (PDF report generation) needs the system
# graphics stack — libgobject-2.0, libpango, libpangoft2, libharfbuzz,
# libcairo, libffi. Without these the worker raises
#   OSError: cannot load library 'libgobject-2.0-0'
# at the `from weasyprint import HTML` line, the report task catches
# the ImportError and falls back to writing HTML content with a
# `.pdf` filename — silently. The user gets a "PDF" that's actually
# raw HTML; their PDF reader chokes. Audit reports-003 / reports-010.
#
# `--no-install-recommends` keeps the layer small (no fontconfig
# cache rebuild, no GUI deps). The runtime libraries here pull in
# everything WeasyPrint touches at import time + render time. Build
# tools (gcc, libpq-dev) stay for asyncpg / Pydantic compilation.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc libpq-dev \
        libglib2.0-0 libpango-1.0-0 libpangoft2-1.0-0 \
        libharfbuzz0b libcairo2 libffi8 \
        fonts-dejavu-core && \
    rm -rf /var/lib/apt/lists/*

# Scanner is a local dependency of the API; install it first.
COPY packages/scanner /app/packages/scanner
RUN pip install /app/packages/scanner

COPY packages/api /app/packages/api
RUN pip install /app/packages/api

# Drop privileges. /app is owned by the api user so volume-mounted source
# in the dev compose remains readable to the container process.
#
# v2.4.19: also pre-create /tmp/nis2-reports with api ownership. The
# dev compose mounts a Docker named volume (`reports-data`) at this
# path so the api and celery-worker containers can share generated
# report files. Docker's "first-mount-from-image" rule copies the
# directory's ownership/mode into an empty named volume — but only
# if the directory exists in the image. Without this mkdir+chown,
# the named volume comes up root-owned and the api-user worker hits
# `PermissionError: [Errno 13]` on the first write.
RUN groupadd --system --gid 1001 api && \
    useradd  --system --uid 1001 --gid api --no-create-home --shell /usr/sbin/nologin api && \
    mkdir -p /tmp/nis2-reports && \
    chown -R api:api /app /tmp/nis2-reports
USER api

WORKDIR /app/packages/api

EXPOSE 8000

# P0-01 audit fix: run Alembic migrations before the server starts.
# The entrypoint falls back gracefully if alembic fails.
ENTRYPOINT ["/app/packages/api/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
