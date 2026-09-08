# Pinned to the immutable manifest digest of python:3.14.5-slim-bookworm.
# Refresh with: docker pull python:3.14.5-slim-bookworm && \
#               docker inspect --format='{{index .RepoDigests 0}}' python:3.14.5-slim-bookworm
FROM python:3.14.7-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f

# Traceability from a running container back to its source.
#
# Neither image carried anything identifying the commit it was built from. The
# API could report a package version, so an artefact could be attributed to a
# RELEASE — but not to a commit, and several commits share a version string
# during development. A customer running a container had no way to establish
# whether it came from the tagged commit, a branch, or a working tree with local
# modifications; neither did the maintainer receiving a bug report. For AGPL
# software distributed as images, being unable to identify which source
# corresponds to a given image is also a licence-obligation problem.
#
# Passed by the compose files from the build context; "unknown" when built by
# hand outside them, which is honest rather than misleading.
ARG GIT_COMMIT=unknown
ARG APP_VERSION=unknown
LABEL org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.source="https://github.com/fabriziosalmi/nis2-public" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
ENV GIT_COMMIT=${GIT_COMMIT}

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
# Versions pinned. These packages are the entire rendering stack for the PDF/A
# dossier — Pango, Cairo, HarfBuzz and the DejaVu fonts are what WeasyPrint draws
# with — plus the toolchain asyncpg and Pydantic compile against. Unpinned, two
# builds of the same commit a month apart contained different renderers, so a
# rendering regression introduced by a Debian point release could appear in a
# customer's dossier with no change to this repository and could not be
# reproduced by rebuilding the commit. For a document meant to be archival
# evidence, a floating renderer is the wrong kind of variation.
#
# The trade-off, stated plainly: when Debian publishes a security update the old
# version leaves the archive and this build fails with "Version '...' was not
# found". That is the intended signal, not a defect. To refresh, run
# `docker compose exec api dpkg-query -W -f='${Package}=${Version}\n' <pkg>`
# against a freshly built image and update the list below in one commit.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc=4:12.2.0-3 \
        libpq-dev=15.19-0+deb12u1 \
        libglib2.0-0=2.74.6-2+deb12u9 \
        libpango-1.0-0=1.50.12+ds-1 \
        libpangoft2-1.0-0=1.50.12+ds-1 \
        libharfbuzz0b=6.0.0+dfsg-3 \
        libcairo2=1.16.0-7 \
        libffi8=3.4.4-1 \
        fonts-dejavu-core=2.37-6 && \
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

# Defensive against a Windows (CRLF) checkout: strip any carriage returns and
# ensure the entrypoint stays executable, so the image builds and runs no
# matter the host's git line-ending config. The .gitattributes at the repo
# root is the primary fix; this is belt-and-suspenders. See issue #202.
RUN sed -i 's/\r$//' /app/packages/api/entrypoint.sh && chmod +x /app/packages/api/entrypoint.sh

# P0-01 audit fix: run Alembic migrations before the server starts.
# The entrypoint falls back gracefully if alembic fails.
ENTRYPOINT ["/app/packages/api/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
