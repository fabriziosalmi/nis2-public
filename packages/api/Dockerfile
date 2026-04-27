# Pinned to the immutable manifest digest of python:3.12.7-slim-bookworm.
# Refresh with: docker pull python:3.12.7-slim-bookworm && \
#               docker inspect --format='{{index .RepoDigests 0}}' python:3.12.7-slim-bookworm
FROM python:3.14.0-slim-bookworm@sha256:d13fa0424035d290decef3d575cea23d1b7d5952cdf429df8f5542c71e961576

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Scanner is a local dependency of the API; install it first.
COPY packages/scanner /app/packages/scanner
RUN pip install /app/packages/scanner

COPY packages/api /app/packages/api
RUN pip install /app/packages/api

# Drop privileges. /app is owned by the api user so volume-mounted source
# in the dev compose remains readable to the container process.
RUN groupadd --system --gid 1001 api && \
    useradd  --system --uid 1001 --gid api --no-create-home --shell /usr/sbin/nologin api && \
    chown -R api:api /app
USER api

WORKDIR /app/packages/api

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
