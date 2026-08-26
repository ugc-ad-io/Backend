# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — build wheels
#
# requirements.txt pins several packages that have no pure-python wheel and must
# be compiled: jq, bcrypt, cryptography, numpy, Pillow. Those need gcc and a set
# of -dev headers. Building them here and copying only the finished wheels into
# the runtime stage keeps the compiler toolchain out of the shipped image.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      gcc \
      libffi-dev \
      libssl-dev \
      autoconf \
      automake \
      libtool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .

# Build every dependency to a wheel up front. If a package ships a manylinux
# wheel pip just downloads it; only the handful above actually compile.
RUN pip wheel --wheel-dir /wheels -r requirements.txt


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — runtime
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# curl is used by the compose healthcheck; libjq/libonig are jq's runtime libs.
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl \
      libjq1 \
      libonig5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /wheels /wheels
COPY requirements.txt .
# --no-index: install strictly from the wheels built above, never reach out to
# PyPI at runtime-image build. Guarantees the two stages agree.
RUN pip install --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

COPY . .

# ── Uploads ──────────────────────────────────────────────────────────────────
# storage.py prefers Cloudinary and falls back to this directory when Cloudinary
# credentials are absent. Container filesystems are ephemeral, so this path is
# mounted as a named volume in compose — without that, every restart would wipe
# profile photos, logos and creator work files.
ENV UPLOAD_DIR=/app/uploads
RUN mkdir -p /app/uploads

# Run unprivileged. Done after COPY so the app files aren't owned by the app user
# (it only needs to read them) — but uploads must be writable.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app/uploads
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:8000/docs -o /dev/null || exit 1

# server.py has no `if __name__ == "__main__"` block, so uvicorn is invoked
# directly against the module-level `app` object (server.py L64: app = FastAPI(...)).
# One worker: the app uses motor (async MongoDB) and asyncio throughout, so it is
# concurrent within a single process. Scale by running more containers rather
# than more workers, so each stays independently restartable and observable.
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
