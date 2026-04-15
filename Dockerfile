FROM python:3.12-slim

# ── System dependencies ──────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        wget \
        ca-certificates \
        grep \
    && rm -rf /var/lib/apt/lists/*

# ── (Optional) CodeQL CLI ────────────────────────────────────────────────────
# Download the CodeQL bundle.  Comment this block out if you mount the binary
# via a volume or don't need CodeQL support.
ARG CODEQL_VERSION=2.25.1
RUN wget -q \
    "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz" \
    -O /tmp/codeql.tar.gz \
    && tar -xzf /tmp/codeql.tar.gz -C /opt \
    && rm /tmp/codeql.tar.gz \
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql

# ── Python dependencies ──────────────────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application source ───────────────────────────────────────────────────────
COPY . .

# ── Runtime ─────────────────────────────────────────────────────────────────
# /repo  → mount your target repository here (read-only)
# /output → mount a host directory to persist results
VOLUME ["/repo", "/output"]

ENTRYPOINT ["python", "pipeline.py"]
CMD ["--help"]
