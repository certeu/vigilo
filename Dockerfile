# Vigilo
#
# Multi-stage build: installs Python deps + security tools in builder,
# copies venv and tool binaries to runtime.
# Runtime has Claude Code, Playwright, security tools, and the pipeline code.
#
# Build with: make build DIR=/path/to/repo

# ── Stage 1: Builder ─────────────────────────────────────────────
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

RUN apk update && apk add --no-cache \
    build-base git curl wget ca-certificates \
    libpcap-dev linux-headers \
    go nodejs-22 npm \
    python3 py3-pip \
    ruby ruby-dev \
    nmap bash

# Go tools
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
ENV CGO_ENABLED=1
RUN mkdir -p $GOPATH/bin && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.13.0

# WhatWeb (Ruby-based web fingerprinter)
RUN curl -sL https://github.com/urbanadventurer/WhatWeb/archive/refs/tags/v0.6.3.tar.gz | tar xz -C /opt && \
    mv /opt/WhatWeb-0.6.3 /opt/whatweb && \
    chmod +x /opt/whatweb/whatweb && \
    gem install addressable -v 2.8.9 && \
    echo '#!/bin/bash' > /usr/local/bin/whatweb && \
    echo 'cd /opt/whatweb && exec ./whatweb "$@"' >> /usr/local/bin/whatweb && \
    chmod +x /usr/local/bin/whatweb

# Python dependencies into an isolated venv
WORKDIR /app
COPY pyproject.toml .
COPY src/ ./src/
COPY scripts/ ./scripts/
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -e .

# Python-based API testing tool
RUN /app/venv/bin/pip install --no-cache-dir schemathesis==4.13.0

# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM cgr.dev/chainguard/wolfi-base:latest

# Runtime dependencies
USER root
RUN apk update && apk add --no-cache \
    git bash curl ca-certificates \
    libpcap nmap \
    nodejs-22 npm \
    python3 ruby \
    # Chromium and dependencies for Playwright
    chromium \
    nss freetype harfbuzz \
    libx11 libxcomposite libxdamage libxext libxfixes libxrandr \
    mesa-gbm fontconfig

# WhatWeb Ruby dependencies (needed at runtime)
RUN gem install addressable -v 2.8.9

# Claude Code, Codex CLI, and Playwright CLI (skill-based browser automation).
# Both LLM CLIs are baked in; VIGILO_EXECUTOR (in .env) selects one at runtime.
# --allow-scripts is REQUIRED for claude-code: recent npm blocks global install
# scripts by default, so its postinstall (which downloads the native binary)
# won't run otherwise, leaving a stub that fails with "Exec format error".
RUN npm install -g --allow-scripts=@anthropic-ai/claude-code \
    @anthropic-ai/claude-code @openai/codex@0.142.5 @playwright/cli@0.1.1
# The playwright-cli skill must live under EACH CLI's own skill-discovery path,
# else the executor not matching the install path never sees it and falls back
# to raw HTTP. Claude scans /tmp/.claude/skills; Codex scans $CODEX_HOME/skills
# (=/tmp/.codex/skills). SKILL.md is a cross-compatible standard, so the same
# skill dir works for both — copy it into both paths.
RUN mkdir -p /tmp/.claude/skills /tmp/.codex/skills && \
    playwright-cli install --skills && \
    cp -r .claude/skills/playwright-cli /tmp/.claude/skills/ && \
    cp -r .claude/skills/playwright-cli /tmp/.codex/skills/ && \
    rm -rf .claude

# Copy Go binaries from builder
COPY --from=builder /go/bin/subfinder /usr/local/bin/

# Copy WhatWeb from builder
COPY --from=builder /opt/whatweb /opt/whatweb
COPY --from=builder /usr/local/bin/whatweb /usr/local/bin/whatweb

# Copy Python venv from builder (includes schemathesis)
COPY --from=builder /app/venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

WORKDIR /app

# Copy application code
COPY src/ ./src/
COPY prompts/ ./prompts/
COPY scripts/ ./scripts/
COPY configs/ ./configs/
COPY pyproject.toml .

# Install the package in editable mode (sources already present)
RUN /app/venv/bin/pip install --no-cache-dir -e .

# Make CLI tools available on PATH
RUN ln -sf /app/scripts/save_deliverable.py /usr/local/bin/save-deliverable && \
    chmod +x /app/scripts/save_deliverable.py && \
    ln -sf /app/scripts/generate_totp.py /usr/local/bin/generate-totp && \
    chmod +x /app/scripts/generate_totp.py && \
    ln -sf /app/scripts/config_codex.sh /usr/local/bin/config-codex && \
    chmod +x /app/scripts/config_codex.sh

# System-level git config (survives UID changes)
RUN git config --system user.email "agent@localhost" && \
    git config --system user.name "Vigilo Agent" && \
    git config --system --add safe.directory '*'

# Non-root scanner user
RUN addgroup -g 1001 scanner && \
    adduser -u 1001 -G scanner -s /bin/bash -D scanner && \
    mkdir -p /repos && \
    mkdir -p /tmp/.cache /tmp/.config /tmp/.npm /tmp/.codex && \
    chmod 777 /app /tmp/.cache /tmp/.config /tmp/.npm /tmp/.codex && \
    chown -R scanner:scanner /app /repos /tmp/.claude /tmp/.cache /tmp/.config /tmp/.npm /tmp/.codex

# Bake target repository into image (build arg)
ARG REPO_DIR=.
COPY ${REPO_DIR} /repos/target
RUN chown -R scanner:scanner /repos && chmod -R 777 /repos

# Copy entrypoint for optional UID remapping
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Playwright uses system Chromium — no download needed
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV PLAYWRIGHT_MCP_EXECUTABLE_PATH=/usr/bin/chromium-browser
# Belt-and-suspenders: Wolfi Chromium works without this, but ensures no sandbox issues
ENV CHROMIUM_FLAGS="--no-sandbox --disable-setuid-sandbox"
ENV VIGILO_DOCKER=true
ENV HOME=/tmp
ENV CODEX_HOME=/tmp/.codex
ENV XDG_CACHE_HOME=/tmp/.cache
ENV XDG_CONFIG_HOME=/tmp/.config
ENV npm_config_cache=/tmp/.npm

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python3", "-m", "src.temporal.worker"]
