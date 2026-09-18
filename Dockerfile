FROM python:3.11-slim

# Populated automatically by BuildKit (arm64 on this host, amd64 on the prod host).
ARG TARGETARCH=amd64

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    lsb-release \
    nmap \
    postgresql-client \
    git \
    ca-certificates \
    unzip \
    sqlmap \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy (install.sh auto-detects arch)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Nuclei (has a real linux_arm64 asset)
RUN curl -sfL "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_${TARGETARCH}.zip" -o nuclei.zip \
    && unzip -o nuclei.zip nuclei -d /usr/local/bin && rm nuclei.zip

# Install Syft (install.sh auto-detects arch)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Grype (install.sh auto-detects arch)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install ffuf (has a real linux_arm64 asset)
RUN curl -sfL "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_${TARGETARCH}.tar.gz" -o ffuf.tar.gz \
    && tar -xzf ffuf.tar.gz -C /usr/local/bin ffuf && rm ffuf.tar.gz

# Install Kiterunner -- upstream ships an amd64 build only. Skip on other arches rather
# than baking in a binary that can't execute (was silently doing this before).
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        curl -sfL https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz -o kr.tar.gz \
        && tar -xzf kr.tar.gz -C /usr/local/bin kr && rm kr.tar.gz ; \
    else echo "kiterunner: no ${TARGETARCH} release upstream, skipping" ; fi

# Install TruffleHog (install.sh auto-detects arch)
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Set working directory
WORKDIR /app

# Install Python dependencies.
# Two-phase install to stop pip's resolver from backtracking for hours (real incident,
# see CLAUDE.md 2026-08-14): first the pinned base set from requirements.txt, then freeze
# it into a constraints file so the second install can ONLY add the orchestrator-extra
# packages without ever re-resolving semgrep / prowler / medusa-security / cvss again.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip freeze > /tmp/constraints.txt \
    && pip install --no-cache-dir -c /tmp/constraints.txt \
        langchain \
        langchain-postgres \
        langchain-google-vertexai \
        langchain-google-genai \
        streamlit \
        plotly \
        checkov \
        PyYAML \
        passlib \
        hvac

# Create non-root user for CMMI / CIS hardening compliance
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Set environment variables
ENV PYTHONUNBUFFERED=1

CMD ["python", "centinela.py"]
