FROM python:3.11-slim

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
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Nuclei
RUN curl -sfL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip -o nuclei.zip \
    && unzip nuclei.zip && mv nuclei /usr/local/bin/ && rm nuclei.zip

# Install Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install ffuf
RUN curl -sfL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -o ffuf.tar.gz \
    && tar -xzf ffuf.tar.gz -C /usr/local/bin ffuf && rm ffuf.tar.gz

# Install Kiterunner
RUN curl -sfL https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz -o kr.tar.gz \
    && tar -xzf kr.tar.gz -C /usr/local/bin kr && rm kr.tar.gz

# Set working directory
WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir \
    google-genai \
    langchain \
    langchain-openai \
    langchain-postgres \
    langchain-google-vertexai \
    langchain-google-genai \
    langchain-community \
    streamlit \
    pandas \
    plotly \
    psycopg2-binary \
    redis \
    hvac \
    python-dotenv \
    PyYAML \
    checkov \
    docker \
    ansible \
    passlib \
    semgrep \
    prowler \
    neo4j

# Copy agent structure
COPY . /app/

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Command to keep alive (placeholder)
CMD ["python", "centinela.py"]
