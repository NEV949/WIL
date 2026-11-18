FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_DATA_HOME=/tmp/.local/share \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        python3-pip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN if ! getent group 1000 >/dev/null; then groupadd --gid 1000 sandbox; fi \
    && if ! id -u 1000 >/dev/null 2>&1; then \
        useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home sandbox; \
    fi \
    && id -u 1000 && id -g 1000

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/python -m pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt \
    && rm -rf /root/.cache /tmp/*

RUN mkdir -p /workspace && chown 1000:1000 /workspace

COPY verify/ /opt/verify/
RUN chmod -R a+rX /opt/verify

WORKDIR /workspace
USER 1000:1000

CMD ["/bin/bash"]
