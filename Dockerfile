FROM python:3.12-slim@sha256:3d5ed973e45820f5ba5e46bd065bd88b3a504ff0724d85980dcd05eab361fcf4

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates git subversion mercurial curl && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 checker && \
    useradd --uid 1000 --gid checker --create-home --shell /bin/sh checker

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt \
 && python -m pip check

COPY --chown=checker:checker *.py purl_to_vcs.json README.md ./
COPY --chown=checker:checker schemas/ schemas/
COPY --chown=checker:checker additional_schemas/ additional_schemas/
COPY --chown=checker:checker odt_templates/ odt_templates/

USER checker

ENTRYPOINT ["python", "-u", "sbom-checker.py"]
