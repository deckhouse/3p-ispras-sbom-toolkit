FROM python:3.14.2-slim-trixie

RUN apt-get update && \
    apt-get install -y git subversion mercurial curl bzr dpkg-dev && rm -rf /var/lib/apt/lists/* && rm -f /etc/apt/sources.list.d/*

COPY . /app/

WORKDIR /app

VOLUME ["/app"]

RUN pip install --no-cache-dir -r requirements.txt

CMD ["sh"]