# PostgreSQL with WAL-G for the router (Plan §75, §106). The data sits on the node's disk; WAL-G
# ships the WAL and the base backups, encrypted, to Object Storage, so Swarm can start this on any
# node. Debian based: WAL-G ships no musl build.
FROM postgres:17-bookworm

ARG WALG_VERSION=v3.0.9
ARG WALG_SHA256=444ce216230c254edef803e098a59a1746806da3e0d55671d7b0f0082db14ef4

RUN set -eux; \
    apt-get update; apt-get install -y --no-install-recommends ca-certificates curl; \
    curl -fsSL -o /tmp/wal-g.tar.gz \
      "https://github.com/wal-g/wal-g/releases/download/${WALG_VERSION}/wal-g-pg-24.04-amd64.tar.gz"; \
    echo "${WALG_SHA256}  /tmp/wal-g.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/wal-g.tar.gz -C /tmp; \
    install -m 0755 /tmp/wal-g-pg-24.04-amd64 /usr/local/bin/wal-g; \
    rm -rf /tmp/wal-g*; \
    apt-get purge -y curl; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*; \
    wal-g --version

COPY start.sh /usr/local/bin/start.sh
RUN chmod 0755 /usr/local/bin/start.sh

ENTRYPOINT ["start.sh"]
# Archive the WAL as it is written, and never wait more than a minute for a segment to fill: at
# most the last minute is lost if the node dies. The commands do nothing without WALG_S3_PREFIX.
CMD ["postgres", \
     "-c", "archive_mode=on", \
     "-c", "archive_timeout=60", \
     "-c", "archive_command=test -z \"$WALG_S3_PREFIX\" || wal-g wal-push %p", \
     "-c", "restore_command=wal-g wal-fetch %f %p"]
