#!/usr/bin/env bash
set -euo pipefail

: "${PGDATA:=/var/lib/postgresql/data}"
: "${BACKUP_EVERY:=86400}" # seconds, 0 disables base backups
: "${SECRETS_DIR:=/run/secrets}"

# Swarm secrets, so the Object Storage keys never sit in an environment tab or a database.
from_secret() { # from_secret <variable> <secret file>
  [ -f "$SECRETS_DIR/$2" ] || return 0
  export "$1"="$(cat "$SECRETS_DIR/$2")"
}
from_secret AWS_ACCESS_KEY_ID ft_s3_access_key
from_secret AWS_SECRET_ACCESS_KEY ft_s3_secret_key
from_secret WALG_LIBSODIUM_KEY ft_walg_key

if [ -n "${WALG_S3_PREFIX:-}" ]; then
  if [ ! -s "$PGDATA/PG_VERSION" ]; then
    echo "postgres: empty data directory, restoring from $WALG_S3_PREFIX"
    mkdir -p "$PGDATA"
    wal-g backup-fetch "$PGDATA" LATEST
    touch "$PGDATA/recovery.signal"
    chmod 700 "$PGDATA" 2>/dev/null || true
  fi

  if [ "$BACKUP_EVERY" -gt 0 ]; then
    (
      while sleep "$BACKUP_EVERY"; do
        wal-g backup-push "$PGDATA" && wal-g delete retain FULL 2 --confirm
      done
    ) &
  fi
fi

exec docker-entrypoint.sh "$@"
