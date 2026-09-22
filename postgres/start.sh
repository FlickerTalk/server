#!/usr/bin/env bash
# PostgreSQL with WAL-G (Plan §75): the data lives on the node's disk and the WAL goes to Object
# Storage, so Swarm can start this service on any node.
#
#   empty data directory → restore the last base backup and replay the WAL
#   data already there   → start as it is and keep archiving
#   no WALG_S3_PREFIX    → plain PostgreSQL, nothing else
#
# Base backups are taken every BACKUP_EVERY seconds (0 disables them) and only the last two are
# kept: the device registry rebuilds itself, so there is no history to keep (§73). The mailbox is
# UNLOGGED and never reaches the WAL or a backup (§19).
set -euo pipefail

: "${PGDATA:=/var/lib/postgresql/data}"
: "${BACKUP_EVERY:=86400}"
: "${SECRETS_DIR:=/run/secrets}"

# The Object Storage keys are Swarm secrets, so they never sit in an environment tab or a database.
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
