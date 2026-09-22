#!/usr/bin/env bash
# What start.sh must decide before PostgreSQL starts (Plan §75): restore from Object Storage when
# the data directory is empty, carry on when it is not, and never get in the way when WAL-G is not
# configured. Run: ./entrypoint.test.sh
set -uo pipefail
cd "$(dirname "$0")"

fails=0
check() { # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then
    echo "ok   - $1"
  else
    echo "FAIL - $1: expected [$2], got [$3]"
    fails=$((fails + 1))
  fi
}

run() { # run <pgdata> [env assignments...]: prints what start.sh did, with wal-g and postgres faked
  local data="$1"; shift
  local bin
  bin="$(mktemp -d)"
  cat > "$bin/wal-g" <<'FAKE'
#!/usr/bin/env bash
echo "wal-g $*" >> "$TRACE"
FAKE
  cat > "$bin/docker-entrypoint.sh" <<'FAKE'
#!/usr/bin/env bash
echo "postgres $*" >> "$TRACE"
echo "keys ${AWS_ACCESS_KEY_ID:-}/${AWS_SECRET_ACCESS_KEY:-}/${WALG_LIBSODIUM_KEY:-}" >> "$TRACE"
FAKE
  chmod +x "$bin/wal-g" "$bin/docker-entrypoint.sh"
  TRACE="$(mktemp)"
  export TRACE
  PATH="$bin:$PATH" PGDATA="$data" BACKUP_EVERY=0 env "$@" bash ./start.sh postgres > /dev/null 2>&1
  tr '\n' ';' < "$TRACE"
}

empty="$(mktemp -d)"
check "an empty data directory is restored from the last base backup" \
  "wal-g backup-fetch $empty LATEST;postgres postgres;keys //;" \
  "$(run "$empty" WALG_S3_PREFIX=s3://ft/pg)"
check "a restored directory is told to replay the WAL" \
  "1" "$([ -f "$empty/recovery.signal" ] && echo 1 || echo 0)"

full="$(mktemp -d)"
echo 17 > "$full/PG_VERSION"   # what a real data directory has
check "a directory with data starts as it is" \
  "postgres postgres;keys //;" \
  "$(run "$full" WALG_S3_PREFIX=s3://ft/pg)"

# The Object Storage keys are Swarm secrets, never environment of the stack: they must not sit in
# Dokploy's database (§75, §105).
secrets="$(mktemp -d)"
printf 'access' > "$secrets/ft_s3_access_key"
printf 'shh' > "$secrets/ft_s3_secret_key"
printf 'sodium' > "$secrets/ft_walg_key"
check "the Object Storage keys come from the Swarm secrets" \
  "postgres postgres;keys access/shh/sodium;" \
  "$(run "$full" WALG_S3_PREFIX=s3://ft/pg SECRETS_DIR="$secrets")"

alone="$(mktemp -d)"
check "without WAL-G configured it only starts PostgreSQL" \
  "postgres postgres;keys //;" \
  "$(run "$alone")"

[ "$fails" -eq 0 ] || exit 1
echo "all good"
