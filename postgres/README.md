# PostgreSQL with WAL-G

The database of the router (Plan §75). The data lives on the disk of whichever node runs it, and
WAL-G ships the write-ahead log and the base backups — encrypted before they leave — to Object
Storage, so Docker Swarm can start it anywhere:

- **empty data directory** → restore the last base backup and replay the WAL;
- **data already there** → start as it is and keep archiving;
- **`WALG_S3_PREFIX` unset** → plain PostgreSQL, nothing else. That is how it runs until the bucket
  exists.

Only the last two base backups are kept: the device registry rebuilds itself, so there is no
history worth keeping (§73). The mailbox table is `UNLOGGED`, so it never reaches the WAL or a
backup (§19); if the database is restored, the mailbox comes back empty and the senders resend
what was pending (§84).

## Settings

| Variable | What it does |
| --- | --- |
| `WALG_S3_PREFIX` | `s3://bucket/path`; without it WAL-G stays out of the way |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_ENDPOINT`, `AWS_REGION` | the Object Storage credentials |
| `WALG_LIBSODIUM_KEY` | encrypts every backup and WAL segment before it leaves the server |
| `BACKUP_EVERY` | seconds between base backups (86400 by default; 0 turns them off) |

```sh
./entrypoint.test.sh     # what start.sh decides, with wal-g and postgres faked
docker build -t ft-postgres .
```
