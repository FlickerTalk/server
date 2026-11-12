-- Router database (Plan §8, §19, §34, §100): only what is needed to route, nothing about people.

-- A device registers its public identity key and the hash of its route capability. Nothing else.
CREATE TABLE devices (
    device_id       TEXT        PRIMARY KEY,   -- ft_ + base58(BLAKE3(signing_key))
    signing_key     BYTEA       NOT NULL,      -- Ed25519, to check its signed requests (§7)
    capability_hash BYTEA       NOT NULL,      -- BLAKE3 of the route capability (§34)
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Encrypted mailbox (§19). UNLOGGED: never written to the WAL, so it never reaches the WAL
-- archive or a backup; if Postgres crashes it is emptied and senders resend from their outbox.
-- No sender, no creation time: the id (UUIDv7) orders the blobs and expires_at drops them.
CREATE UNLOGGED TABLE mailbox (
    id         UUID        PRIMARY KEY,
    device_id  TEXT        NOT NULL,
    blob       BYTEA       NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX mailbox_by_device ON mailbox (device_id, id);
