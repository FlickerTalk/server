CREATE TABLE devices (
    device_id       TEXT        PRIMARY KEY,   -- ft_ + base58(BLAKE3(signing_key))
    signing_key     BYTEA       NOT NULL,      -- Ed25519, to check its signed requests
    capability_hash BYTEA       NOT NULL,      -- BLAKE3 of the route capability
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- UNLOGGED: never in the WAL, so never in a backup; a crash empties it and senders resend.
-- Encrypted blobs, no sender, no creation time: the UUIDv7 id orders them, expires_at drops them.
CREATE UNLOGGED TABLE mailbox (
    id         UUID        PRIMARY KEY,
    device_id  TEXT        NOT NULL,
    blob       BYTEA       NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX mailbox_by_device ON mailbox (device_id, id);
