-- rule 1 wakes the phone without ringing, rule 2 sends no push at all.
CREATE TABLE call_rules (
    device_id TEXT     NOT NULL REFERENCES devices (device_id) ON DELETE CASCADE,
    caller    BYTEA    NOT NULL CHECK (octet_length(caller) = 32),
    rule      SMALLINT NOT NULL CHECK (rule IN (1, 2)),
    PRIMARY KEY (device_id, caller)
);
