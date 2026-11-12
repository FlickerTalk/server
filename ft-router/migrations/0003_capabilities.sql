-- Always eight per device, most unused, so the router cannot count a phone's hidden sessions.
-- `devices.capability_hash` stays slot 0 for older apps.
CREATE TABLE capabilities (
    device_id       TEXT     NOT NULL REFERENCES devices (device_id) ON DELETE CASCADE,
    slot            SMALLINT NOT NULL CHECK (slot BETWEEN 0 AND 7),
    capability_hash BYTEA    NOT NULL,
    PRIMARY KEY (device_id, slot)
);
