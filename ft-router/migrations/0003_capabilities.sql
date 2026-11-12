-- Hidden sessions, phase 2 (app#9): a device may hand out eight route capabilities, always
-- eight, most of them unused, so the router cannot tell how many hidden sessions a phone has.
-- `devices.capability_hash` stays the first (slot 0) for apps from before.
CREATE TABLE capabilities (
    device_id       TEXT     NOT NULL REFERENCES devices (device_id) ON DELETE CASCADE,
    slot            SMALLINT NOT NULL CHECK (slot BETWEEN 0 AND 7),
    capability_hash BYTEA    NOT NULL,
    PRIMARY KEY (device_id, slot)
);
