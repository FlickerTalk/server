-- Silent slots (2026-10-01): which of the device's eight capabilities are sessions the user has
-- left, as a bitmask (bit i = slot i). The router sends no push for them. Opaque bits, replaced by
-- every registration; devices from before have none.
ALTER TABLE devices ADD COLUMN silent_slots SMALLINT NOT NULL DEFAULT 0 CHECK (silent_slots BETWEEN 0 AND 255);
