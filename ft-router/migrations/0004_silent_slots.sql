-- Bit i set: the user has left the session on slot i, and the router sends no push for it.
ALTER TABLE devices ADD COLUMN silent_slots SMALLINT NOT NULL DEFAULT 0 CHECK (silent_slots BETWEEN 0 AND 255);
