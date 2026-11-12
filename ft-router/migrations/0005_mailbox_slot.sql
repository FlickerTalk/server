-- A left session is unreachable (2026-10-01): each blob remembers which of the device's eight
-- slots it came through, a number 0–7 and nothing else, so that mail through a silent slot is
-- kept but not handed over until the user opens that session again. Blobs stored before came
-- through the main list as far as the router knows (0), which is never withheld. The table stays
-- UNLOGGED.
ALTER TABLE mailbox ADD COLUMN slot SMALLINT NOT NULL DEFAULT 0 CHECK (slot BETWEEN 0 AND 7);
