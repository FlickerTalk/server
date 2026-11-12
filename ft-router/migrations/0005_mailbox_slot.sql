-- Mail through a silent slot is kept but withheld; slot 0 is the main list, never withheld.
ALTER TABLE mailbox ADD COLUMN slot SMALLINT NOT NULL DEFAULT 0 CHECK (slot BETWEEN 0 AND 7);
