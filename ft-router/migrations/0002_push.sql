-- push_target is the push token, encrypted with a master key kept outside the database.
ALTER TABLE devices ADD COLUMN push_provider TEXT;
ALTER TABLE devices ADD COLUMN push_target BYTEA;
