-- Push wake-ups (Plan §8–12): where a device can be woken. The token is encrypted with a master
-- key kept outside the database; the provider is only "fcm" for now.
ALTER TABLE devices ADD COLUMN push_provider TEXT;
ALTER TABLE devices ADD COLUMN push_target BYTEA;
