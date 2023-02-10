DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS public_keys;

CREATE TABLE public_keys (
    kid TEXT PRIMARY KEY,
    pubkey BLOB NOT NULL,
    attestation_data BLOB NOT NULL,
    cose_alg INT NOT NULL,
    sign_counter BLOB,
    user_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TRIGGER IF NOT EXISTS set_updated_at_timestamp
AFTER
UPDATE
    ON public_keys BEGIN
UPDATE
    public_keys
SET
    updated_at = CURRENT_TIMESTAMP
WHERE
    kid = NEW.kid;

END;