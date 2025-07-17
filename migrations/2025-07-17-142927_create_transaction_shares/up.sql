CREATE TABLE transaction_shares
(
    uid            TEXT    NOT NULL PRIMARY KEY,
    transaction_id TEXT    NOT NULL,
    user_id        TEXT    NOT NULL,
    paid_cents     INTEGER NOT NULL DEFAULT 0, -- What this user paid
    owed_cents     INTEGER NOT NULL DEFAULT 0, -- What this user owes

    FOREIGN KEY (transaction_id) REFERENCES transactions (uid) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (uid) ON DELETE CASCADE,

    UNIQUE (transaction_id, user_id)           -- Prevent duplicates
);
