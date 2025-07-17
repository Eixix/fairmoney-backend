CREATE TABLE transactions
(
    uid              TEXT    NOT NULL PRIMARY KEY,
    transaction_name TEXT    NOT NULL,
    amount           INTEGER NOT NULL, -- amount in cents
    group_id         TEXT    NOT NULL,
    created_by       TEXT    NOT NULL,
    created_at       TEXT DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (group_id) REFERENCES groups (uid) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users (uid) ON DELETE SET NULL
);
