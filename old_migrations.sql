-- Enable foreign key constraints
PRAGMA foreign_keys = ON;

-- Create users table with UUID as primary key
CREATE TABLE users
(
    id              TEXT PRIMARY KEY, -- UUID as TEXT
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL
);

-- Create groups table with UUID as primary key
CREATE TABLE groups
(
    id         TEXT PRIMARY KEY, -- UUID as TEXT
    name       TEXT NOT NULL,
    created_by TEXT NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
);

-- Create group_members table
CREATE TABLE group_members
(
    group_id TEXT NOT NULL,
    user_id  TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Create transactions table
CREATE TABLE transactions
(
    id          TEXT PRIMARY KEY, -- UUID
    group_id    TEXT    NOT NULL,
    paid_by     TEXT    NOT NULL,
    amount      INTEGER NOT NULL,
    description TEXT,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
    FOREIGN KEY (paid_by) REFERENCES users (id) ON DELETE SET NULL
);

-- Create transaction_shares table
CREATE TABLE transaction_shares
(
    transaction_id TEXT    NOT NULL,
    user_id        TEXT    NOT NULL,
    amount         INTEGER NOT NULL,
    PRIMARY KEY (transaction_id, user_id),
    FOREIGN KEY (transaction_id) REFERENCES transactions (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
