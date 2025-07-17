CREATE TABLE group_memberships
(
    uid      TEXT NOT NULL PRIMARY KEY,
    user_id  TEXT NOT NULL,
    group_id TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (uid) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups (uid) ON DELETE CASCADE,
    UNIQUE (user_id, group_id) -- Prevent duplicate membership
);
