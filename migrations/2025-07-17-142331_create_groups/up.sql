CREATE TABLE groups
(
    uid        TEXT NOT NULL PRIMARY KEY,
    group_name TEXT NOT NULL,
    created_by TEXT NOT NULL,


    FOREIGN KEY (created_by) REFERENCES users (uid) ON DELETE CASCADE
)