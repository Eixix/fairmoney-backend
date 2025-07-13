-- Enable foreign key constraints
PRAGMA foreign_keys = ON;

-- Create users table with UUID as primary key
CREATE TABLE users
(
    uid             TEXT NOT NULL PRIMARY KEY, -- UUID as TEXT
    username        TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL
);
