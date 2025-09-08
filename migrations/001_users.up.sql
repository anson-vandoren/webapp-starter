create table if not exists users (
    user_id         blob primary key not null default (randomblob(16)),              -- UUID in blob/binary form
    username        text unique collate nocase not null,    -- usernames must be unique
    password_hash   text not null,
    is_revoked      boolean not null default false,         -- User exists, but is suspended and cannot be used
    created_at      integer not null default (unixepoch()), -- UNIX timestamp
    updated_at      integer not null default (unixepoch()) -- UNIX timestamp
);

create index idx_usernames on users(username);
