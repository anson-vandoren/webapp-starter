create table if not exists user_sessions (
    token_id        blob not null primary key default (randomblob(16)), -- UUID, but opaque to the frontend
    user_id         blob not null,
    messages        blob,
    created_at      integer not null default (unixepoch()),             -- UNIX timestamp
    expires_at      integer not null,                                   -- UNIX timestamp
    last_used_at    integer not null default (unixepoch()),             -- UNIX timestamp

    foreign key(user_id) references users(user_id)
);

create index idx_user_sessions_user_id on user_sessions(user_id);
