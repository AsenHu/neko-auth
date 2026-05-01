```sql
CREATE TABLE oidc_login_tx (
    csrf_hash BLOB NOT NULL PRIMARY KEY
        CHECK(length(csrf_hash) = 32),

    pkce_verifier TEXT NOT NULL
        CHECK(length(pkce_verifier) BETWEEN 43 AND 128),

    nonce_hash BLOB NOT NULL
        CHECK(length(nonce_hash) = 32),

    created_at INTEGER NOT NULL
);
```

```sql
CREATE TABLE auth_users (
    sub TEXT NOT NULL PRIMARY KEY
        CHECK(length(sub) <= 255),

    claims_json TEXT NOT NULL
        CHECK(json_valid(claims_json)),

    idle_timeout_seconds INTEGER NOT NULL
        DEFAULT 28800
        CHECK(idle_timeout_seconds > 0),

    tor_transition TEXT NOT NULL
        DEFAULT 'deny'
        CHECK(tor_transition IN ('allow', 'deny'))
);
```

```sql
CREATE TABLE sessions (
    session_id BLOB NOT NULL PRIMARY KEY
        CHECK(length(session_id) = 32),

    sub TEXT NOT NULL
        REFERENCES auth_users(sub)
        ON DELETE CASCADE,

    current_rt_hash BLOB NOT NULL
        CHECK(length(current_rt_hash) = 32),

    next_rt_hash BLOB NOT NULL
        CHECK(length(next_rt_hash) = 32),

    CHECK(current_rt_hash <> next_rt_hash),

    context_json TEXT NOT NULL
        CHECK(json_valid(context_json)),

    last_network TEXT NOT NULL
        CHECK(last_network IN ('tor', 'clearnet')),

    last_refresh_at INTEGER NOT NULL
);

CREATE INDEX idx_sessions_sub
ON sessions(sub);
```
