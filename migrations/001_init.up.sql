create extension if not exists pgcrypto;

create table users (
    id uuid primary key default gen_random_uuid(),
    username text unique not null,
    password_hash text not null,
    created_at timestamptz not null default now()
);

create table items (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id),
    type text not null,
    metadata jsonb not null default '{}'::jsonb,
    ciphertext bytea not null,
    payload_nonce bytea not null,
    enc_dek bytea not null,
    dek_nonce bytea not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index items_user_id_idx on items(user_id);
create index items_created_at_idx on items(created_at);
