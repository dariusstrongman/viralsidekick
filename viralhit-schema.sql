-- ViralSidekick schema — run ONCE in the dedicated Supabase project (fzlwnsoknngbdkizxpnl)
-- SQL editor → paste → run. The n8n engine degrades gracefully until these exist.

-- 1) scan history + lead list (email captured on every scan)
create table if not exists viralsidekick_scans (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  channel_id text not null,
  channel_name text,
  score int,
  report jsonb,
  created_at timestamptz default now()
);
create index if not exists viralsidekick_scans_email_idx on viralsidekick_scans (email, created_at desc);
create index if not exists viralsidekick_scans_channel_idx on viralsidekick_scans (channel_id, created_at desc);

-- 2) per-email subscriber status (weekly pulse opt-out + future stripe pro flag)
create table if not exists viralsidekick_subscribers (
  email text primary key,
  is_pro boolean default false,
  unsubscribed boolean default false,
  stripe_customer text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- lock both down: service-role only (the n8n engine uses the secret key; no anon/public access)
alter table viralsidekick_scans enable row level security;
alter table viralsidekick_subscribers enable row level security;
