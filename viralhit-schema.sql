-- ViralHit v1 schema (run once in Supabase SQL editor, main project iadzcnzgbtuigyodeqas)
-- The analyze workflow degrades gracefully if this table is missing (leads still land in businesses).

create table if not exists viralhit_scans (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  channel_id text not null,
  channel_name text,
  score int,
  report jsonb,
  created_at timestamptz default now()
);
create index if not exists viralhit_scans_email_idx on viralhit_scans (email, created_at desc);
create index if not exists viralhit_scans_channel_idx on viralhit_scans (channel_id, created_at desc);

-- lock it down: service-role only (the n8n workflow uses the service key; no anon access)
alter table viralhit_scans enable row level security;
