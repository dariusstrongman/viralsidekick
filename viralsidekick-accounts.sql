-- ViralSidekick ACCOUNTS — run in the dedicated project (fzlwnsoknngbdkizxpnl) AFTER the base schema.
-- Adds user accounts, per-user ownership of scans, and profiles. Safe to re-run.

-- 1) link scans to an account (nullable: anonymous try-scans still allowed, user_id = null)
alter table viralsidekick_scans add column if not exists user_id uuid references auth.users(id) on delete cascade;
create index if not exists viralsidekick_scans_user_idx on viralsidekick_scans (user_id, created_at desc);

-- users read ONLY their own scans (the n8n engine writes via the service key, which bypasses RLS)
drop policy if exists "own scans read" on viralsidekick_scans;
create policy "own scans read" on viralsidekick_scans for select using (auth.uid() = user_id);

-- 2) profile per user: their primary channel + plan
create table if not exists viralsidekick_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  primary_channel_id text,
  primary_channel_name text,
  plan text default 'free',
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
alter table viralsidekick_profiles enable row level security;
drop policy if exists "own profile" on viralsidekick_profiles;
create policy "own profile" on viralsidekick_profiles for all
  using (auth.uid() = id) with check (auth.uid() = id);

-- 3) auto-create a profile row the moment someone signs up
create or replace function public.handle_new_user() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  insert into public.viralsidekick_profiles (id, email)
  values (new.id, new.email) on conflict (id) do nothing;
  return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute procedure public.handle_new_user();
