-- ============================================================================
-- ViralSidekick FULL data model. Run in project fzlwnsoknngbdkizxpnl (SQL editor).
-- Pure tables + RLS. No trigger functions (the app creates the profile row on
-- login), so nothing here can trip the SQL editor. Idempotent, safe to re-run.
--
-- RLS: logged-in users read/write ONLY their own rows. The n8n engine writes with
-- the service key (bypasses RLS). Anonymous scans have user_id = null.
-- Token + email tables have NO browser policy: service key only.
-- ============================================================================

-- 1) PROFILES
create table if not exists viralsidekick_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  display_name text,
  avatar_url text,
  timezone text,
  primary_channel_id text,
  primary_channel_name text,
  plan text default 'free',
  plan_status text default 'active',
  stripe_customer text,
  onboarded boolean default false,
  referral_source text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
alter table viralsidekick_profiles add column if not exists primary_channel_id text;
alter table viralsidekick_profiles add column if not exists primary_channel_name text;
alter table viralsidekick_profiles enable row level security;
drop policy if exists "own profile" on viralsidekick_profiles;
create policy "own profile" on viralsidekick_profiles for all
  using (auth.uid() = id) with check (auth.uid() = id);

-- 2) CHANNELS
create table if not exists viralsidekick_channels (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  platform text default 'youtube',
  channel_id text,
  handle text,
  title text,
  thumbnail_url text,
  subscriber_count bigint,
  is_primary boolean default false,
  is_competitor boolean default false,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  unique (user_id, platform, channel_id)
);
create index if not exists vs_channels_user_idx on viralsidekick_channels(user_id);
alter table viralsidekick_channels enable row level security;
drop policy if exists "own channels" on viralsidekick_channels;
create policy "own channels" on viralsidekick_channels for all
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- 3) SCANS
create table if not exists viralsidekick_scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  channel_id text not null,
  channel_name text,
  platform text default 'youtube',
  email text,
  score int,
  verdict text,
  median_views bigint,
  mean_views bigint,
  cadence_days numeric,
  upload_count int,
  outlier_count int,
  flop_count int,
  radar_live boolean default false,
  report jsonb,
  created_at timestamptz default now()
);
alter table viralsidekick_scans add column if not exists user_id uuid references auth.users(id) on delete cascade;
alter table viralsidekick_scans add column if not exists platform text default 'youtube';
alter table viralsidekick_scans add column if not exists verdict text;
alter table viralsidekick_scans add column if not exists median_views bigint;
alter table viralsidekick_scans add column if not exists mean_views bigint;
alter table viralsidekick_scans add column if not exists cadence_days numeric;
alter table viralsidekick_scans add column if not exists upload_count int;
alter table viralsidekick_scans add column if not exists outlier_count int;
alter table viralsidekick_scans add column if not exists flop_count int;
alter table viralsidekick_scans add column if not exists radar_live boolean default false;
create index if not exists vs_scans_user_idx on viralsidekick_scans(user_id, created_at desc);
create index if not exists vs_scans_channel_idx on viralsidekick_scans(channel_id, created_at desc);
alter table viralsidekick_scans enable row level security;
drop policy if exists "own scans read" on viralsidekick_scans;
create policy "own scans read" on viralsidekick_scans for select using (auth.uid() = user_id);

-- 4) SCAN_VIDEOS
create table if not exists viralsidekick_scan_videos (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid references viralsidekick_scans(id) on delete cascade,
  user_id uuid references auth.users(id) on delete cascade,
  video_id text,
  title text,
  url text,
  published_at timestamptz,
  views bigint,
  ratio numeric,
  is_outlier boolean default false,
  is_deadzone boolean default false,
  created_at timestamptz default now()
);
create index if not exists vs_videos_scan_idx on viralsidekick_scan_videos(scan_id);
create index if not exists vs_videos_user_idx on viralsidekick_scan_videos(user_id, published_at desc);
alter table viralsidekick_scan_videos enable row level security;
drop policy if exists "own videos" on viralsidekick_scan_videos;
create policy "own videos" on viralsidekick_scan_videos for select using (auth.uid() = user_id);

-- 5) RECOMMENDATIONS
create table if not exists viralsidekick_recommendations (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  scan_id uuid references viralsidekick_scans(id) on delete cascade,
  kind text default 'fix',
  severity text,
  area text,
  title text,
  action text,
  status text default 'open',
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
create index if not exists vs_recs_user_idx on viralsidekick_recommendations(user_id, status);
alter table viralsidekick_recommendations enable row level security;
drop policy if exists "own recs" on viralsidekick_recommendations;
create policy "own recs" on viralsidekick_recommendations for all
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- 6) RADAR
create table if not exists viralsidekick_radar (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  scan_id uuid references viralsidekick_scans(id) on delete cascade,
  trend text,
  evidence text,
  your_version text,
  urgency text,
  competitor_channel text,
  is_live boolean default false,
  created_at timestamptz default now()
);
create index if not exists vs_radar_user_idx on viralsidekick_radar(user_id, created_at desc);
alter table viralsidekick_radar enable row level security;
drop policy if exists "own radar" on viralsidekick_radar;
create policy "own radar" on viralsidekick_radar for select using (auth.uid() = user_id);

-- 7) SUBSCRIPTIONS
create table if not exists viralsidekick_subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  stripe_customer text,
  stripe_subscription text,
  status text,
  price_id text,
  current_period_end timestamptz,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  unique (user_id)
);
alter table viralsidekick_subscriptions enable row level security;
drop policy if exists "own sub read" on viralsidekick_subscriptions;
create policy "own sub read" on viralsidekick_subscriptions for select using (auth.uid() = user_id);

-- 8) SOCIAL_CONNECTIONS (OAuth tokens = secrets: service key only, no browser policy)
create table if not exists viralsidekick_social_connections (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  platform text,
  external_channel_id text,
  access_token text,
  refresh_token text,
  scope text,
  expires_at timestamptz,
  connected_at timestamptz default now(),
  unique (user_id, platform)
);
alter table viralsidekick_social_connections enable row level security;

-- 9) EVENTS
create table if not exists viralsidekick_events (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users(id) on delete set null,
  event text,
  meta jsonb,
  created_at timestamptz default now()
);
create index if not exists vs_events_idx on viralsidekick_events(event, created_at desc);
alter table viralsidekick_events enable row level security;
drop policy if exists "own events insert" on viralsidekick_events;
create policy "own events insert" on viralsidekick_events for insert with check (auth.uid() = user_id);

-- 10) SUBSCRIBERS (service key only)
create table if not exists viralsidekick_subscribers (
  email text primary key,
  is_pro boolean default false,
  unsubscribed boolean default false,
  stripe_customer text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
alter table viralsidekick_subscribers enable row level security;
