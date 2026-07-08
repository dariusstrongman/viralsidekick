-- ============================================================================
-- ViralSidekick TEAMS / WORKSPACES + TEAM BOARD. Run in project fzlwnsoknngbdkizxpnl
-- AFTER the main schema. Idempotent, editor-safe, STRICT dependency order:
--   1) tables  2) helper functions  3) RLS policies  4) data-table columns  5) board
-- (sql function bodies are validated at create time, so tables must exist first)
-- ============================================================================

-- 1) TABLES
create table if not exists viralsidekick_workspaces (
  id uuid primary key default gen_random_uuid(),
  name text,
  owner_id uuid references auth.users(id) on delete cascade,
  plan text default 'free',
  plan_status text default 'active',
  stripe_customer text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table if not exists viralsidekick_members (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid references viralsidekick_workspaces(id) on delete cascade,
  user_id uuid references auth.users(id) on delete cascade,
  email text,
  role text default 'viewer',
  created_at timestamptz default now(),
  unique (workspace_id, user_id)
);
create index if not exists vs_members_user_idx on viralsidekick_members(user_id);
create index if not exists vs_members_ws_idx on viralsidekick_members(workspace_id);

create table if not exists viralsidekick_invites (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid references viralsidekick_workspaces(id) on delete cascade,
  email text,
  role text default 'viewer',
  token text,
  invited_by uuid references auth.users(id) on delete set null,
  status text default 'pending',
  created_at timestamptz default now(),
  expires_at timestamptz
);
create index if not exists vs_invites_token_idx on viralsidekick_invites(token);
create index if not exists vs_invites_email_idx on viralsidekick_invites(email);

-- 2) HELPERS (tables now exist; SECURITY DEFINER avoids RLS recursion on members)
create or replace function public.vs_my_workspaces() returns setof uuid
  language sql security definer stable set search_path = public as $$
  select workspace_id from public.viralsidekick_members where user_id = auth.uid()
$$;

create or replace function public.vs_role(wid uuid) returns text
  language sql security definer stable set search_path = public as $$
  select role from public.viralsidekick_members where workspace_id = wid and user_id = auth.uid()
$$;

-- 3) RLS: members READ their workspace world; team writes go via n8n (service key)
alter table viralsidekick_workspaces enable row level security;
drop policy if exists "member reads workspace" on viralsidekick_workspaces;
create policy "member reads workspace" on viralsidekick_workspaces for select
  using (id in (select vs_my_workspaces()));

alter table viralsidekick_members enable row level security;
drop policy if exists "read my workspace members" on viralsidekick_members;
create policy "read my workspace members" on viralsidekick_members for select
  using (workspace_id in (select vs_my_workspaces()));

alter table viralsidekick_invites enable row level security;
drop policy if exists "admin reads invites" on viralsidekick_invites;
create policy "admin reads invites" on viralsidekick_invites for select
  using (vs_role(workspace_id) in ('owner','admin'));

-- 4) DATA TABLES join the workspace
alter table viralsidekick_scans add column if not exists workspace_id uuid references viralsidekick_workspaces(id) on delete cascade;
alter table viralsidekick_channels add column if not exists workspace_id uuid references viralsidekick_workspaces(id) on delete cascade;
alter table viralsidekick_recommendations add column if not exists workspace_id uuid;
alter table viralsidekick_radar add column if not exists workspace_id uuid;
alter table viralsidekick_scan_videos add column if not exists workspace_id uuid;
create index if not exists vs_scans_ws_idx on viralsidekick_scans(workspace_id, created_at desc);
create index if not exists vs_channels_ws_idx on viralsidekick_channels(workspace_id);

drop policy if exists "own scans read" on viralsidekick_scans;
drop policy if exists "workspace scans read" on viralsidekick_scans;
create policy "workspace scans read" on viralsidekick_scans for select
  using (workspace_id in (select vs_my_workspaces()) or auth.uid() = user_id);

drop policy if exists "own channels" on viralsidekick_channels;
drop policy if exists "workspace channels read" on viralsidekick_channels;
create policy "workspace channels read" on viralsidekick_channels for select
  using (workspace_id in (select vs_my_workspaces()) or auth.uid() = user_id);
drop policy if exists "workspace channels write" on viralsidekick_channels;
create policy "workspace channels write" on viralsidekick_channels for all
  using (vs_role(workspace_id) in ('owner','admin'))
  with check (vs_role(workspace_id) in ('owner','admin'));

drop policy if exists "own recs" on viralsidekick_recommendations;
drop policy if exists "workspace recs read" on viralsidekick_recommendations;
create policy "workspace recs read" on viralsidekick_recommendations for select
  using (workspace_id in (select vs_my_workspaces()) or auth.uid() = user_id);
drop policy if exists "workspace recs write" on viralsidekick_recommendations;
create policy "workspace recs write" on viralsidekick_recommendations for update
  using (vs_role(workspace_id) in ('owner','admin'))
  with check (vs_role(workspace_id) in ('owner','admin'));

drop policy if exists "own radar" on viralsidekick_radar;
drop policy if exists "workspace radar read" on viralsidekick_radar;
create policy "workspace radar read" on viralsidekick_radar for select
  using (workspace_id in (select vs_my_workspaces()) or auth.uid() = user_id);
drop policy if exists "own videos" on viralsidekick_scan_videos;
drop policy if exists "workspace videos read" on viralsidekick_scan_videos;
create policy "workspace videos read" on viralsidekick_scan_videos for select
  using (workspace_id in (select vs_my_workspaces()) or auth.uid() = user_id);

-- 5) TEAM BOARD: ideas, notes, wins, questions — app reads/writes under RLS
create table if not exists viralsidekick_posts (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid references viralsidekick_workspaces(id) on delete cascade,
  user_id uuid references auth.users(id) on delete set null,
  author_email text,
  author_name text,
  kind text default 'idea',
  body text,
  status text default 'open',
  created_at timestamptz default now()
);
create index if not exists vs_posts_ws_idx on viralsidekick_posts(workspace_id, created_at desc);
alter table viralsidekick_posts enable row level security;
drop policy if exists "members read posts" on viralsidekick_posts;
create policy "members read posts" on viralsidekick_posts for select
  using (workspace_id in (select vs_my_workspaces()));
drop policy if exists "members write posts" on viralsidekick_posts;
create policy "members write posts" on viralsidekick_posts for insert
  with check (workspace_id in (select vs_my_workspaces()) and user_id = auth.uid());
drop policy if exists "author or admin updates posts" on viralsidekick_posts;
create policy "author or admin updates posts" on viralsidekick_posts for update
  using (user_id = auth.uid() or vs_role(workspace_id) in ('owner','admin'))
  with check (workspace_id in (select vs_my_workspaces()));
drop policy if exists "author or admin deletes posts" on viralsidekick_posts;
create policy "author or admin deletes posts" on viralsidekick_posts for delete
  using (user_id = auth.uid() or vs_role(workspace_id) in ('owner','admin'));
