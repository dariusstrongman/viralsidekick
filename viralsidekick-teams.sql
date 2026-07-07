-- ============================================================================
-- ViralSidekick TEAMS / WORKSPACES. Run in project fzlwnsoknngbdkizxpnl AFTER the
-- main schema. Idempotent. Editor-safe (helper funcs are single-statement SQL, no
-- internal semicolons). Model: data belongs to a WORKSPACE; users are MEMBERS with
-- a role (owner | admin | viewer). Whole-workspace Pro billing.
--
-- Security: members can READ their workspace's data via RLS. All team WRITES
-- (create workspace, invite, accept, change role, remove) go through the n8n team
-- endpoint with the service key, so RLS here only needs safe read/role policies.
-- ============================================================================

-- helper: workspace ids the current user belongs to (SECURITY DEFINER bypasses
-- RLS on members -> no recursion; single SELECT -> editor-safe)
create or replace function public.vs_my_workspaces() returns setof uuid
  language sql security definer stable set search_path = public as $$
  select workspace_id from public.viralsidekick_members where user_id = auth.uid()
$$;

-- helper: current user's role in a workspace
create or replace function public.vs_role(wid uuid) returns text
  language sql security definer stable set search_path = public as $$
  select role from public.viralsidekick_members where workspace_id = wid and user_id = auth.uid()
$$;

-- WORKSPACES
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
alter table viralsidekick_workspaces enable row level security;
drop policy if exists "member reads workspace" on viralsidekick_workspaces;
create policy "member reads workspace" on viralsidekick_workspaces for select
  using (id in (select vs_my_workspaces()));

-- MEMBERS
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
alter table viralsidekick_members enable row level security;
drop policy if exists "read my workspace members" on viralsidekick_members;
create policy "read my workspace members" on viralsidekick_members for select
  using (workspace_id in (select vs_my_workspaces()));

-- INVITES
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
alter table viralsidekick_invites enable row level security;
drop policy if exists "admin reads invites" on viralsidekick_invites;
create policy "admin reads invites" on viralsidekick_invites for select
  using (vs_role(workspace_id) in ('owner','admin'));

-- attach workspace_id to the data tables
alter table viralsidekick_scans add column if not exists workspace_id uuid references viralsidekick_workspaces(id) on delete cascade;
alter table viralsidekick_channels add column if not exists workspace_id uuid references viralsidekick_workspaces(id) on delete cascade;
alter table viralsidekick_recommendations add column if not exists workspace_id uuid;
alter table viralsidekick_radar add column if not exists workspace_id uuid;
alter table viralsidekick_scan_videos add column if not exists workspace_id uuid;
create index if not exists vs_scans_ws_idx on viralsidekick_scans(workspace_id, created_at desc);
create index if not exists vs_channels_ws_idx on viralsidekick_channels(workspace_id);

-- scans: members read the whole team's scans (plus your own legacy personal ones)
drop policy if exists "own scans read" on viralsidekick_scans;
drop policy if exists "workspace scans read" on viralsidekick_scans;
create policy "workspace scans read" on viralsidekick_scans for select
  using (workspace_id in (select vs_my_workspaces()) or auth.uid() = user_id);

-- channels: members read; owner/admin write
drop policy if exists "own channels" on viralsidekick_channels;
drop policy if exists "workspace channels read" on viralsidekick_channels;
create policy "workspace channels read" on viralsidekick_channels for select
  using (workspace_id in (select vs_my_workspaces()) or auth.uid() = user_id);
drop policy if exists "workspace channels write" on viralsidekick_channels;
create policy "workspace channels write" on viralsidekick_channels for all
  using (vs_role(workspace_id) in ('owner','admin'))
  with check (vs_role(workspace_id) in ('owner','admin'));

-- recommendations: members read the team's; owner/admin can tick them off
drop policy if exists "own recs" on viralsidekick_recommendations;
drop policy if exists "workspace recs read" on viralsidekick_recommendations;
create policy "workspace recs read" on viralsidekick_recommendations for select
  using (workspace_id in (select vs_my_workspaces()) or auth.uid() = user_id);
drop policy if exists "workspace recs write" on viralsidekick_recommendations;
create policy "workspace recs write" on viralsidekick_recommendations for update
  using (vs_role(workspace_id) in ('owner','admin'))
  with check (vs_role(workspace_id) in ('owner','admin'));

-- radar + scan_videos: members read
drop policy if exists "own radar" on viralsidekick_radar;
drop policy if exists "workspace radar read" on viralsidekick_radar;
create policy "workspace radar read" on viralsidekick_radar for select
  using (workspace_id in (select vs_my_workspaces()) or auth.uid() = user_id);
drop policy if exists "own videos" on viralsidekick_scan_videos;
drop policy if exists "workspace videos read" on viralsidekick_scan_videos;
create policy "workspace videos read" on viralsidekick_scan_videos for select
  using (workspace_id in (select vs_my_workspaces()) or auth.uid() = user_id);
