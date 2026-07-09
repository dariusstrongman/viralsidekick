-- ============================================================================
-- ViralSidekick SECURITY hardening v3 — the definitive version. RUN THIS WHOLE
-- FILE in the Supabase SQL editor (one paste, then Run).
--
-- Why v3: v1's column REVOKEs were no-ops (a table UPDATE grant overrides them).
-- v2 (revoke table / grant back safe cols) is correct BUT only works if it truly
-- runs — a partial paste silently leaves the table wide open. v3 adds a database
-- TRIGGER that forcibly resets protected columns for any non-server caller. A
-- trigger cannot be overridden by grant ordering and cannot half-apply, so this
-- closes the self-upgrade-to-Pro hole for good. Idempotent — safe to re-run.
-- ============================================================================

alter table viralsidekick_profiles add column if not exists channel_changed_at timestamptz;

-- ---------------------------------------------------------------------------
-- 1) THE GUARANTEE: a trigger. Only the server (service_role key) may change
--    plan / billing / channel binding. Everyone else's attempts are reverted
--    to the existing value — the UPDATE still "succeeds" (returns 200) but the
--    protected fields do not move. auth.role() reflects the request's JWT.
-- ---------------------------------------------------------------------------
create or replace function viralsidekick_guard_profile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.role() = 'service_role' then
    return new;  -- server writes (n8n bind_channel, Stripe webhook) pass through
  end if;
  -- anyone else: freeze the server-only columns to their prior values
  new.plan                   := old.plan;
  new.plan_status            := old.plan_status;
  new.stripe_customer        := old.stripe_customer;
  new.primary_channel_id     := old.primary_channel_id;
  new.primary_channel_name   := old.primary_channel_name;
  new.primary_channel_handle := old.primary_channel_handle;
  new.primary_channel_avatar := old.primary_channel_avatar;
  new.primary_channel_subs   := old.primary_channel_subs;
  new.channel_changed_at     := old.channel_changed_at;
  return new;
end $$;

drop trigger if exists viralsidekick_guard on viralsidekick_profiles;
create trigger viralsidekick_guard
  before update on viralsidekick_profiles
  for each row execute function viralsidekick_guard_profile();

-- ---------------------------------------------------------------------------
-- 2) DEFENCE IN DEPTH: column-level grants (v2). Belt + suspenders.
-- ---------------------------------------------------------------------------
revoke update on viralsidekick_profiles from authenticated;
revoke update on viralsidekick_profiles from anon;
revoke insert on viralsidekick_profiles from authenticated;
revoke insert on viralsidekick_profiles from anon;

-- users may create their own row with only these fields
grant insert (id, email, display_name, avatar_url, timezone, referral_source,
              onboarded, tiktok_handle, instagram_handle, updated_at)
  on viralsidekick_profiles to authenticated;

-- and may edit only these (NOT plan / billing / channel binding — server only)
grant update (email, display_name, avatar_url, timezone, referral_source,
              onboarded, tiktok_handle, instagram_handle, updated_at)
  on viralsidekick_profiles to authenticated;

-- ---------------------------------------------------------------------------
-- 3) personal competitor list: own rows with no workspace
-- ---------------------------------------------------------------------------
drop policy if exists "own channels write" on viralsidekick_channels;
create policy "own channels write" on viralsidekick_channels for all
  using (auth.uid() = user_id and workspace_id is null)
  with check (auth.uid() = user_id and workspace_id is null);
