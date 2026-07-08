-- ============================================================================
-- ViralSidekick SECURITY hardening v2 — run this INSTEAD of v1 (v1's column
-- REVOKEs were no-ops: a table-level UPDATE grant overrides column revokes).
-- Correct pattern: revoke the whole table privilege, grant back ONLY the safe
-- columns. RLS (own-row) still applies on top. Idempotent.
-- ============================================================================

alter table viralsidekick_profiles add column if not exists channel_changed_at timestamptz;

-- ---- lock the profiles table down to safe columns ----
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

-- personal competitor list: own rows with no workspace
drop policy if exists "own channels write" on viralsidekick_channels;
create policy "own channels write" on viralsidekick_channels for all
  using (auth.uid() = user_id and workspace_id is null)
  with check (auth.uid() = user_id and workspace_id is null);
