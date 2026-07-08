-- ============================================================================
-- ViralSidekick SECURITY hardening. Run AFTER teams sql. Idempotent.
-- 1) users can no longer self-edit plan/billing/channel-binding columns
--    (only the server, via service key, can - the app routes channel changes
--    through the authed endpoint which enforces a 7-day rebind cooldown)
-- 2) personal competitor lists (workspace competitor policies already exist)
-- ============================================================================

alter table viralsidekick_profiles add column if not exists channel_changed_at timestamptz;

-- column-level lockdown: authenticated users keep updating their own row
-- (display name, handles...) but NOT these columns
revoke update (plan, plan_status, stripe_customer,
               primary_channel_id, primary_channel_name, primary_channel_handle,
               primary_channel_avatar, primary_channel_subs, channel_changed_at)
  on viralsidekick_profiles from authenticated;
revoke update (plan, plan_status, stripe_customer,
               primary_channel_id, primary_channel_name, primary_channel_handle,
               primary_channel_avatar, primary_channel_subs, channel_changed_at)
  on viralsidekick_profiles from anon;

-- also stop self-inserting a privileged plan on first login
revoke insert (plan, plan_status, stripe_customer, channel_changed_at)
  on viralsidekick_profiles from authenticated;
revoke insert (plan, plan_status, stripe_customer, channel_changed_at)
  on viralsidekick_profiles from anon;

-- personal competitor list: own rows with no workspace
drop policy if exists "own channels write" on viralsidekick_channels;
create policy "own channels write" on viralsidekick_channels for all
  using (auth.uid() = user_id and workspace_id is null)
  with check (auth.uid() = user_id and workspace_id is null);
