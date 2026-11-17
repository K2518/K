-- JAVDAN: cloud project visibility is granted only after Super Admin approval.
-- Safe follow-up patch: does NOT archive, delete, or modify project data.
-- Run once in Supabase SQL Editor.

create or replace function public.can_access_project(p_project_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.is_super_admin()
    or exists (
      select 1
      from public.projects pr
      join public.profiles owner_profile on owner_profile.user_id = pr.created_by
      where pr.id = p_project_id
        and pr.is_archived = false
        and pr.is_approved = true
        and pr.created_by = auth.uid()
        and owner_profile.is_active = true
    )
    or exists (
      select 1
      from public.projects pr
      join public.project_members pm on pm.project_id = pr.id
      join public.profiles member_profile on member_profile.user_id = pm.user_id
      where pr.id = p_project_id
        and pr.is_archived = false
        and pr.is_approved = true
        and pm.user_id = auth.uid()
        and member_profile.is_active = true
    );
$$;

create or replace function public.can_manage_project(p_project_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.is_super_admin()
    or exists (
      select 1
      from public.projects pr
      join public.profiles owner_profile on owner_profile.user_id = pr.created_by
      where pr.id = p_project_id
        and pr.is_archived = false
        and pr.is_approved = true
        and pr.created_by = auth.uid()
        and owner_profile.is_active = true
    )
    or exists (
      select 1
      from public.projects pr
      join public.project_members pm on pm.project_id = pr.id
      join public.profiles member_profile on member_profile.user_id = pm.user_id
      where pr.id = p_project_id
        and pr.is_archived = false
        and pr.is_approved = true
        and pm.user_id = auth.uid()
        and pm.access_level = 'manager'
        and member_profile.is_active = true
    );
$$;

-- Existing project read/update RLS policies must use these helper functions.
-- Pending projects may be submitted by active users, but are visible only to Super Admin.
