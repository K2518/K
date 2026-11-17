-- JAVDAN security hardening
-- Run once in Supabase SQL Editor. Prevents disabled account owners from reading/updating their projects.
create or replace function public.can_access_project(p_project_id uuid)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select public.is_super_admin()
    or exists (
      select 1 from public.project_members pm
      join public.profiles p on p.user_id = pm.user_id
      where pm.project_id = p_project_id
        and pm.user_id = auth.uid()
        and p.is_active = true
    )
    or exists (
      select 1 from public.projects pr
      join public.profiles p on p.user_id = pr.created_by
      where pr.id = p_project_id
        and pr.created_by = auth.uid()
        and p.is_active = true
    );
$$;

create or replace function public.can_manage_project(p_project_id uuid)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select public.is_super_admin()
    or exists (
      select 1 from public.project_members pm
      join public.profiles p on p.user_id = pm.user_id
      where pm.project_id = p_project_id
        and pm.user_id = auth.uid()
        and pm.access_level = 'manager'
        and p.is_active = true
    )
    or exists (
      select 1 from public.projects pr
      join public.profiles p on p.user_id = pr.created_by
      where pr.id = p_project_id
        and pr.created_by = auth.uid()
        and p.is_active = true
    );
$$;
