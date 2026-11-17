-- JAVDAN: private projects until Super Admin approval
-- Run once in Supabase Dashboard > SQL Editor.

-- Existing projects stay approved; all projects created after this migration default to private.
alter table public.projects
  add column if not exists is_approved boolean not null default true;
alter table public.projects
  alter column is_approved set default false;

-- Owners can continue working on their own private projects.
-- Project members can access a project only after the Super Admin approves it.
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
      join public.profiles p on p.user_id = pr.created_by
      where pr.id = p_project_id
        and pr.created_by = auth.uid()
        and p.is_active = true
    )
    or exists (
      select 1
      from public.projects pr
      join public.project_members pm on pm.project_id = pr.id
      join public.profiles p on p.user_id = pm.user_id
      where pr.id = p_project_id
        and pr.is_approved = true
        and pm.user_id = auth.uid()
        and p.is_active = true
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
      join public.profiles p on p.user_id = pr.created_by
      where pr.id = p_project_id
        and pr.created_by = auth.uid()
        and p.is_active = true
    )
    or exists (
      select 1
      from public.projects pr
      join public.project_members pm on pm.project_id = pr.id
      join public.profiles p on p.user_id = pm.user_id
      where pr.id = p_project_id
        and pr.is_approved = true
        and pm.user_id = auth.uid()
        and pm.access_level = 'manager'
        and p.is_active = true
    );
$$;

-- A regular active account may create a private project, but cannot self-publish it.
drop policy if exists "projects_create_authenticated" on public.projects;
create policy "projects_create_authenticated" on public.projects
for insert to authenticated
with check (
  (
    created_by = auth.uid()
    and is_approved = false
    and exists (
      select 1 from public.profiles p
      where p.user_id = auth.uid() and p.is_active = true
    )
  )
  or public.is_super_admin()
);

-- Only the Super Admin can approve/unpublish. Other managers may edit content,
-- but cannot change a project's publication status.
drop policy if exists "projects_update_managers" on public.projects;
create policy "projects_update_managers" on public.projects
for update to authenticated
using (public.can_manage_project(id))
with check (
  public.can_manage_project(id)
  and (is_approved = false or public.is_super_admin())
);

-- The existing projects_read_accessible policy continues to use can_access_project().
