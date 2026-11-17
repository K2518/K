-- JAVDAN: private projects until Super Admin approval
-- Run once in Supabase Dashboard > SQL Editor.

-- Mark all current projects private so none are exposed before your review.
-- Projects created after this migration also default to private.
alter table public.projects
  add column if not exists is_approved boolean not null default false;
alter table public.projects
  alter column is_approved set default false;
update public.projects set is_approved = false;

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
with check (public.can_manage_project(id));

-- Publication status itself is reserved for the Super Admin, even when a project
-- manager can edit the rest of an approved project's data.
create or replace function public.guard_project_approval_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $
begin
  if new.is_approved is distinct from old.is_approved
     and not public.is_super_admin() then
    raise exception 'Only the Super Admin can approve or unpublish projects';
  end if;
  return new;
end;
$;

drop trigger if exists guard_project_approval_change on public.projects;
create trigger guard_project_approval_change
before update of is_approved on public.projects
for each row execute function public.guard_project_approval_change();

-- The existing projects_read_accessible policy continues to use can_access_project().
