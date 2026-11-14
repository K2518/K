-- JAVDAN SAZEH: approval-based membership hardening
-- Run once in Supabase Dashboard > SQL Editor. Existing Super Admin account remains active.
alter table public.profiles alter column is_active set default false;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (user_id,email,full_name,role,is_active)
  values (new.id,new.email,coalesce(new.raw_user_meta_data->>'full_name',''),'user',false)
  on conflict (user_id) do update set email=excluded.email;
  return new;
end;
$$;

create or replace function public.is_active_user()
returns boolean language sql stable security definer set search_path=public
as $$
  select exists(select 1 from public.profiles p where p.user_id=auth.uid() and p.is_active=true);
$$;

create or replace function public.can_access_project(p_project_id uuid)
returns boolean language sql stable security definer set search_path=public
as $$
  select public.is_super_admin() or (
    public.is_active_user() and (
      exists(select 1 from public.project_members pm where pm.project_id=p_project_id and pm.user_id=auth.uid())
      or exists(select 1 from public.projects pr where pr.id=p_project_id and pr.created_by=auth.uid())
    )
  );
$$;

create or replace function public.can_manage_project(p_project_id uuid)
returns boolean language sql stable security definer set search_path=public
as $$
  select public.is_super_admin() or (
    public.is_active_user() and (
      exists(select 1 from public.project_members pm where pm.project_id=p_project_id and pm.user_id=auth.uid() and pm.access_level='manager')
      or exists(select 1 from public.projects pr where pr.id=p_project_id and pr.created_by=auth.uid())
    )
  );
$$;

drop policy if exists "projects_create_authenticated" on public.projects;
create policy "projects_create_active" on public.projects for insert to authenticated
with check (public.is_active_user() and (created_by=auth.uid() or public.is_super_admin()));

drop policy if exists "templates_read_authenticated" on public.checklist_templates;
create policy "templates_read_active" on public.checklist_templates for select to authenticated
using (public.is_active_user() and (is_published=true or public.is_super_admin()));

drop policy if exists "members_read_self_admin_manager" on public.project_members;
create policy "members_read_active" on public.project_members for select to authenticated
using (public.is_active_user() and (user_id=auth.uid() or public.is_super_admin() or public.can_manage_project(project_id)));

drop policy if exists "audit_insert_authenticated" on public.audit_logs;
create policy "audit_insert_active" on public.audit_logs for insert to authenticated
with check (public.is_active_user() and actor_id=auth.uid());

-- Ensure the existing primary administrator is not accidentally disabled.
update public.profiles p set role='super_admin',is_active=true,updated_at=now()
from auth.users u where p.user_id=u.id and lower(u.email)=lower('kamand.salehi13771998@gmail.com');
