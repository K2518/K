-- JAVDAN / Supabase schema v1
-- Run this file in Supabase Dashboard > SQL Editor > New query.
-- Never place the Supabase service_role/secret key in the browser.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text unique,
  full_name text,
  role text not null default 'user' check (role in ('super_admin','project_manager','user')),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  client_name text,
  created_by uuid not null references auth.users(id),
  project_data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.project_members (
  project_id uuid not null references public.projects(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  access_level text not null default 'user' check (access_level in ('manager','user','viewer')),
  created_at timestamptz not null default now(),
  primary key (project_id, user_id)
);

create table if not exists public.checklist_templates (
  id uuid primary key default gen_random_uuid(),
  template_key text not null,
  version integer not null default 1,
  title text not null,
  content jsonb not null default '[]'::jsonb,
  source_url text,
  source_checked_at timestamptz,
  is_published boolean not null default false,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  unique (template_key, version)
);

create table if not exists public.audit_logs (
  id bigint generated always as identity primary key,
  actor_id uuid references auth.users(id),
  action text not null,
  entity_type text not null,
  entity_id text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists projects_created_by_idx on public.projects(created_by);
create index if not exists project_members_user_idx on public.project_members(user_id);
create index if not exists checklist_templates_published_idx on public.checklist_templates(is_published);

create or replace function public.is_super_admin()
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.user_id = auth.uid() and p.role = 'super_admin' and p.is_active = true
  );
$$;

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
      where pr.id = p_project_id and pr.created_by = auth.uid()
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
      where pr.id = p_project_id and pr.created_by = auth.uid()
    );
$$;

create or replace function public.handle_new_user()
returns trigger
language plpgsql security definer
set search_path = public
as $$
begin
  insert into public.profiles (user_id, email, full_name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'full_name',''))
  on conflict (user_id) do update set email = excluded.email;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_javdan on auth.users;
create trigger on_auth_user_created_javdan
after insert on auth.users
for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.projects enable row level security;
alter table public.project_members enable row level security;
alter table public.checklist_templates enable row level security;
alter table public.audit_logs enable row level security;

drop policy if exists "profiles_read_self_or_admin" on public.profiles;
create policy "profiles_read_self_or_admin" on public.profiles
for select to authenticated
using (user_id = auth.uid() or public.is_super_admin());

drop policy if exists "profiles_admin_manage" on public.profiles;
create policy "profiles_admin_manage" on public.profiles
for all to authenticated
using (public.is_super_admin())
with check (public.is_super_admin());

drop policy if exists "projects_read_accessible" on public.projects;
create policy "projects_read_accessible" on public.projects
for select to authenticated
using (public.can_access_project(id));

drop policy if exists "projects_create_authenticated" on public.projects;
create policy "projects_create_authenticated" on public.projects
for insert to authenticated
with check (created_by = auth.uid() or public.is_super_admin());

drop policy if exists "projects_update_managers" on public.projects;
create policy "projects_update_managers" on public.projects
for update to authenticated
using (public.can_manage_project(id))
with check (public.can_manage_project(id));

drop policy if exists "projects_delete_admin" on public.projects;
create policy "projects_delete_admin" on public.projects
for delete to authenticated
using (public.is_super_admin());

drop policy if exists "members_read_self_admin_manager" on public.project_members;
create policy "members_read_self_admin_manager" on public.project_members
for select to authenticated
using (user_id = auth.uid() or public.is_super_admin() or public.can_manage_project(project_id));

drop policy if exists "members_admin_manage" on public.project_members;
create policy "members_admin_manage" on public.project_members
for all to authenticated
using (public.is_super_admin())
with check (public.is_super_admin());

drop policy if exists "templates_read_authenticated" on public.checklist_templates;
create policy "templates_read_authenticated" on public.checklist_templates
for select to authenticated
using (is_published = true or public.is_super_admin());

drop policy if exists "templates_admin_manage" on public.checklist_templates;
create policy "templates_admin_manage" on public.checklist_templates
for all to authenticated
using (public.is_super_admin())
with check (public.is_super_admin());

drop policy if exists "audit_admin_read" on public.audit_logs;
create policy "audit_admin_read" on public.audit_logs
for select to authenticated
using (public.is_super_admin());

drop policy if exists "audit_insert_authenticated" on public.audit_logs;
create policy "audit_insert_authenticated" on public.audit_logs
for insert to authenticated
with check (actor_id = auth.uid());

-- FIRST SUPER ADMIN:
-- 1) Sign up in Supabase Auth using kamand.salehi13771998@gmail.com.
-- 2) Confirm the email.
-- 3) Run the statement below once in SQL Editor.
-- Do not grant admin based on a browser-side email check.
update public.profiles p
set role = 'super_admin', is_active = true, updated_at = now()
from auth.users u
where p.user_id = u.id
  and lower(u.email) = lower('kamand.salehi13771998@gmail.com');
