-- Barreau Alger: court request workflow
create extension if not exists pgcrypto;

create table if not exists public.courts (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  kind text not null check (kind in ('council','court','annex','specialized')),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null,
  role text not null check (role in ('admin','assistant')),
  court_id uuid references public.courts(id),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  constraint profile_court_role check (
    (role = 'admin' and court_id is null) or
    (role = 'assistant' and court_id is not null)
  )
);

create table if not exists public.court_requests (
  id uuid primary key default gen_random_uuid(),
  court_id uuid not null references public.courts(id),
  case_number text not null,
  lawyer_full_name text not null,
  lawyer_accreditation_date date not null,
  request_type text not null check (request_type in ('advance','postpone')),
  hearing_date date not null,
  note text,
  status text not null default 'new'
    check (status in ('new','in_progress','completed','rejected')),
  status_note text,
  created_by uuid not null references auth.users(id),
  handled_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists court_requests_court_created_idx
  on public.court_requests (court_id, created_at desc);
create index if not exists court_requests_status_idx
  on public.court_requests (status, hearing_date);

create or replace function public.set_updated_at()
returns trigger language plpgsql set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists court_requests_set_updated_at on public.court_requests;
create trigger court_requests_set_updated_at
before update on public.court_requests
for each row execute function public.set_updated_at();

alter table public.courts enable row level security;
alter table public.profiles enable row level security;
alter table public.court_requests enable row level security;

-- Authorization is based on server-managed app_metadata claims, never user_metadata.
create policy "authenticated users can read active courts"
on public.courts for select to authenticated
using (active = true or ((select auth.jwt())->'app_metadata'->>'role' = 'admin' and (select auth.jwt())->'app_metadata'->>'active' = 'true'));

create policy "admins manage courts"
on public.courts for all to authenticated
using (((select auth.jwt())->'app_metadata'->>'role' = 'admin' and (select auth.jwt())->'app_metadata'->>'active' = 'true'))
with check (((select auth.jwt())->'app_metadata'->>'role' = 'admin' and (select auth.jwt())->'app_metadata'->>'active' = 'true'));

create policy "users read own profile and admins read all"
on public.profiles for select to authenticated
using (
  id = (select auth.uid()) or
  ((select auth.jwt())->'app_metadata'->>'role' = 'admin' and (select auth.jwt())->'app_metadata'->>'active' = 'true')
);

create policy "admins read all court requests and assistants read own court"
on public.court_requests for select to authenticated
using (
  ((select auth.jwt())->'app_metadata'->>'role' = 'admin' and (select auth.jwt())->'app_metadata'->>'active' = 'true')
  or (((select auth.jwt())->'app_metadata'->>'role' = 'assistant') and ((select auth.jwt())->'app_metadata'->>'active' = 'true') and court_id::text = ((select auth.jwt())->'app_metadata'->>'court_id'))
);

create policy "assistants create requests for their own court"
on public.court_requests for insert to authenticated
with check (
  ((select auth.jwt())->'app_metadata'->>'role' = 'assistant' and (select auth.jwt())->'app_metadata'->>'active' = 'true')
  and court_id::text = ((select auth.jwt())->'app_metadata'->>'court_id')
  and created_by = (select auth.uid())
);

create policy "admins and same-court assistants update requests"
on public.court_requests for update to authenticated
using (
  ((select auth.jwt())->'app_metadata'->>'role' = 'admin' and (select auth.jwt())->'app_metadata'->>'active' = 'true')
  or (
    ((select auth.jwt())->'app_metadata'->>'role' = 'assistant' and (select auth.jwt())->'app_metadata'->>'active' = 'true')
    and court_id::text = ((select auth.jwt())->'app_metadata'->>'court_id')
  )
)
with check (
  ((select auth.jwt())->'app_metadata'->>'role' = 'admin' and (select auth.jwt())->'app_metadata'->>'active' = 'true')
  or (
    ((select auth.jwt())->'app_metadata'->>'role' = 'assistant' and (select auth.jwt())->'app_metadata'->>'active' = 'true')
    and court_id::text = ((select auth.jwt())->'app_metadata'->>'court_id')
  )
);

create policy "admins delete requests"
on public.court_requests for delete to authenticated
using (((select auth.jwt())->'app_metadata'->>'role' = 'admin' and (select auth.jwt())->'app_metadata'->>'active' = 'true'));

revoke all on public.courts, public.profiles, public.court_requests from anon;
grant select, insert, update, delete on public.courts to authenticated;
grant select on public.profiles to authenticated;
grant select, insert, update, delete on public.court_requests to authenticated;

insert into public.courts (name, kind) values
  ('مجلس قضاء الجزائر', 'council'),
  ('محكمة سيدي امحمد', 'court'),
  ('محكمة الحراش', 'court'),
  ('محكمة حسين داي', 'court'),
  ('محكمة بئر مراد رايس', 'court'),
  ('محكمة باب الوادي', 'court'),
  ('محكمة الدار البيضاء', 'court'),
  ('محكمة الرويبة', 'court'),
  ('ملحقة الحراش', 'annex'),
  ('محكمة شراقة', 'court'),
  ('محكمة الجنايات', 'specialized')
on conflict (name) do nothing;
