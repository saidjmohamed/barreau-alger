-- Barreau Alger: scoped court administrators and stronger global administration.
-- Additive migration: preserves existing assistants and request records.

alter table public.profiles drop constraint if exists profile_court_role;
alter table public.profiles
  add constraint profile_court_role check (
    (role = 'admin' and court_id is null) or
    (role in ('assistant','court_admin') and court_id is not null)
  );

create unique index if not exists profiles_one_court_admin_per_court
  on public.profiles (court_id) where role = 'court_admin';

drop policy if exists "public can read active courts" on public.courts;
create policy "public can read active courts"
on public.courts for select to anon, authenticated
using (
  active = true or
  (((select auth.jwt())->'app_metadata'->>'role' = 'admin')
    and ((select auth.jwt())->'app_metadata'->>'active' = 'true'))
);

drop policy if exists "admins manage courts" on public.courts;
create policy "global admin manages courts"
on public.courts for all to authenticated
using (
  ((select auth.jwt())->'app_metadata'->>'role' = 'admin')
  and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
)
with check (
  ((select auth.jwt())->'app_metadata'->>'role' = 'admin')
  and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
);

drop policy if exists "users read own profile and admins read all" on public.profiles;
create policy "users read own profile and global admin reads all"
on public.profiles for select to authenticated
using (
  id = (select auth.uid()) or
  (
    ((select auth.jwt())->'app_metadata'->>'role' = 'admin')
    and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
  )
);

drop policy if exists "admins read all court requests and assistants read own court" on public.court_requests;
create policy "global admin reads all and court staff read own court"
on public.court_requests for select to authenticated
using (
  (
    ((select auth.jwt())->'app_metadata'->>'role' = 'admin')
    and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
  )
  or (
    ((select auth.jwt())->'app_metadata'->>'role' in ('assistant','court_admin'))
    and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
    and court_id::text = ((select auth.jwt())->'app_metadata'->>'court_id')
  )
);

drop policy if exists "admins and same-court assistants update requests" on public.court_requests;
create policy "global admin and same-court staff update requests"
on public.court_requests for update to authenticated
using (
  (
    ((select auth.jwt())->'app_metadata'->>'role' = 'admin')
    and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
  )
  or (
    ((select auth.jwt())->'app_metadata'->>'role' in ('assistant','court_admin'))
    and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
    and court_id::text = ((select auth.jwt())->'app_metadata'->>'court_id')
  )
)
with check (
  (
    ((select auth.jwt())->'app_metadata'->>'role' = 'admin')
    and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
  )
  or (
    ((select auth.jwt())->'app_metadata'->>'role' in ('assistant','court_admin'))
    and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
    and court_id::text = ((select auth.jwt())->'app_metadata'->>'court_id')
  )
);

-- Keep all table writes authenticated. RLS limits court CRUD to the global admin.
grant select, insert, update, delete on public.courts to authenticated;
