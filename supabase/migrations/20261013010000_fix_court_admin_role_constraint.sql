-- Correct the inline role constraint and avoid a broad FOR ALL court policy.
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles
  add constraint profiles_role_check check (role in ('admin','assistant','court_admin'));

drop policy if exists "global admin manages courts" on public.courts;
drop policy if exists "global admin inserts courts" on public.courts;
drop policy if exists "global admin updates courts" on public.courts;
drop policy if exists "global admin deletes courts" on public.courts;

create policy "global admin inserts courts"
on public.courts for insert to authenticated
with check (
  ((select auth.jwt())->'app_metadata'->>'role' = 'admin')
  and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
);
create policy "global admin updates courts"
on public.courts for update to authenticated
using (
  ((select auth.jwt())->'app_metadata'->>'role' = 'admin')
  and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
)
with check (
  ((select auth.jwt())->'app_metadata'->>'role' = 'admin')
  and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
);
create policy "global admin deletes courts"
on public.courts for delete to authenticated
using (
  ((select auth.jwt())->'app_metadata'->>'role' = 'admin')
  and ((select auth.jwt())->'app_metadata'->>'active' = 'true')
);
