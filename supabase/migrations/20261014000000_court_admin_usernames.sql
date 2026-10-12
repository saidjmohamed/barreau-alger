-- Username-based court admin accounts, while keeping passwords managed by Supabase Auth.
alter table public.profiles add column if not exists username text;
create unique index if not exists profiles_username_unique
  on public.profiles (lower(username)) where username is not null;
update public.profiles p
set username = split_part(u.email, '@', 1)
from auth.users u
where p.id = u.id and p.role = 'court_admin' and p.username is null;
