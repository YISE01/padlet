-- MINDLET 신규(빈) DB 초기화 스크립트
-- 사용: Supabase SQL Editor에서 한 번 실행합니다. 샘플 데이터는 넣지 않습니다.
-- 기존 데이터가 있는 DB에는 사용하지 말고 migration.sql을 사용하세요.
-- 주의: anon / authenticated / service_role 은 DB 역할 이름이며 레거시 키 이름이 아닙니다.

begin;

-- 1. 공개 메모 테이블 (암호/해시 없음)
create table public.memos (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 80),
  content text not null check (char_length(content) between 1 and 2000),
  color text not null default '#fef3c7' check (char_length(color) > 0),
  position integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 2. 비공개 작성자 암호 해시 (메모 삭제 시 함께 삭제)
create table public.memo_credentials (
  memo_id uuid primary key references public.memos(id) on delete cascade,
  password_hash text not null
);

-- 3. 서버 전용 테이블
create table public.rate_limits (
  scope text not null,
  subject text not null,
  window_start timestamptz not null,
  hits integer not null default 0,
  primary key (scope, subject, window_start)
);

create table public.admin_sessions (
  token_hash text primary key,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create index memos_created_at_idx on public.memos (created_at desc);
create index memos_position_idx on public.memos (position asc, created_at desc);
create index rate_limits_window_idx on public.rate_limits (window_start);
create index admin_sessions_expires_idx on public.admin_sessions (expires_at);

-- 4. updated_at 트리거
create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger memos_set_updated_at
before update on public.memos
for each row
execute function public.set_updated_at();

-- 5. 서버 전용 RPC (SECURITY INVOKER: service_role 권한으로만 실행됨)
create or replace function public.create_memo_with_credentials(
  p_title text,
  p_content text,
  p_password_hash text,
  p_color text default '#fef3c7'
)
returns public.memos
language plpgsql
set search_path = public
as $$
declare
  inserted_memo public.memos;
begin
  if char_length(p_title) < 1 or char_length(p_title) > 80 then
    raise exception 'Invalid title length';
  end if;

  if char_length(p_content) < 1 or char_length(p_content) > 2000 then
    raise exception 'Invalid content length';
  end if;

  if p_password_hash is null or char_length(p_password_hash) < 50 then
    raise exception 'Invalid password hash';
  end if;

  insert into public.memos (title, content, color, position)
  values (p_title, p_content, coalesce(nullif(p_color, ''), '#fef3c7'), 0)
  returning * into inserted_memo;

  insert into public.memo_credentials (memo_id, password_hash)
  values (inserted_memo.id, p_password_hash);

  return inserted_memo;
end;
$$;

create or replace function public.rate_limit_consume(
  p_scope text,
  p_subject text,
  p_limit integer,
  p_window_seconds integer
)
returns table (allowed boolean, retry_after integer)
language plpgsql
set search_path = public
as $$
declare
  v_window timestamptz;
  v_hits integer;
begin
  if p_limit < 1 or p_window_seconds < 1 then
    raise exception 'Invalid rate limit parameters';
  end if;

  v_window := to_timestamp(
    floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds
  );

  if random() < 0.02 then
    delete from public.rate_limits where window_start < now() - interval '1 day';
  end if;

  insert into public.rate_limits as r (scope, subject, window_start, hits)
  values (p_scope, p_subject, v_window, 1)
  on conflict (scope, subject, window_start)
  do update set hits = r.hits + 1
  returning r.hits into v_hits;

  allowed := v_hits <= p_limit;
  retry_after := greatest(
    1,
    ceil(extract(epoch from (v_window + make_interval(secs => p_window_seconds) - now())))::integer
  );
  return next;
end;
$$;

create or replace function public.rate_limit_reset(p_scope text, p_subject text)
returns void
language sql
set search_path = public
as $$
  delete from public.rate_limits where scope = p_scope and subject = p_subject;
$$;

-- 6. RLS
alter table public.memos enable row level security;
alter table public.memo_credentials enable row level security;
alter table public.rate_limits enable row level security;
alter table public.admin_sessions enable row level security;

create policy "Public memos are readable"
on public.memos
for select
to anon, authenticated
using (true);
-- memo_credentials, rate_limits, admin_sessions: 일반 사용자 정책 없음(기본 거부)

-- 7. GRANT (앱 테이블/함수에만 적용, public 스키마 전체 권한은 변경하지 않음)
revoke all on table public.memos, public.memo_credentials,
  public.rate_limits, public.admin_sessions
from public, anon, authenticated;

grant select (id, title, content, color, position, created_at, updated_at)
on public.memos to anon, authenticated;

grant all on table public.memos, public.memo_credentials,
  public.rate_limits, public.admin_sessions
to service_role;

revoke all on function public.set_updated_at() from public, anon, authenticated;
revoke all on function public.create_memo_with_credentials(text, text, text, text)
  from public, anon, authenticated;
revoke all on function public.rate_limit_consume(text, text, integer, integer)
  from public, anon, authenticated;
revoke all on function public.rate_limit_reset(text, text)
  from public, anon, authenticated;

grant execute on function public.create_memo_with_credentials(text, text, text, text)
  to service_role;
grant execute on function public.rate_limit_consume(text, text, integer, integer)
  to service_role;
grant execute on function public.rate_limit_reset(text, text)
  to service_role;

commit;
