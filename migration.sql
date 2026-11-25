-- MINDLET 기존 DB 변경(마이그레이션) 스크립트 — 데이터 보존형
--
-- 적용 전제조건
--   1. 먼저 inspect.sql 을 실행해 실제 구조를 확인하고, DB 백업(또는 Supabase 백업 시점)을 확보한다.
--   2. public.memos 가 존재하고 id 가 uuid 이다.
--   3. 앱 트래픽이 없는 시간에 실행한다(구버전 앱은 새 구조와 호환되지 않음).
--   4. 레거시 public.memos.password_hash 가 있다면 모든 행에 bcrypt 해시가 있어야 한다.
--      하나라도 누락되면 이 스크립트는 오류로 전체 롤백된다(데이터 변경 없음).
-- 보존 항목: 메모 ID, 제목, 내용, 생성/수정 일시, 기존 bcrypt 해시.
-- 주의: anon / authenticated / service_role 은 DB 역할 이름이며 레거시 키 이름이 아닙니다.
-- 전체가 하나의 트랜잭션이므로 중간에 실패하면 아무것도 적용되지 않는다.

begin;

-- 1. 전제조건 확인
do $$
begin
  if to_regclass('public.memos') is null then
    raise exception 'public.memos 테이블이 없습니다. 신규 DB라면 schema.sql 을 사용하세요.';
  end if;

  if not exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'memos'
      and column_name = 'id' and data_type = 'uuid'
  ) then
    raise exception 'public.memos.id 가 uuid 가 아닙니다. 수동 검토가 필요합니다.';
  end if;

  if not exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'memos' and column_name = 'title'
  ) or not exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'memos' and column_name = 'content'
  ) then
    raise exception 'public.memos 에 title/content 컬럼이 없습니다. 수동 검토가 필요합니다.';
  end if;

  if to_regclass('public.memo_credentials') is not null and (
    select count(*) from information_schema.columns
    where table_schema = 'public' and table_name = 'memo_credentials'
      and column_name in ('memo_id', 'password_hash')
  ) <> 2 then
    raise exception '기존 memo_credentials 구조가 예상과 다릅니다. 수동 검토가 필요합니다.';
  end if;
end $$;

-- 2. 누락된 공개 컬럼 추가
alter table public.memos add column if not exists color text not null default '#fef3c7';
alter table public.memos add column if not exists position integer not null default 0;
alter table public.memos add column if not exists created_at timestamptz not null default now();
alter table public.memos add column if not exists updated_at timestamptz not null default now();
alter table public.memos alter column color set default '#fef3c7';

-- 기존 데이터가 새 길이 제약을 위반해도 마이그레이션이 실패하지 않도록 NOT VALID 로 추가(신규 쓰기만 검사)
do $$
begin
  if not exists (select 1 from pg_constraint where conrelid = 'public.memos'::regclass and conname = 'memos_title_length_chk') then
    alter table public.memos add constraint memos_title_length_chk
      check (char_length(title) between 1 and 80) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conrelid = 'public.memos'::regclass and conname = 'memos_content_length_chk') then
    alter table public.memos add constraint memos_content_length_chk
      check (char_length(content) between 1 and 2000) not valid;
  end if;
end $$;

-- 3. 비공개 암호 테이블
create table if not exists public.memo_credentials (
  memo_id uuid primary key references public.memos(id) on delete cascade,
  password_hash text not null
);

do $$
begin
  if exists (select 1 from public.memo_credentials c where not exists (select 1 from public.memos m where m.id = c.memo_id)) then
    raise exception 'memo_credentials 에 고아 행이 있습니다. 정리 후 다시 실행하세요.';
  end if;

  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.memo_credentials'::regclass and contype = 'f'
      and confrelid = 'public.memos'::regclass and confdeltype = 'c'
  ) then
    alter table public.memo_credentials
      add constraint memo_credentials_memo_id_fkey
      foreign key (memo_id) references public.memos(id) on delete cascade;
  end if;
end $$;

-- 4. 레거시 memos.password_hash 이전 → 검증 → 제거
do $$
declare
  missing_count bigint;
  bad_count bigint;
  memo_count bigint;
  cred_count bigint;
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'memos' and column_name = 'password_hash'
  ) then
    execute 'select count(*) from public.memos where password_hash is null or password_hash = ''''' into missing_count;
    if missing_count > 0 then
      raise exception '암호 해시가 없는 메모가 % 건 있습니다. 처리 방침을 정한 뒤 다시 실행하세요.', missing_count;
    end if;

    execute 'select count(*) from public.memos where password_hash !~ ''^\$2[aby]\$''' into bad_count;
    if bad_count > 0 then
      raise exception 'bcrypt 형식이 아닌 해시가 % 건 있습니다. 수동 검토가 필요합니다.', bad_count;
    end if;

    execute 'insert into public.memo_credentials (memo_id, password_hash)
             select id, password_hash from public.memos
             on conflict (memo_id) do nothing';

    -- 누락/불일치 검증
    execute 'select count(*) from public.memos m
             left join public.memo_credentials c on c.memo_id = m.id
             where c.memo_id is null or c.password_hash is distinct from m.password_hash'
      into missing_count;
    if missing_count > 0 then
      raise exception '해시 이전 검증 실패: 누락/불일치 % 건', missing_count;
    end if;

    select count(*) into memo_count from public.memos;
    select count(*) into cred_count from public.memo_credentials;
    if memo_count <> cred_count then
      raise exception '해시 이전 검증 실패: memos % 건, memo_credentials % 건', memo_count, cred_count;
    end if;

    alter table public.memos drop column password_hash; -- not null/기존 제약도 함께 제거됨
  end if;
end $$;

-- 5. 서버 전용 테이블
create table if not exists public.rate_limits (
  scope text not null,
  subject text not null,
  window_start timestamptz not null,
  hits integer not null default 0,
  primary key (scope, subject, window_start)
);

create table if not exists public.admin_sessions (
  token_hash text primary key,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create index if not exists memos_created_at_idx on public.memos (created_at desc);
create index if not exists memos_position_idx on public.memos (position asc, created_at desc);
create index if not exists rate_limits_window_idx on public.rate_limits (window_start);
create index if not exists admin_sessions_expires_idx on public.admin_sessions (expires_at);

-- 6. 트리거와 서버 전용 RPC
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

drop trigger if exists memos_set_updated_at on public.memos;
create trigger memos_set_updated_at
before update on public.memos
for each row
execute function public.set_updated_at();

-- 기존 SECURITY DEFINER 버전을 SECURITY INVOKER 로 교체(service_role 권한으로만 실행)
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

-- 7. RLS: 앱 테이블 4개의 기존 정책을 모두 제거하고 필요한 읽기 정책만 다시 생성
alter table public.memos enable row level security;
alter table public.memo_credentials enable row level security;
alter table public.rate_limits enable row level security;
alter table public.admin_sessions enable row level security;

do $$
declare
  p record;
begin
  for p in
    select policyname, tablename from pg_policies
    where schemaname = 'public'
      and tablename in ('memos', 'memo_credentials', 'rate_limits', 'admin_sessions')
  loop
    execute format('drop policy %I on public.%I', p.policyname, p.tablename);
  end loop;
end $$;

create policy "Public memos are readable"
on public.memos
for select
to anon, authenticated
using (true);

-- 8. GRANT: 앱 테이블/함수에만 적용(public 스키마 전체 권한은 변경하지 않음)
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

-- 적용 후 확인(선택):
--   select count(*) from public.memos;
--   select count(*) from public.memo_credentials;   -- 위와 같아야 함
--   select column_name from information_schema.columns
--     where table_schema='public' and table_name='memos';  -- password_hash 가 없어야 함
