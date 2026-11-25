-- MINDLET 기존 DB 점검용 (읽기 전용). migration.sql 적용 전에 먼저 실행해 결과를 확인하세요.

-- 1. memos / memo_credentials 컬럼 구조
select table_name, column_name, data_type, is_nullable, column_default
from information_schema.columns
where table_schema = 'public'
  and table_name in ('memos', 'memo_credentials', 'rate_limits', 'admin_sessions')
order by table_name, ordinal_position;

-- 2. 기존 데이터 수 / 해시 현황 (memos.password_hash 컬럼이 있을 때만 3번 실행)
select count(*) as memo_count from public.memos;

-- 3. (레거시) memos.password_hash 가 있는 경우
-- select count(*) filter (where password_hash is null) as missing_hash,
--        count(*) filter (where password_hash !~ '^\$2[aby]\$') as not_bcrypt
-- from public.memos;

-- 4. 현재 RLS 상태, 정책, 권한
select c.relname, c.relrowsecurity as rls_enabled
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relname in ('memos','memo_credentials','rate_limits','admin_sessions');

select tablename, policyname, cmd, roles, qual, with_check
from pg_policies where schemaname = 'public';

select grantee, table_name, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and grantee in ('anon','authenticated','PUBLIC')
  and table_name in ('memos','memo_credentials','rate_limits','admin_sessions');

-- 5. 제약조건
select conrelid::regclass as table_name, conname, pg_get_constraintdef(oid) as definition
from pg_constraint
where connamespace = 'public'::regnamespace
  and conrelid in ('public.memos'::regclass);
