# MINDLET

Next.js + Supabase + Vercel 메모 보드. 섹션·컬럼·카테고리 없이 하나의 보드에 메모 카드를 붙입니다.

## 로컬 실행

1. 프로젝트 폴더를 열고 `node -v`, `npm -v` 확인 (Node.js 22 이상 권장)
2. `npm ci`
3. `.env.example`을 `.env.local`로 복사하고 본인의 Supabase 값 입력
4. 관리자 암호 해시 생성 (평문 암호는 어디에도 저장하지 않음):
   ```bash
   node -e "require('bcryptjs').hash(process.argv[1], 12).then(console.log)" "원하는-관리자-암호"
   ```
   > 출력 해시에 `$`가 있으므로 `.env.local`에서는 `\$`로 이스케이프하거나 Next.js의 dotenv 확장 규칙에 맞게 확인하세요. Vercel에는 그대로 입력합니다.
5. 세션 비밀값 생성 (32자 이상 필수):
   ```bash
   node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
   ```
6. Supabase SQL Editor에서 SQL 실행
   - 신규 빈 DB: `schema.sql`
   - 기존 DB: 먼저 `inspect.sql`로 구조 확인 및 백업 → `migration.sql` (데이터·bcrypt 해시 보존, 하나라도 누락되면 전체 롤백)
7. `npm run dev` → http://localhost:3000

## Vercel 배포

Project Settings → Environment Variables(Production/Preview)에 다섯 개를 등록합니다.
`NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`, `ADMIN_PASSWORD_HASH`, `ADMIN_SESSION_SECRET`.
비밀값에는 `NEXT_PUBLIC_`을 붙이지 마세요. 설정 후 배포하고 작성·삭제·관리자 로그인을 확인합니다.
환경 변수가 누락되면 서버가 변수 이름만 안내하는 오류를 남깁니다.

## 보안 구조

- 브라우저: Publishable key로 공개 컬럼만 조회. 쓰기/비공개 테이블/RPC는 DB 권한으로 차단.
- 서버(`server-only`): Secret key로 작성·삭제·요청 제한·관리자 세션 처리.
- 작성자 암호는 서버에서 bcrypt 해시 후 `memo_credentials`에 원자적 RPC로 저장, 삭제 시 서버에서 비교.
- 요청 제한은 Supabase `rate_limits` 테이블 + 원자적 RPC. bcrypt 실행 전에 확인하며 저장소 오류 시 작업 중단.
  - IP: Vercel은 `x-forwarded-for`를 실제 접속 IP로 덮어쓰며 외부 값을 전달하지 않음 ([Vercel 문서](https://vercel.com/docs/headers/request-headers)). Vercel 외 환경(`VERCEL` 미설정)에서는 헤더를 신뢰하지 않고 단일 버킷으로 처리.
- 관리자 세션: 무작위 토큰 → HMAC(`ADMIN_SESSION_SECRET`) 검증값과 만료시간만 DB 저장, 8시간, HttpOnly/SameSite=Strict/Secure(프로덕션), 로그아웃 시 폐기.
- 모든 상태 변경 API: 요청 URL의 Origin과 `Origin` 헤더를 비교(없거나 다르면 403).
