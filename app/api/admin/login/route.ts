import { NextResponse } from "next/server";
import {
  ADMIN_COOKIE,
  ADMIN_SESSION_SECONDS,
  adminCookieOptions,
  createAdminSession,
  getAdminPasswordHash,
  getAdminSecret,
} from "@/lib/adminSession";
import { verifyPassword } from "@/lib/password";
import { LIMITS, consume, reset, tooManyRequests } from "@/lib/rateLimit";
import {
  getClientIpHash,
  jsonError,
  readJsonObject,
  rejectCrossOrigin,
} from "@/lib/requestSecurity";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const blocked = rejectCrossOrigin(request);
  if (blocked) return blocked;

  try {
    const adminHash = getAdminPasswordHash();
    getAdminSecret();

    // 시도를 먼저 기록하고 성공 시 초기화한다(동시 요청 우회 방지).
    const ip = getClientIpHash(request);
    const attempt = await consume("admin_login_fail", ip, LIMITS.adminLogin);
    if (!attempt.allowed) return tooManyRequests(attempt.retryAfter);

    const body = await readJsonObject(request);
    if (!body || typeof body.password !== "string" || body.password.length > 128) {
      return jsonError("잘못된 요청입니다.", 400);
    }

    if (!(await verifyPassword(body.password, adminHash))) {
      return jsonError("관리자 비밀번호가 일치하지 않습니다.", 401);
    }

    await reset("admin_login_fail", ip);
    const token = await createAdminSession();

    const response = NextResponse.json({ ok: true });
    response.cookies.set(ADMIN_COOKIE, token, {
      ...adminCookieOptions,
      maxAge: ADMIN_SESSION_SECONDS,
    });
    return response;
  } catch (error) {
    console.error("POST /api/admin/login", error instanceof Error ? error.message : error);
    return jsonError("관리자 로그인에 실패했습니다.", 500);
  }
}
