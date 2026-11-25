import { NextResponse } from "next/server";
import {
  ADMIN_COOKIE,
  adminCookieOptions,
  getAdminToken,
  revokeAdminSession,
} from "@/lib/adminSession";
import { jsonError, rejectCrossOrigin } from "@/lib/requestSecurity";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const blocked = rejectCrossOrigin(request);
  if (blocked) return blocked;

  try {
    await revokeAdminSession(await getAdminToken());
  } catch (error) {
    console.error("POST /api/admin/logout", error);
    return jsonError("로그아웃하지 못했습니다.", 500);
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set(ADMIN_COOKIE, "", { ...adminCookieOptions, maxAge: 0 });
  return response;
}
