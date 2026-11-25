import "server-only";

import { createHmac, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";

export const ADMIN_COOKIE = "mindlet_admin";
export const ADMIN_SESSION_SECONDS = 60 * 60 * 8;

export function getAdminSecret() {
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error(
      "ADMIN_SESSION_SECRET 환경 변수가 없거나 32자 미만입니다. 길고 무작위인 값으로 설정하세요.",
    );
  }
  return secret;
}

export function getAdminPasswordHash() {
  const hash = process.env.ADMIN_PASSWORD_HASH;
  if (!hash || !/^\$2[aby]\$\d{2}\$.{53}$/.test(hash)) {
    throw new Error(
      "ADMIN_PASSWORD_HASH 환경 변수가 없거나 bcrypt 해시 형식이 아닙니다. README의 생성 방법을 확인하세요.",
    );
  }
  return hash;
}

function tokenDigest(token: string) {
  return createHmac("sha256", getAdminSecret()).update(token).digest("hex");
}

export const adminCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict" as const,
  path: "/",
};

/** 새 세션을 DB에 저장하고 쿠키에 넣을 원본 토큰을 반환한다. */
export async function createAdminSession() {
  const token = randomBytes(32).toString("base64url");
  const supabase = getSupabaseAdmin();

  await supabase
    .from("admin_sessions")
    .delete()
    .lt("expires_at", new Date().toISOString());

  const { error } = await supabase.from("admin_sessions").insert({
    token_hash: tokenDigest(token),
    expires_at: new Date(Date.now() + ADMIN_SESSION_SECONDS * 1000).toISOString(),
  });
  if (error) throw error;

  return token;
}

export async function revokeAdminSession(token: string | undefined) {
  if (!token) return;
  const { error } = await getSupabaseAdmin()
    .from("admin_sessions")
    .delete()
    .eq("token_hash", tokenDigest(token));
  if (error) throw error;
}

export async function getAdminToken() {
  return (await cookies()).get(ADMIN_COOKIE)?.value;
}

/** 요청마다 서버 DB에서 세션 존재 여부와 만료시간을 확인한다. */
export async function isAdminRequest() {
  const token = await getAdminToken();
  if (!token || token.length > 128) return false;

  const { data, error } = await getSupabaseAdmin()
    .from("admin_sessions")
    .select("expires_at")
    .eq("token_hash", tokenDigest(token))
    .gt("expires_at", new Date().toISOString())
    .maybeSingle();
  if (error) throw error;

  return Boolean(data);
}
