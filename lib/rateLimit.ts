import "server-only";

import { getSupabaseAdmin } from "@/lib/supabaseAdmin";
import { jsonError } from "@/lib/requestSecurity";

export const LIMITS = {
  create: { limit: 20, windowSeconds: 600 },
  delete: { limit: 30, windowSeconds: 600 },
  deleteFail: { limit: 5, windowSeconds: 600 },
  adminLogin: { limit: 5, windowSeconds: 900 },
} as const;

type Rule = { limit: number; windowSeconds: number };

/** 시도를 원자적으로 기록하고 허용 여부를 반환한다. 저장소 오류는 예외로 전파(차단)된다. */
export async function consume(scope: string, subject: string, rule: Rule) {
  const { data, error } = await getSupabaseAdmin().rpc("rate_limit_consume", {
    p_scope: scope,
    p_subject: subject,
    p_limit: rule.limit,
    p_window_seconds: rule.windowSeconds,
  });
  if (error) throw error;

  const row = Array.isArray(data) ? data[0] : data;
  if (!row || typeof row.allowed !== "boolean") {
    throw new Error("rate_limit_consume returned an unexpected result");
  }
  return { allowed: row.allowed as boolean, retryAfter: Number(row.retry_after ?? 1) };
}

export async function reset(scope: string, subject: string) {
  const { error } = await getSupabaseAdmin().rpc("rate_limit_reset", {
    p_scope: scope,
    p_subject: subject,
  });
  if (error) throw error;
}

export function tooManyRequests(retryAfter: number) {
  return jsonError(
    "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.",
    429,
    { "Retry-After": String(Math.max(1, retryAfter)) },
  );
}
