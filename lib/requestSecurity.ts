import "server-only";

import { createHash } from "node:crypto";
import { NextResponse } from "next/server";

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_RE.test(value);
}

export function jsonError(message: string, status: number, headers?: HeadersInit) {
  return NextResponse.json({ error: message }, { status, headers });
}

export const INTERNAL_ERROR = "요청을 처리하지 못했습니다.";

/**
 * 상태 변경 요청의 Origin이 서버가 인식한 요청 URL의 Origin과 같은지 확인한다.
 * Origin 헤더가 없으면 거부한다. 별도 환경 변수 없이 Preview/Production에서 동작한다.
 */
export function isSameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin || origin === "null") return false;

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

export function rejectCrossOrigin(request: Request) {
  return isSameOrigin(request)
    ? null
    : jsonError("허용되지 않은 요청입니다.", 403);
}

/**
 * Vercel은 x-forwarded-for를 실제 접속 IP로 덮어쓰므로(외부 값 미전달) 신뢰할 수 있다.
 * Vercel 밖에서는 헤더 위조가 가능하므로 IP를 구분하지 않고 하나의 버킷으로 처리한다.
 */
export function getClientIpHash(request: Request) {
  let ip = "unknown";
  if (process.env.VERCEL) {
    const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
    ip = forwarded || request.headers.get("x-real-ip")?.trim() || "unknown";
  }
  return createHash("sha256").update(ip).digest("hex");
}

export async function readJsonObject(
  request: Request,
): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await request.json();
    if (body && typeof body === "object" && !Array.isArray(body)) {
      return body as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}
