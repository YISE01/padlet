import "server-only";

import { NextResponse } from "next/server";
import { isAdminRequest } from "@/lib/adminSession";
import { PASTEL_COLORS, CONTENT_MAX, TITLE_MAX } from "@/lib/constants";
import { hashPassword, isFourDigitPassword, verifyPassword } from "@/lib/password";
import { LIMITS, consume, reset, tooManyRequests } from "@/lib/rateLimit";
import {
  getClientIpHash,
  isUuid,
  jsonError,
  readJsonObject,
  rejectCrossOrigin,
} from "@/lib/requestSecurity";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";

const length = (value: string) => Array.from(value).length;

export async function createMemo(request: Request) {
  const blocked = rejectCrossOrigin(request);
  if (blocked) return blocked;

  try {
    const ip = getClientIpHash(request);
    const limit = await consume("memo_create", ip, LIMITS.create);
    if (!limit.allowed) return tooManyRequests(limit.retryAfter);

    const body = await readJsonObject(request);
    if (!body) return jsonError("잘못된 요청입니다.", 400);

    const title = typeof body.title === "string" ? body.title.trim() : "";
    const content = typeof body.content === "string" ? body.content.trim() : "";

    if (!title || !content) {
      return jsonError("제목과 내용을 모두 입력해 주세요.", 400);
    }
    if (length(title) > TITLE_MAX || length(content) > CONTENT_MAX) {
      return jsonError("메모가 허용된 길이를 초과했습니다.", 400);
    }
    if (!isFourDigitPassword(body.password)) {
      return jsonError("삭제 비밀번호는 숫자 4자리여야 합니다.", 400);
    }

    let color: string;
    if (body.color === undefined || body.color === null || body.color === "") {
      color = PASTEL_COLORS[Math.floor(Math.random() * PASTEL_COLORS.length)];
    } else if (
      typeof body.color === "string" &&
      (PASTEL_COLORS as readonly string[]).includes(body.color)
    ) {
      color = body.color;
    } else {
      return jsonError("허용되지 않은 색상입니다.", 400);
    }

    const passwordHash = await hashPassword(body.password);
    const { data, error } = await getSupabaseAdmin().rpc(
      "create_memo_with_credentials",
      {
        p_title: title,
        p_content: content,
        p_color: color,
        p_password_hash: passwordHash,
      },
    );
    if (error) throw error;

    return NextResponse.json({ memo: data }, { status: 201 });
  } catch (error) {
    console.error("createMemo", error);
    return jsonError("메모를 저장하지 못했습니다.", 500);
  }
}

export async function deleteMemoWithPassword(request: Request, routeId?: string) {
  const blocked = rejectCrossOrigin(request);
  if (blocked) return blocked;

  try {
    const body = await readJsonObject(request);
    if (!body) return jsonError("잘못된 요청입니다.", 400);

    const id = routeId ?? body.id;
    if (!isUuid(id) || !isFourDigitPassword(body.password)) {
      return jsonError("메모와 숫자 4자리 비밀번호를 확인해 주세요.", 400);
    }

    const ip = getClientIpHash(request);
    const general = await consume("memo_delete", ip, LIMITS.delete);
    if (!general.allowed) return tooManyRequests(general.retryAfter);

    // 시도를 먼저 기록하고 성공 시 초기화하여 동시 요청으로 인한 우회를 막는다.
    const failKey = `${id}:${ip}`;
    const attempt = await consume("memo_delete_fail", failKey, LIMITS.deleteFail);
    if (!attempt.allowed) return tooManyRequests(attempt.retryAfter);

    const supabase = getSupabaseAdmin();
    const { data: credential, error: readError } = await supabase
      .from("memo_credentials")
      .select("password_hash")
      .eq("memo_id", id)
      .maybeSingle();
    if (readError) throw readError;
    if (!credential) return jsonError("메모를 찾을 수 없습니다.", 404);

    if (!(await verifyPassword(body.password, credential.password_hash))) {
      return jsonError("삭제 비밀번호가 일치하지 않습니다.", 403);
    }

    const { error: deleteError } = await supabase.from("memos").delete().eq("id", id);
    if (deleteError) throw deleteError;

    await reset("memo_delete_fail", failKey).catch(() => undefined);
    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("deleteMemoWithPassword", error);
    return jsonError("메모를 삭제하지 못했습니다.", 500);
  }
}

export async function adminDeleteMemo(request: Request, routeId?: string) {
  const blocked = rejectCrossOrigin(request);
  if (blocked) return blocked;

  try {
    if (!(await isAdminRequest())) return jsonError("관리자 인증이 필요합니다.", 401);

    let id: unknown = routeId;
    if (id === undefined) {
      const body = await readJsonObject(request);
      if (!body) return jsonError("잘못된 요청입니다.", 400);
      id = body.id;
    }
    if (!isUuid(id)) return jsonError("잘못된 요청입니다.", 400);

    const { error } = await getSupabaseAdmin().from("memos").delete().eq("id", id);
    if (error) throw error;
    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("adminDeleteMemo", error);
    return jsonError("메모를 강제 삭제하지 못했습니다.", 500);
  }
}

export async function adminDeleteAll(request: Request) {
  const blocked = rejectCrossOrigin(request);
  if (blocked) return blocked;

  try {
    if (!(await isAdminRequest())) return jsonError("관리자 인증이 필요합니다.", 401);

    const { error } = await getSupabaseAdmin()
      .from("memos")
      .delete()
      .not("id", "is", null);
    if (error) throw error;
    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("adminDeleteAll", error);
    return jsonError("전체 메모를 삭제하지 못했습니다.", 500);
  }
}
