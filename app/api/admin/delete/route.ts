import { adminDeleteMemo } from "@/lib/memoApi";

export const runtime = "nodejs";

export function POST(request: Request) {
  return adminDeleteMemo(request);
}
