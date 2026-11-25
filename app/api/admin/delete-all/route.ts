import { adminDeleteAll } from "@/lib/memoApi";

export const runtime = "nodejs";

export function POST(request: Request) {
  return adminDeleteAll(request);
}
