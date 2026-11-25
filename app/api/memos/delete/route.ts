import { deleteMemoWithPassword } from "@/lib/memoApi";

export const runtime = "nodejs";

export function POST(request: Request) {
  return deleteMemoWithPassword(request);
}
