import { adminDeleteAll } from "@/lib/memoApi";

export const runtime = "nodejs";

export function DELETE(request: Request) {
  return adminDeleteAll(request);
}

export function POST(request: Request) {
  return adminDeleteAll(request);
}
