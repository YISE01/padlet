import { deleteMemoWithPassword } from "@/lib/memoApi";

export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  return deleteMemoWithPassword(request, (await params).id);
}
