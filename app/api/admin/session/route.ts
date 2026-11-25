import { NextResponse } from "next/server";
import { isAdminRequest } from "@/lib/adminSession";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    return NextResponse.json({ isAdmin: await isAdminRequest() });
  } catch (error) {
    console.error("GET /api/admin/session", error);
    return NextResponse.json({ isAdmin: false });
  }
}
