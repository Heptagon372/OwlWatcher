import Link from "next/link";
import SeatMap from "./SeatMap";
import { supabase, configured } from "@/lib/supabase";
import type { Exam } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function ExamPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!configured) return <div className="notice warn">Supabase 에 연결되지 않았다.</div>;

  const { data } = await supabase!
    .from("exams")
    .select("id, title, starts_at, ends_at, level, retention_days")
    .eq("id", id)
    .maybeSingle();

  const exam = data as Exam | null;

  return (
    <>
      <p className="sub" style={{ margin: 0 }}><Link href="/">← 시험 목록</Link></p>
      <h1>{exam?.title ?? "알 수 없는 시험"}</h1>
      <p className="sub">
        {exam
          ? `${exam.level} · ${new Date(exam.starts_at).toLocaleString("ko-KR")} · 보관 ${exam.retention_days}일`
          : "이 시험을 볼 권한이 없거나 존재하지 않는다."}
      </p>
      <SeatMap examId={id} />
    </>
  );
}
