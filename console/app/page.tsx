import Link from "next/link";
import { supabase, configured } from "@/lib/supabase";
import type { Exam } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function Home() {
  if (!configured) return <NotConfigured />;

  const { data, error } = await supabase!
    .from("exams")
    .select("id, title, starts_at, ends_at, level, retention_days")
    .order("starts_at", { ascending: false })
    .limit(50);

  return (
    <>
      <h1>시험</h1>
      <p className="sub">RLS 가 소유자와 배정된 감독에게만 보여 준다.</p>

      {error && <div className="notice warn">시험을 읽지 못했다: {error.message}</div>}

      {!error && (!data || data.length === 0) && (
        <div className="empty">보이는 시험이 없다.</div>
      )}

      <div className="feed">
        {(data as Exam[] | null)?.map((e) => (
          <div className="ev" key={e.id}>
            <Link href={`/exams/${e.id}`}>{e.title}</Link>
            <div className="rule">
              {e.level} · {new Date(e.starts_at).toLocaleString("ko-KR")} –{" "}
              {new Date(e.ends_at).toLocaleTimeString("ko-KR")} · 보관 {e.retention_days}일
            </div>
          </div>
        ))}
      </div>
    </>
  );
}

function NotConfigured() {
  return (
    <>
      <h1>OwlWatch 콘솔</h1>
      <p className="sub">아직 Supabase 에 연결되지 않았다.</p>
      <div className="notice warn">
        <p><code>NEXT_PUBLIC_SUPABASE_URL</code> 과 <code>NEXT_PUBLIC_SUPABASE_ANON_KEY</code> 를 설정하라.</p>
        <p style={{ marginBottom: 0 }}>
          개발 중에는 <code>mock-server/</code> 가 같은 하트비트 계약을 구현한다 —
          Supabase 계정 없이 전체 흐름을 볼 수 있다.
        </p>
      </div>
    </>
  );
}
