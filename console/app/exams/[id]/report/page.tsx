import Link from "next/link";
import { supabase, configured } from "@/lib/supabase";
import type { Exam, OwlEvent, Seat } from "@/lib/types";
import { CONTEXT_LABEL, GRADE_MEANING } from "@/lib/labels";

export const dynamic = "force-dynamic";

/**
 * 리포트. 설계서 08장:
 * "P0 확인된 사실 / P1 정황 / P2 참고를 절대 섞지 않고 세 절로 출력."
 *
 * 이 분리는 서식이 아니라 규칙이다. 처분 문서에 P1 을 사실처럼 쓰는 순간
 * 시스템 전체의 신뢰가 무너진다(설계서 02장).
 */
export default async function Report({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!configured) return <div className="notice warn">Supabase 에 연결되지 않았다.</div>;

  const { data: examRow } = await supabase!
    .from("exams").select("*").eq("id", id).maybeSingle();
  const exam = examRow as Exam | null;

  const { data: seatRows } = await supabase!
    .from("sessions").select("*").eq("exam_id", id).order("seat");
  const seats = (seatRows ?? []) as Seat[];

  const ids = seats.map((s) => s.id);
  const { data: eventRows } = ids.length
    ? await supabase!.from("events").select("*").in("session_id", ids).order("ts")
    : { data: [] as OwlEvent[] };
  const events = (eventRows ?? []) as OwlEvent[];

  const seatOf = (sid: string) => seats.find((s) => s.id === sid)?.seat ?? null;
  const byGrade = (g: "P0" | "P1" | "P2") => events.filter((e) => e.grade === g);

  const pollingSeats = seats.filter((s) => s.ledger !== "kernel").length;
  const softKeySeats = seats.filter((s) => s.attestation !== "hw").length;

  return (
    <>
      <p className="sub" style={{ margin: 0 }}><Link href={`/exams/${id}`}>← 좌석 맵</Link></p>
      <h1>{exam?.title ?? "시험"} 리포트</h1>
      <p className="sub">좌석 {seats.length} · 이벤트 {events.length}건</p>

      {(pollingSeats > 0 || softKeySeats > 0) && (
        <div className="notice warn">
          <b>이 리포트의 등급을 읽을 때 알아야 할 것.</b>
          <ul style={{ margin: "6px 0 0", paddingLeft: "1.2em" }}>
            {pollingSeats > 0 && (
              <li>
                좌석 {pollingSeats}곳은 커널 원장을 쓰지 못했다. 그 좌석의 프로세스 실행 근거는
                P0 가 아니라 P1 로 기록됐다 — 짧게 실행된 프로그램을 놓쳤을 수 있다는 뜻이다.
              </li>
            )}
            {softKeySeats > 0 && (
              <li>
                좌석 {softKeySeats}곳은 하드웨어 키가 없어 소프트웨어 키로 서명했다.
                그 서명은 기기를 증명하지 못한다.
              </li>
            )}
          </ul>
        </div>
      )}

      <Section grade="P0" title="확인된 사실" events={byGrade("P0")} seatOf={seatOf} />
      <Section grade="P1" title="정황" events={byGrade("P1")} seatOf={seatOf} />
      <Section grade="P2" title="참고" events={byGrade("P2")} seatOf={seatOf} />

      <div className="notice">
        이 문서는 부정행위를 판정하지 않는다. 확인된 사실(P0)과 정황(P1)은 성질이 다르며,
        처분 문서에 P1 을 사실처럼 인용해서는 안 된다.
      </div>
    </>
  );
}

function Section({
  grade, title, events, seatOf,
}: {
  grade: "P0" | "P1" | "P2";
  title: string;
  events: OwlEvent[];
  seatOf: (id: string) => number | null;
}) {
  return (
    <section className={`section ${grade.toLowerCase()}`}>
      <header>
        <h3>{grade} · {title} ({events.length}건)</h3>
        <div className="why">{GRADE_MEANING[grade]}</div>
      </header>
      {events.length === 0 ? (
        <div className="empty">해당 없음.</div>
      ) : (
        <table>
          <thead>
            <tr><th>좌석</th><th>시각</th><th>내용</th><th>규칙 · 신호</th></tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td>{seatOf(e.session_id) ?? "?"}</td>
                <td>{new Date(e.ts).toLocaleTimeString("ko-KR")}</td>
                <td>
                  {e.summary}
                  {e.contexts.length > 0 && (
                    <div className="rule">
                      맥락 {e.contexts.map((c) => CONTEXT_LABEL[c] ?? c).join(", ")}
                    </div>
                  )}
                  {e.evidence?.notes?.map((n, i) => <div className="note" key={i}>{n}</div>)}
                </td>
                <td><span className="rule">{e.rule}<br />{e.signals.join("+")}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
