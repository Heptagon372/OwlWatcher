"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { supabase } from "@/lib/supabase";
import { effectiveState, type OwlEvent, type Seat } from "@/lib/types";
import { CONTEXT_LABEL, GRADE_LABEL, GUARD_LABEL, STATE_LABEL, seatClass, severityClass } from "@/lib/labels";

/**
 * 좌석 맵과 알림 피드. 설계서 08장.
 *
 * 등급 배지를 문장 앞에 두고, 서버가 등급을 다시 매기지 않는다 —
 * 이벤트는 기기에서 판정돼 서명된 것이고 콘솔은 그걸 그대로 보여 준다.
 */
export default function SeatMap({ examId }: { examId: string }) {
  const [seats, setSeats] = useState<Seat[]>([]);
  const [events, setEvents] = useState<OwlEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async () => {
    if (!supabase) return;

    const { data: s, error: se } = await supabase
      .from("sessions")
      .select("*")
      .eq("exam_id", examId)
      .order("seat", { ascending: true });
    if (se) { setError(se.message); return; }
    setSeats((s ?? []) as Seat[]);

    const ids = (s ?? []).map((x: { id: string }) => x.id);
    if (ids.length) {
      const { data: e } = await supabase
        .from("events")
        .select("*")
        .in("session_id", ids)
        .order("ts", { ascending: false })
        .limit(80);
      setEvents((e ?? []) as OwlEvent[]);
    } else {
      setEvents([]);
    }
    setError(null);
    setNow(Date.now());
  }, [examId]);

  useEffect(() => {
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [load]);

  async function arm(sessionId: string) {
    if (!supabase) return;
    // ARMED 진입의 정식 경로. 다음 하트비트 응답으로 arm 명령이 내려간다 —
    // 학생 쪽에서 만들 수 없다(설계서 09장).
    await supabase.from("sessions").update({ arm_pending: true }).eq("id", sessionId);
    load();
  }

  const seatOf = (id: string) => seats.find((s) => s.id === id)?.seat ?? null;

  return (
    <>
      {error && <div className="notice warn">{error}</div>}

      <div className="seats">
        {seats.length === 0 && <div className="empty">접속한 좌석이 없다.</div>}
        {seats.map((s) => {
          const state = effectiveState(s, now);
          return (
            <div className={seatClass(state)} key={s.id}>
              <div className="no">{s.seat ?? "—"}</div>
              <div className="st">{STATE_LABEL[state]}</div>
              <div className="meta">
                {s.os} · {s.attestation === "hw" ? "TPM" : <span className="flag">소프트키</span>}
                {" · "}
                {s.ledger === "kernel" ? "커널 원장" : <span className="flag">폴링 원장</span>}
                <br />
                {GUARD_LABEL[s.posture?.captureGuard ?? "off"]} · 비콘{" "}
                {s.posture?.beacon ? "O" : "X"} · 카나리{" "}
                {s.posture?.canary ? <span className="flag">도달!</span> : "차단"}
                <br />
                seq {s.last_seq}
              </div>
              {state === "ready" && <button onClick={() => arm(s.id)}>시험 시작</button>}
            </div>
          );
        })}
      </div>

      <h2>알림 피드 — 등급을 먼저 말한다</h2>
      <div className="feed">
        {events.length === 0 && <div className="empty">아직 이벤트가 없다.</div>}
        {events
          // P2 는 알림을 만들지 않는다(설계서 02장). 타임라인·리포트에만 남는다.
          .filter((e) => e.grade !== "P2")
          .map((e) => (
            <div className={`ev ${severityClass(e.severity)}`} key={e.id}>
              <span className="badge">{GRADE_LABEL[e.grade]}</span>
              {e.summary}
              <div className="rule">
                좌석 {seatOf(e.session_id) ?? "?"} · {e.rule} · 신호 {e.signals.join("+")}
                {e.contexts.length > 0 &&
                  " · 맥락 " + e.contexts.map((c) => CONTEXT_LABEL[c] ?? c).join(", ")}
              </div>
              {e.evidence?.notes?.map((n, i) => (
                <div className="note" key={i}>{n}</div>
              ))}
            </div>
          ))}
      </div>

      <p className="sub" style={{ marginTop: 18 }}>
        <Link href={`/exams/${examId}/report`}>리포트 보기</Link> — P0·P1·P2 를 세 절로 분리해 출력한다.
      </p>
    </>
  );
}
