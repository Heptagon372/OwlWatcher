// POST /functions/v1/heartbeat — 설계서 08장의 계약.
//
// 서버가 하는 일은 네 가지다.
//   1) seq 단조 증가        재생 공격 차단
//   2) 시각 편차 ±30s       시계 조작 차단
//   3) 기기 키 서명 검증    실패하면 S14 (P0) — 다른 기기가 대신 쏘고 있다는 뜻
//   4) 이벤트 적재          해시체인은 DB 트리거가 검증한다
//
// **등급을 서버가 다시 매기지 않는다.** 이벤트는 기기에서 판정돼 서명된 것이고,
// 서버가 고치면 그 서명이 무의미해진다. 서버는 받아들일지 거부할지만 정한다.
//
// mock-server/server.mjs 가 같은 계약을 구현한다 — 개발은 그걸로 하고 검증 로직은 여기와 같다.

import { createClient } from "jsr:@supabase/supabase-js@2";
import { verifyHeartbeat, importDevicePublicKey } from "../_shared/canonical.ts";

const CLOCK_SKEW_MS = 30_000;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

// service_role 로 돈다. RLS 를 우회하므로 이 함수가 유일한 쓰기 경로여야 한다 —
// 에이전트에게 anon 키로 events 를 쓰게 하면 클라이언트를 믿는 것이 된다(설계서 P4).
const db = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  { auth: { persistSession: false } },
);

Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ error: "POST 만 받는다" }, 405);

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "JSON 파싱 실패" }, 400);
  }

  const sessionId = body.sessionId;
  if (typeof sessionId !== "string") return json({ error: "sessionId 필요" }, 400);

  const { data: session, error: readErr } = await db
    .from("sessions")
    .select("id, exam_id, last_seq, hw_key_pub, arm_pending, attestation")
    .eq("id", sessionId)
    .single();

  if (readErr || !session) return json({ error: "등록되지 않은 세션" }, 404);

  // 1) seq 단조 증가
  const seq = body.seq;
  if (typeof seq !== "number" || !Number.isInteger(seq) || seq <= session.last_seq) {
    await audit(session.exam_id, "heartbeat-reject", sessionId, { reason: "seq", got: seq, have: session.last_seq });
    return json({ error: "seq 는 단조 증가해야 한다", expectedAbove: session.last_seq }, 409);
  }

  // 2) 시각 편차
  const skew = Math.abs(Date.now() - Date.parse(String(body.ts)));
  if (!Number.isFinite(skew) || skew > CLOCK_SKEW_MS) {
    await audit(session.exam_id, "heartbeat-reject", sessionId, { reason: "clock", skewMs: skew });
    return json({ error: "시각 편차가 허용 범위를 넘는다", skewMs: skew }, 400);
  }

  // 3) 기기 키 서명. 실패는 S14 — 등급 P0 다.
  let verdict: { ok: boolean; why?: string };
  try {
    const key = await importDevicePublicKey(session.hw_key_pub);
    verdict = await verifyHeartbeat(body, key);
  } catch (e) {
    verdict = { ok: false, why: `키를 읽지 못했다: ${(e as Error).message}` };
  }

  if (!verdict.ok) {
    await audit(session.exam_id, "heartbeat-reject", sessionId, { reason: "signature", why: verdict.why });
    return json({ error: "서명 검증 실패", why: verdict.why, signal: "S14", grade: "P0" }, 401);
  }

  // 4) 이벤트 적재. 체인 검증은 DB 트리거가 한다 — 애플리케이션 코드를 믿지 않는다.
  const events = Array.isArray(body.events) ? body.events : [];
  let inserted = 0;
  let chainError: string | null = null;

  for (const e of events as Record<string, unknown>[]) {
    const { error } = await db.from("events").insert({
      session_id: sessionId,
      seq: e.seq,
      ts: e.ts,
      grade: e.grade,
      severity: e.severity,
      rule: e.rule,
      signals: e.signals,
      summary: e.summary,
      subject: e.subject,
      evidence: e.evidence,
      contexts: e.contexts ?? [],
      prev_hash: e.prevHash,
      hash: e.hash,
      sig: e.sig ?? null,
    });

    if (error) {
      // 23505 = 중복. 오프라인 재전송에서 정상적으로 일어난다.
      if (error.code === "23505") continue;
      chainError = error.message;
      break;
    }
    inserted++;

    // P2 는 알림을 만들지 않는다(설계서 02장). 트리거도 막지만 여기서도 거르지 않으면
    // 매번 예외가 나 로그가 더러워진다.
    if (e.grade !== "P2") {
      const { data: row } = await db.from("events")
        .select("id").eq("session_id", sessionId).eq("seq", e.seq).single();
      if (row) await db.from("alerts").insert({ event_id: row.id }).select();
    }
  }

  if (chainError) {
    await audit(session.exam_id, "heartbeat-chain-broken", sessionId, { error: chainError });
    return json({ error: "이벤트 체인이 거부됐다", detail: chainError, signal: "S14", grade: "P0" }, 409);
  }

  const posture = (body.posture ?? {}) as Record<string, unknown>;
  await db.from("sessions").update({
    last_seq: seq,
    state: body.state ?? "armed",
    posture,
    summary: body.summary ?? {},
    attestation: body.attestation ?? session.attestation,
    last_heartbeat_at: new Date().toISOString(),
    arm_pending: false,
  }).eq("id", sessionId);

  return json({
    ok: true,
    inserted,
    // 감독관이 콘솔에서 시작을 눌렀는가. ARMED 진입의 정식 경로다(설계서 09장).
    command: session.arm_pending ? "arm" : null,
    serverTime: new Date().toISOString(),
  });
});

async function audit(examId: string, action: string, target: string, detail: unknown) {
  await db.from("audit_log").insert({ actor: null, action, target, detail: { examId, ...(detail as object) } });
}
