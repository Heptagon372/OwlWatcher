// POST /functions/v1/session/register — 좌석 등록.
//
// 여기서 기기 공개키가 고정된다. 이후 모든 하트비트는 이 키로 검증되므로,
// 등록 시점에 키를 바꿔치기하면 전부 무너진다. 그래서 이미 등록된 좌석에
// **다른 키로 다시 등록하는 것을 거부한다** — 세션 중 기기 교체는 감독관이
// 콘솔에서 좌석을 초기화해야만 가능하다.

import { createClient } from "jsr:@supabase/supabase-js@2";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

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

  const { sessionId, examId, seat, os, agentVersion, hwKeyPub, attestation, ledger, studentHash } = body as {
    sessionId?: string; examId?: string; seat?: number; os?: string;
    agentVersion?: string; hwKeyPub?: string; attestation?: string;
    ledger?: string; studentHash?: string;
  };

  if (!sessionId || !examId || !hwKeyPub || !os || !agentVersion) {
    return json({ error: "sessionId · examId · os · agentVersion · hwKeyPub 가 필요하다" }, 400);
  }

  // 공개키가 실제로 P-256 SPKI 인지 확인한다. 여기서 걸러야 하트비트 검증이
  // "키를 읽지 못했다"로 실패하며 S14 오탐을 만드는 일이 없다.
  try {
    const der = Uint8Array.from(atob(hwKeyPub), (c) => c.charCodeAt(0));
    await crypto.subtle.importKey("spki", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch (e) {
    return json({ error: `공개키를 읽지 못했다: ${(e as Error).message}` }, 400);
  }

  const { data: existing } = await db
    .from("sessions").select("id, hw_key_pub").eq("id", sessionId).maybeSingle();

  if (existing && existing.hw_key_pub !== hwKeyPub) {
    await db.from("audit_log").insert({
      action: "register-key-mismatch", target: sessionId,
      detail: { examId, seat, note: "이미 등록된 좌석에 다른 기기 키로 등록 시도" },
    });
    return json({
      error: "이 좌석은 다른 기기 키로 이미 등록됐다. 기기를 바꾸려면 감독관이 좌석을 초기화해야 한다.",
      signal: "S14", grade: "P0",
    }, 409);
  }

  const { error } = await db.from("sessions").upsert({
    id: sessionId,
    exam_id: examId,
    seat: seat ?? null,
    student_hash: studentHash ?? null,   // 이름은 받지 않는다
    os,
    agent_version: agentVersion,
    hw_key_pub: hwKeyPub,
    attestation: attestation === "hw" ? "hw" : "sw",
    ledger: ledger ?? "fallback",
    state: "precheck",
  }, { onConflict: "id" });

  if (error) return json({ error: error.message }, 400);

  await db.from("audit_log").insert({
    action: "register", target: sessionId,
    detail: { examId, seat, os, attestation, ledger },
  });

  return json({
    ok: true,
    // 학생 화면과 감독관 화면이 같은 것을 봐야 한다. 무엇이 낮은 등급으로
    // 표기될지 등록 시점에 알려 준다(설계서 10장 학생 상태창).
    notes: [
      attestation !== "hw"
        ? "이 기기는 하드웨어 키가 없어 소프트웨어 키로 폴백했다. 기기 신원을 증명하지 못하며 UI 에 그대로 표기된다."
        : null,
      ledger !== "kernel"
        ? "커널 원장을 쓰지 못한다. 프로세스 실행 근거가 P0 이 아니라 P1 로 기록된다."
        : null,
    ].filter(Boolean),
  });
});
