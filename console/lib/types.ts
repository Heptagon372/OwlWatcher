// 콘솔이 다루는 값. spec/*.schema.json 과 supabase/migrations 를 함께 반영한다.

export type Grade = "P0" | "P1" | "P2";
export type Severity = "info" | "warn" | "crit";

export type SessionState =
  | "idle" | "precheck" | "ready" | "armed"
  | "warn" | "crit" | "offline" | "ended";

export interface Exam {
  id: string;
  title: string;
  starts_at: string;
  ends_at: string;
  level: "L0" | "L1" | "L2";
  retention_days: number;
}

export interface Seat {
  id: string;
  exam_id: string;
  seat: number | null;
  os: "windows" | "macos";
  agent_version: string;
  attestation: "hw" | "sw";
  /** kernel 이 아니면 S9 이 P0 를 만들지 못한다. */
  ledger: "kernel" | "fallback" | "off";
  state: SessionState;
  last_seq: number;
  last_heartbeat_at: string | null;
  posture: {
    beacon?: boolean;
    canary?: boolean;
    ifaces?: number;
    captureGuard?: "ok" | "failed" | "unsupported" | "off";
  };
  summary: {
    ledgerExecs?: number;
    unknownProcs?: number;
    statusItems?: number;
    capsPatterns?: number;
  };
}

export interface OwlEvent {
  id: number;
  session_id: string;
  seq: number;
  ts: string;
  grade: Grade;
  severity: Severity;
  rule: string;
  signals: string[];
  summary: string;
  subject: { kind: string; key: string; label?: string; pid?: number | null };
  evidence: { observations?: unknown[]; notes?: string[]; escalatedFrom?: string[] };
  contexts: string[];
  prev_hash: string;
  hash: string;
}

/**
 * 하트비트가 30초 넘게 끊기면 오프라인이다.
 * 서버가 state 를 바꾸지 않고 화면에서 계산한다 — 마지막으로 받은 사실만 저장하고,
 * "지금 어떤가"는 보는 시점에 판단한다.
 */
export function effectiveState(seat: Seat, now = Date.now()): SessionState {
  if (seat.state === "ended") return "ended";
  const last = seat.last_heartbeat_at ? Date.parse(seat.last_heartbeat_at) : 0;
  if (last && now - last > 30_000) return "offline";
  return seat.state;
}
