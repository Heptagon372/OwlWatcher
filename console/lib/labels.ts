import type { Grade, Severity, SessionState } from "./types";

/** 설계서 05장: 알림 문구는 등급을 먼저 말한다. */
export const GRADE_LABEL: Record<Grade, string> = {
  P0: "확정",
  P1: "정황",
  P2: "참고",
};

export const GRADE_MEANING: Record<Grade, string> = {
  P0: "커널·서버가 기록했거나 우리 코드의 검증이 실패했다. 학생 기기가 위조할 수 없다.",
  P1: "정상 사용에서 잘 나오지 않는 조합. 개별로는 설명 가능하다.",
  P2: "단독으로는 아무 의미 없다. 알림을 만들지 않는다.",
};

export const STATE_LABEL: Record<SessionState, string> = {
  idle: "대기",
  precheck: "사전 점검",
  ready: "시작 대기",
  armed: "감시 중",
  warn: "정황 있음",
  crit: "확인 필요",
  offline: "연결 끊김",
  ended: "종료",
};

export const GUARD_LABEL: Record<string, string> = {
  ok: "캡처차단 유효",
  failed: "캡처차단 깨짐",
  unsupported: "확인 불가",
  off: "꺼짐",
};

export const CONTEXT_LABEL: Record<string, string> = {
  downloadsPath: "다운로드 경로",
  unsignedBinary: "미서명",
  unnotarizedBinary: "미공증",
  startedNearExamStart: "시험 직전 시작",
  startedDuringExam: "시험 중 시작",
  multipleInterfaces: "인터페이스 2개 이상",
  softwareAttestation: "소프트웨어 키",
};

export function severityClass(s: Severity): string {
  return s === "crit" ? "crit" : s === "warn" ? "warn" : "info";
}

/** 좌석 색. 설계서 08장 좌석 맵. */
export function seatClass(state: SessionState): string {
  switch (state) {
    case "crit": return "seat crit";
    case "warn": return "seat warn";
    case "armed": return "seat armed";
    case "offline": return "seat offline";
    case "ready": return "seat ready";
    default: return "seat";
  }
}
