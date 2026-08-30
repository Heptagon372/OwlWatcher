// 정규화 JSON + 서명 검증. core-rules/src/canonical.js 의 포트.
//
// 세 번째 구현이다 — JS 레퍼런스, C# 에이전트, 그리고 이 Edge Function.
// 셋의 바이트가 같아야 하트비트 서명이 검증된다. 그래서 표준 직렬화기를 쓰지 않고
// 여기서도 직접 쓴다: JSON.stringify 는 키를 정렬하지 않고, .NET 기본 직렬화기는
// 비ASCII 를 이스케이프한다. 한글이 들어간 summary 하나로 전부 어긋난다.

const ESCAPES: Record<number, string> = { 8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r" };

export function canonicalString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 34) out += '\\"';
    else if (c === 92) out += "\\\\";
    else if (c < 0x20) out += ESCAPES[c] ?? "\\u" + c.toString(16).padStart(4, "0");
    else out += s[i];
  }
  return out + '"';
}

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "string") return canonicalString(value as string);
  if (t === "number") {
    if (!Number.isInteger(value)) {
      throw new TypeError(
        `정규화 JSON은 정수만 허용한다 (받은 값: ${value}). 부동소수는 언어마다 표현이 갈려 서명이 어긋난다.`,
      );
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalize(v === undefined ? null : v)).join(",") + "]";
  }
  if (t === "object") {
    const o = value as Record<string, unknown>;
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
    return "{" + keys.map((k) => canonicalString(k) + ":" + canonicalize(o[k])).join(",") + "}";
  }
  throw new TypeError(`정규화할 수 없는 타입: ${t}`);
}

export const GENESIS_HASH = "0".repeat(64);

export async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** 이벤트 해시. sig 와 hash 자신은 대상에서 뺀다. hashEvent() 와 같은 필드 집합. */
export async function hashEvent(evt: Record<string, unknown>): Promise<string> {
  return await sha256Hex(canonicalize({
    sessionId: evt.sessionId,
    seq: evt.seq,
    ts: evt.ts,
    grade: evt.grade,
    severity: evt.severity,
    rule: evt.rule,
    signals: evt.signals,
    summary: evt.summary,
    subject: evt.subject,
    evidence: evt.evidence,
    contexts: evt.contexts ?? [],
    prevHash: evt.prevHash,
  }));
}

const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function importDevicePublicKey(spkiBase64: string): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "spki",
    b64(spkiBase64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

/**
 * 하트비트 서명 검증.
 *
 * .NET 의 ECDsa.SignData 는 DER 이 아니라 IEEE P1363(r||s) 로 서명을 낸다.
 * WebCrypto 의 ECDSA 도 P1363 을 기대하므로 그대로 맞는다 — DER 을 기대하는
 * 라이브러리를 쓰면 전부 실패하고, 그건 좌석마다 S14(P0) 경보가 뜬다는 뜻이다.
 */
export async function verifyHeartbeat(
  body: Record<string, unknown>,
  key: CryptoKey,
): Promise<{ ok: boolean; why?: string }> {
  const sig = body.sig;
  if (typeof sig !== "string") return { ok: false, why: "sig 없음" };

  const { sig: _drop, ...rest } = body;
  let payload: string;
  try {
    payload = canonicalize(rest);
  } catch (e) {
    return { ok: false, why: `정규화 실패: ${(e as Error).message}` };
  }

  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    b64(sig),
    new TextEncoder().encode(payload),
  );
  return ok ? { ok: true } : { ok: false, why: "서명 불일치" };
}
