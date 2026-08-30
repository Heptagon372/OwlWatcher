// 정규화 JSON + 해시체인.
//
// 이 파일의 출력 바이트는 agent-windows/src/OwlWatch.Core/Canonical.cs 와 바이트 단위로
// 같아야 한다. 두 구현이 같은 픽스처에서 같은 체인 해시를 내는 것이 패리티 테스트의 핵심이고,
// 그래서 언어 표준 직렬화기(JSON.stringify / JsonSerializer)를 쓰지 않고 직접 쓴다 —
// .NET은 기본으로 비ASCII를 \uXXXX 로 이스케이프하고 JS는 그대로 두기 때문에 그대로 두면 어긋난다.
//
// 규칙
//   - 객체 키는 UTF-16 코드 단위 오름차순 (JS 기본 sort == C# string.CompareOrdinal)
//   - undefined 값과 undefined 원소는 제거. null 은 유지.
//   - 공백 없음
//   - 문자열: " \ 와 U+0020 미만만 이스케이프. 비ASCII는 UTF-8 원문 유지.
//   - 숫자: 정수만 허용. 부동소수는 표현이 언어마다 갈리므로 던진다.

import { createHash } from 'node:crypto';

const ESCAPES = { 8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r' };

export function canonicalString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 34) out += '\\"';
    else if (c === 92) out += '\\\\';
    else if (c < 0x20) out += ESCAPES[c] ?? '\\u' + c.toString(16).padStart(4, '0');
    else out += s[i];
  }
  return out + '"';
}

export function canonicalize(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'string') return canonicalString(value);
  if (t === 'number') {
    if (!Number.isInteger(value)) {
      throw new TypeError(`정규화 JSON은 정수만 허용한다 (받은 값: ${value}). ` +
        `부동소수는 JS와 .NET의 표현이 갈려 체인 해시가 어긋난다.`);
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalize(v === undefined ? null : v)).join(',') + ']';
  }
  if (t === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return '{' + keys.map((k) => canonicalString(k) + ':' + canonicalize(value[k])).join(',') + '}';
  }
  throw new TypeError(`정규화할 수 없는 타입: ${t}`);
}

export function sha256Hex(text) {
  return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

export const GENESIS_HASH = '0'.repeat(64);

/** 이벤트 해시. sig 와 hash 자신은 대상에서 뺀다. */
export function hashEvent(evt) {
  const core = {
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
  };
  return sha256Hex(canonicalize(core));
}

/** 체인 검증. 끊긴 지점의 seq 를 돌려준다. 설계서 08장 events append-only. */
export function verifyChain(events, genesis = GENESIS_HASH) {
  let prev = genesis;
  for (const e of events) {
    if (e.prevHash !== prev) return { ok: false, brokenAt: e.seq, reason: 'prevHash 불일치' };
    if (hashEvent(e) !== e.hash) return { ok: false, brokenAt: e.seq, reason: 'hash 불일치(내용 변조)' };
    prev = e.hash;
  }
  return { ok: true, head: prev };
}
