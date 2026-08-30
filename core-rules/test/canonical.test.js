import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, sha256Hex, hashEvent, verifyChain, GENESIS_HASH } from '../src/canonical.js';

test('키 순서가 달라도 같은 바이트가 나온다', () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), canonicalize({ a: 2, b: 1 }));
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
});

test('undefined 는 빠지고 null 은 남는다', () => {
  assert.equal(canonicalize({ a: undefined, b: null }), '{"b":null}');
});

test('비ASCII는 이스케이프하지 않는다 — .NET 기본 직렬화기와 어긋나는 지점', () => {
  assert.equal(canonicalize({ k: '좌석 17' }), '{"k":"좌석 17"}');
  assert.equal(canonicalize('제어\n문자'), '"제어\\n문자"');
});

test('부동소수는 거부한다 — 언어 간 표현이 갈려 체인이 어긋난다', () => {
  assert.throws(() => canonicalize({ x: 1.5 }), /정수만 허용/);
});

test('UTF-8 바이트 기준 해시', () => {
  // C# 포트가 반드시 재현해야 하는 고정값.
  assert.equal(sha256Hex('{"k":"좌석 17"}'),
    sha256Hex(canonicalize({ k: '좌석 17' })));
  assert.match(sha256Hex('abc'), /^ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad$/);
});

test('해시체인은 내용 변조를 잡는다', () => {
  const mk = (seq, prevHash, summary) => {
    const e = {
      sessionId: 's', seq, ts: '2026-10-14T01:00:00Z', grade: 'P0', severity: 'crit',
      rule: 'R-S9-UNKNOWN-EXEC', signals: ['S9'], summary,
      subject: { kind: 'process', key: 'proc:path:x' },
      evidence: { observations: [] }, contexts: [], prevHash,
    };
    e.hash = hashEvent(e);
    return e;
  };
  const a = mk(1, GENESIS_HASH, '첫 번째');
  const b = mk(2, a.hash, '두 번째');
  assert.equal(verifyChain([a, b]).ok, true);

  b.summary = '조작됨';
  const bad = verifyChain([a, b]);
  assert.equal(bad.ok, false);
  assert.equal(bad.brokenAt, 2);
  assert.match(bad.reason, /hash 불일치/);
});

test('체인 중간을 들어내면 prevHash 가 끊긴다', () => {
  const e = { sessionId: 's', seq: 5, ts: '2026-10-14T01:00:00Z', grade: 'P1', severity: 'warn',
    rule: 'R-S1-UNKNOWN-AGENT-PROC', signals: ['S1'], summary: 'x',
    subject: { kind: 'process', key: 'k' }, evidence: { observations: [] }, contexts: [],
    prevHash: 'f'.repeat(64) };
  e.hash = hashEvent(e);
  assert.equal(verifyChain([e]).ok, false);
});
