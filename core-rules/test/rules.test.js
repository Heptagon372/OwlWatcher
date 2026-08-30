import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluate, initialState, SOURCE_GRADE } from '../src/engine.js';
import { classify } from '../src/policy.js';
import { runFixture, compact, loadPolicy } from '../bin/run-fixtures.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXDIR = join(HERE, '..', '..', 'spec', 'fixtures');
const POLICY = loadPolicy(['school-common']);

const SESSION = {
  sessionId: 't', seat: 1, platform: 'windows', ledger: 'kernel',
  examStartsAt: '2026-10-14T01:00:00Z', examEndsAt: '2026-10-14T02:30:00Z',
  tzOffsetMinutes: 540, agentPid: 1000,
};

const run = (observations, scanned = [], session = SESSION, state = initialState()) =>
  evaluate({ observations, scanned, policy: POLICY, session, state });

// ── 픽스처 회귀 (설계서 12장 "탐지기 회귀")

for (const f of readdirSync(FIXDIR).filter((x) => x.endsWith('.json')).sort()) {
  test(`픽스처 ${f}`, () => {
    const fx = JSON.parse(readFileSync(join(FIXDIR, f), 'utf8'));
    const got = runFixture(fx);
    assert.deepEqual(got.events.map(compact), fx.expect.events, fx.why);
    assert.equal(got.chainHead, fx.expect.chainHead, '체인 헤드가 바뀌었다 — 규칙 변경이 의도한 것이면 npm run bless');
  });
}

// ── 등급 모델 (설계서 02장)

test('P0 은 커널·서버·자가검증에서만 나온다', () => {
  assert.equal(SOURCE_GRADE.kernel, 'P0');
  assert.equal(SOURCE_GRADE.server, 'P0');
  assert.equal(SOURCE_GRADE.selfverify, 'P0');
  assert.equal(SOURCE_GRADE.userspace, 'P1');
});

test('같은 사실이라도 출처가 사용자 공간이면 P1로 내려가고 이유가 증거에 남는다', () => {
  const base = {
    kind: 'exec', signal: 'S9', platform: 'windows', ts: '2026-10-14T01:03:00Z',
    pid: 42, path: '~/Downloads/x.exe', sha256: 'a'.repeat(64), signed: false,
  };
  const k = run([{ ...base, source: 'kernel' }]).events[0];
  const u = run([{ ...base, source: 'userspace', collector: 'wmi-poll' }]).events[0];

  assert.equal(k.grade, 'P0');
  assert.equal(k.severity, 'crit');
  assert.equal(u.grade, 'P1');
  assert.equal(u.severity, 'warn');
  assert.match(u.evidence.notes[0], /P0에서 P1로 낮춤/);
});

test('부분 실패한 커널 수집은 P0으로 올리지 않는다', () => {
  const e = run([{
    kind: 'exec', source: 'kernel', signal: 'S9', platform: 'windows', degraded: true,
    ts: '2026-10-14T01:03:00Z', pid: 42, path: '~/Downloads/x.exe', sha256: 'b'.repeat(64), signed: false,
  }]).events[0];
  assert.equal(e.grade, 'P1');
});

test('P2 는 알림을 만들지 않는 등급이지만 이벤트로는 남는다', () => {
  const { events } = run([{
    kind: 'netPosture', source: 'userspace', signal: 'S5', platform: 'windows',
    ts: '2026-10-14T01:03:00Z', beacon: false, canary: false, ifaceCount: 1,
  }]);
  assert.equal(events.length, 1);
  assert.equal(events[0].grade, 'P2');
  assert.equal(events[0].severity, 'info');
});

// ── 허용목록 (설계서 05장)

test('deny 가 allow 를 이긴다 — 정상 서명을 단 원격제어 도구도 금지다', () => {
  const v = classify(POLICY, {
    path: 'C:/Program Files/AnyDesk/AnyDesk.exe', signer: 'Microsoft Corporation',
  }, 'windows');
  assert.equal(v.allowed, false);
  assert.equal(v.denied.id, 'remote-anydesk');
});

test('플랫폼 바이너리는 서명 주체를 따로 보지 않는다', () => {
  const v = classify(POLICY, { path: 'C:/Windows/System32/svchost.exe', platformBinary: true }, 'windows');
  assert.equal(v.allowed, true);
  assert.equal(v.layer, 'os');
});

test('세션 임시 허용은 만료되면 다시 잡힌다', () => {
  const p = { ...POLICY, allow: [...POLICY.allow, {
    sha256: 'c'.repeat(64), layer: 'session', expiresAt: '2026-10-14T02:30:00Z',
  }] };
  const subj = { path: '~/x.exe', sha256: 'c'.repeat(64) };
  assert.equal(classify(p, subj, 'windows', '2026-10-14T01:00:00Z').allowed, true);
  assert.equal(classify(p, subj, 'windows', '2026-10-14T03:00:00Z').allowed, false);
});

test('이름이 아니라 해시로 대조한다 — 이름만 바꾼 위장은 통하지 않는다', () => {
  const p = { ...POLICY, allow: [{ sha256: 'd'.repeat(64), signer: 'Dropbox, Inc' }] };
  assert.equal(classify(p, { path: 'Dropbox.exe', sha256: 'e'.repeat(64), signer: 'Dropbox, Inc' }, 'windows').allowed, false);
});

// ── 디바운스·에스컬레이션

test('같은 규칙·같은 대상은 5분 안에 한 번만 알린다', () => {
  const state = initialState();
  const item = (ts) => ({
    kind: 'statusItem', source: 'userspace', signal: 'S2', platform: 'windows', ts,
    ownerPid: 5000, ownerPath: '~/x/tray.exe', sha256: 'f'.repeat(64), signed: false,
  });
  const s = { ...SESSION, ledger: 'fallback' };
  assert.equal(run([item('2026-10-14T01:00:00Z')], [], s, state).events.length, 1);
  assert.equal(run([item('2026-10-14T01:04:00Z')], [], s, state).events.length, 0);
  assert.equal(run([item('2026-10-14T01:06:00Z')], [], s, state).events.length, 1);
});

test('사라졌다 다시 나타나면 디바운스와 무관하게 즉시 알린다', () => {
  const state = initialState();
  const s = { ...SESSION, ledger: 'fallback' };
  const item = (ts) => ({
    kind: 'statusItem', source: 'userspace', signal: 'S2', platform: 'windows', ts,
    ownerPid: 5000, ownerPath: '~/x/tray.exe', sha256: '1'.repeat(64), signed: false,
  });
  assert.equal(run([item('2026-10-14T01:00:00Z')], ['statusItem'], s, state).events.length, 1);

  const gone = run([], ['statusItem'], s, state);
  assert.equal(gone.events.length, 1);
  assert.equal(gone.events[0].rule, 'R-SUBJECT-CLEARED');

  const back = run([item('2026-10-14T01:01:00Z')], ['statusItem'], s, state);
  assert.equal(back.events.filter((e) => e.rule === 'R-S2-UNKNOWN-STATUS-ITEM').length, 1,
    '재등장은 별도 이벤트다 — 디바운스에 먹히면 안 된다');
});

test('P1 하나는 warn, 같은 대상에 둘이면 crit', () => {
  const s = { ...SESSION, ledger: 'fallback' };
  const sha = '2'.repeat(64);
  const one = run([{
    kind: 'process', source: 'userspace', signal: 'S1', platform: 'windows',
    ts: '2026-10-14T01:00:00Z', pid: 7, path: '~/a.exe', sha256: sha,
    signed: false, hasVisibleWindow: false,
  }], ['process'], s);
  assert.equal(one.events[0].severity, 'warn');

  const two = run([
    { kind: 'process', source: 'userspace', signal: 'S1', platform: 'windows',
      ts: '2026-10-14T01:00:00Z', pid: 7, path: '~/a.exe', sha256: sha, signed: false, hasVisibleWindow: false },
    { kind: 'statusItem', source: 'userspace', signal: 'S2', platform: 'windows',
      ts: '2026-10-14T01:00:01Z', ownerPid: 7, ownerPath: '~/a.exe', sha256: sha, signed: false },
  ], ['process', 'statusItem'], s);
  assert.ok(two.events.every((e) => e.severity === 'crit'));
  assert.ok(two.events.some((e) => e.rule === 'R-P1-ESCALATION'));
});

// ── S4 주기 판정

test('사람의 타이핑 속도는 Caps 패턴으로 잡지 않는다', () => {
  const s = { ...SESSION, ledger: 'fallback' };
  const t = (ms) => new Date(Date.parse('2026-10-14T01:20:00Z') + ms).toISOString();
  const slow = [0, 800, 1700, 2600].map((ms) => ({
    kind: 'capsTransition', source: 'userspace', signal: 'S4', platform: 'windows', ts: t(ms), state: true,
  }));
  assert.equal(run(slow, [], s).events.length, 0);
});

test('300ms 이하 주기가 이어지면 잡는다', () => {
  const s = { ...SESSION, ledger: 'fallback' };
  const t = (ms) => new Date(Date.parse('2026-10-14T01:20:00Z') + ms).toISOString();
  const fast = [0, 250, 500].map((ms) => ({
    kind: 'capsTransition', source: 'userspace', signal: 'S4', platform: 'windows', ts: t(ms), state: true,
  }));
  const { events } = run(fast, [], s);
  assert.equal(events.length, 1);
  assert.equal(events[0].rule, 'R-S4-CAPS-PATTERN');
});

// ── 원장 상관 (설계서 05장)

test('세션 시작 전부터 돌던 프로세스를 원장 우회로 오탐하지 않는다', () => {
  const state = initialState();
  const pre = {
    kind: 'process', source: 'userspace', signal: 'S1', platform: 'windows',
    ts: '2026-10-14T00:50:00Z', pid: 3000, path: '~/old/tool.exe', sha256: '3'.repeat(64),
    signed: false, hasVisibleWindow: false,
  };
  run([pre], ['process'], SESSION, state); // PRECHECK = 기준선
  const again = run([{ ...pre, ts: '2026-10-14T01:10:00Z' }], ['process'], SESSION, state);
  assert.equal(again.events.filter((e) => e.rule === 'R-CORR-LEDGER-BYPASS').length, 0);
});

test('원장이 커널이 아니면 상관 규칙을 아예 돌리지 않는다', () => {
  const state = initialState();
  const s = { ...SESSION, ledger: 'fallback' };
  run([], ['process'], s, state);
  const r = run([{
    kind: 'statusItem', source: 'userspace', signal: 'S2', platform: 'windows',
    ts: '2026-10-14T01:10:00Z', ownerPid: 9999, ownerPath: '~/g.exe', sha256: '4'.repeat(64), signed: false,
  }], ['statusItem'], s, state);
  assert.equal(r.events.filter((e) => e.rule === 'R-CORR-LEDGER-BYPASS').length, 0);
});

// ── 결정성

test('같은 입력은 같은 체인 헤드를 낸다', () => {
  const fx = JSON.parse(readFileSync(join(FIXDIR, '003-scan-evasion.json'), 'utf8'));
  assert.equal(runFixture(fx).chainHead, runFixture(fx).chainHead);
});

test('엔진은 시계를 읽지 않는다 — 모든 시각은 관측에서 온다', () => {
  const src = readFileSync(join(HERE, '..', 'src', 'engine.js'), 'utf8');
  assert.equal(/Date\.now\(\)|new Date\(\s*\)/.test(src), false,
    '엔진에서 현재 시각을 읽으면 픽스처가 재현되지 않고 C# 포트와 해시가 어긋난다');
});
