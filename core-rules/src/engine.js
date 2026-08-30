// 탐지 규칙 · 등급 판정. 순수 함수 — 시계도, 파일도, 네트워크도 만지지 않는다.
// 모든 시각은 관측(observation)에서 온다. 그래야 픽스처로 재현되고 C# 포트와 해시가 맞는다.
//
// 설계서 02장(확신 등급 모델) · 05장(신호 카탈로그 · 탐지 규칙)의 코드판이다.

import { classify, p2Contexts } from './policy.js';
import { buildSummary, DETAIL, GRADE_LABEL } from './summary.js';
import { hashEvent, GENESIS_HASH } from './canonical.js';

/** 관측 출처가 등급의 상한을 정한다. 설계서 02장 "P0에는 휴리스틱을 넣지 않는다". */
export const SOURCE_GRADE = { kernel: 'P0', server: 'P0', selfverify: 'P0', userspace: 'P1' };

const DEFAULTS = {
  capsMaxIntervalMs: 300,
  capsMinTogglesInWindow: 2,
  capsWindowMs: 1500,
  debounceMs: 300000,
  p1EscalationCount: 2,
  preExamContextMs: 900000,
};

export function initialState() {
  return {
    seq: 0,
    prevHash: GENESIS_HASH,
    debounce: {},          // "rule|subjectKey" -> 마지막 발화 시각(ms)
    subjectP1Rules: {},    // subjectKey -> [ruleId]  (같은 대상에 겹친 P1 규칙)
    escalated: {},         // subjectKey -> true
    ledgerPids: {},        // pid -> {path, sha256, signer}  커널 원장이 본 exec
    ledgerExited: {},      // pid -> true
    baselinePids: {},      // 세션 시작 시점에 이미 돌던 pid (원장 상관의 기준선)
    baselineCaptured: false,
    presence: {},          // kind -> [subjectKey]  직전 완전열거 결과
    capsBuffer: [],        // {tsMs, state}
    counters: { ledgerExecs: 0, unknownProcs: 0, statusItems: 0, capsPatterns: 0 },
  };
}

function procKey(o) {
  if (o.sha256) return `proc:sha256:${o.sha256}`;
  if (o.cdhash) return `proc:cdhash:${o.cdhash}`;
  const p = (o.path ?? o.ownerPath ?? 'unknown').replace(/\\/g, '/').toLowerCase();
  return `proc:path:${p}`;
}

/** statusItem/window 관측을 프로세스 판정용 형태로 정규화한다. */
function asSubject(o) {
  return {
    path: o.path ?? o.ownerPath,
    sha256: o.sha256,
    cdhash: o.cdhash,
    signer: o.signer,
    teamId: o.teamId,
    signed: o.signed,
    notarized: o.notarized,
    platformBinary: o.platformBinary,
    startedAt: o.startedAt,
  };
}

export function evaluate({ observations = [], scanned = [], policy, session, state }) {
  const th = { ...DEFAULTS, ...(policy.thresholds ?? {}) };
  const platform = session.platform ?? 'windows';
  const drafts = [];
  const seenThisBatch = {}; // kind -> [subjectKey]

  const ctx = { policy, session, platform, th, state, drafts };

  // ── 0단계 · 원장 색인. 상관 규칙이 쓸 사실을 먼저 쌓는다.
  for (const o of observations) {
    if (o.kind === 'exec' && o.source === 'kernel') {
      state.ledgerPids[o.pid] = { path: o.path, sha256: o.sha256, signer: o.signer };
      delete state.ledgerExited[o.pid];
      state.counters.ledgerExecs++;
    }
    if (o.kind === 'exec' && o.source !== 'kernel') state.counters.ledgerExecs++;
    if (o.kind === 'process' && o.note === 'exit') state.ledgerExited[o.pid] = true;
  }

  // PRECHECK의 첫 완전열거가 기준선이 된다. 이전부터 돌던 프로세스를
  // "원장에 없다"는 이유로 잡으면 좌석마다 오탐이 쏟아진다.
  if (!state.baselineCaptured && scanned.includes('process')) {
    for (const o of observations) if (o.kind === 'process') state.baselinePids[o.pid] = true;
    state.baselineCaptured = true;
  }

  // ── 1단계 · 관측별 규칙
  for (const o of observations) {
    switch (o.kind) {
      case 'exec':          ruleExec(ctx, o); break;
      case 'process':       ruleProcess(ctx, o, seenThisBatch); break;
      case 'statusItem':    ruleStatusItem(ctx, o, seenThisBatch); break;
      case 'captureExcludedWindow': ruleExcludedWindow(ctx, o, seenThisBatch); break;
      case 'capsTransition': state.capsBuffer.push({ tsMs: Date.parse(o.ts), state: o.state, o }); break;
      case 'imageLoad':     ruleImageLoad(ctx, o); break;
      case 'iokitOpen':     ruleIokitOpen(ctx, o); break;
      case 'tccGrant':      ruleTccGrant(ctx, o); break;
      case 'netPosture':    ruleNetPosture(ctx, o); break;
      case 'procConnection': break; // 증거로만 보관. 단독 규칙 없음.
      case 'vmIndicator':   ruleVm(ctx, o); break;
      case 'remoteControlProcess': ruleRemote(ctx, o); break;
      case 'lockdownState': ruleLockdown(ctx, o); break;
      case 'captureGuard':  ruleCaptureGuard(ctx, o); break;
      case 'agentIntegrity': ruleIntegrity(ctx, o); break;
      case 'attestation':   ruleAttestation(ctx, o); break;
    }
  }

  // ── 2단계 · Caps Lock 주기 판정
  ruleCapsPattern(ctx);

  // ── 3단계 · 원장 상관 (설계서 05장 "원장 상관")
  ruleLedgerCorrelation(ctx, observations, scanned, seenThisBatch);

  // ── 4단계 · 완전열거 대상의 소멸 = 상태 변화 이벤트
  for (const kind of scanned) {
    const now = seenThisBatch[kind] ?? [];
    const before = state.presence[kind] ?? [];
    for (const key of before) {
      if (!now.includes(key)) {
        push(ctx, {
          rule: 'R-SUBJECT-CLEARED', grade: 'P2', severity: 'info', signals: ['S1'],
          subject: { kind: kind === 'statusItem' ? 'process' : 'window', key, label: key },
          obs: { ts: lastTs(observations) ?? session.examStartsAt },
          detail: DETAIL.cleared(key), bypassDebounce: true,
        });
        // 재등장 시 즉시 알리기 위해 디바운스를 푼다.
        for (const dk of Object.keys(state.debounce)) if (dk.endsWith(`|${key}`)) delete state.debounce[dk];
      }
    }
    state.presence[kind] = now;
  }

  // ── 5단계 · P1 에스컬레이션. 같은 대상에 서로 다른 P1 규칙이 겹치면 crit.
  applyEscalation(ctx);

  // ── 6단계 · 확정: seq · 해시체인 · 문구
  const events = [];
  for (const d of drafts) {
    state.seq += 1;
    const evt = {
      sessionId: session.sessionId,
      seq: state.seq,
      ts: d.ts,
      grade: d.grade,
      severity: d.severity,
      rule: d.rule,
      signals: d.signals,
      summary: buildSummary(d.rule, {
        session,
        obs: d.obs ?? {},
        subject: { ...d.subject, __grade: d.grade },
        detail: d.detail,
      }),
      subject: d.subject,
      evidence: d.evidence,
      contexts: d.contexts ?? [],
      prevHash: state.prevHash,
    };
    evt.hash = hashEvent(evt);
    evt.sig = null; // 에이전트가 하드웨어 키로 채운다 (S14)
    state.prevHash = evt.hash;
    events.push(evt);
  }

  return { events, state, heartbeatSummary: { ...state.counters } };
}

// ────────────────────────────────────────────────────────────── 내부

function lastTs(observations) {
  return observations.length ? observations[observations.length - 1].ts : null;
}

/**
 * 초안 이벤트를 쌓는다. 등급의 출처 강등과 디바운스가 여기 한 곳에 있다.
 */
function push(ctx, spec) {
  const { state, th } = ctx;
  const obs = spec.obs ?? {};
  let grade = spec.grade;
  const notes = [...(spec.notes ?? [])];

  // 출처 강등: P0 은 kernel/server/selfverify 에서만 나온다.
  if (grade === 'P0') {
    const cap = SOURCE_GRADE[obs.source] ?? 'P1';
    if (cap !== 'P0' || obs.degraded) {
      grade = 'P1';
      notes.push(
        `출처가 ${obs.source ?? '불명'}${obs.degraded ? '(부분 실패)' : ''} 이므로 등급을 P0에서 P1로 낮춤. ` +
        `커널·서버·자가검증이 아닌 근거는 결정적이지 않다.`
      );
    }
  }

  let severity = spec.severity ?? (grade === 'P0' ? 'crit' : grade === 'P1' ? 'warn' : 'info');
  if (grade === 'P2' && spec.severity == null) severity = 'info';

  const dk = `${spec.rule}|${spec.subject.key}`;
  const tsMs = Date.parse(spec.ts ?? obs.ts ?? ctx.session.examStartsAt);
  if (!spec.bypassDebounce) {
    const last = state.debounce[dk];
    if (last != null && tsMs - last < th.debounceMs) return null;
    state.debounce[dk] = tsMs;
  }

  if (grade === 'P1') {
    const list = (state.subjectP1Rules[spec.subject.key] ??= []);
    if (!list.includes(spec.rule)) list.push(spec.rule);
  }

  const draft = {
    rule: spec.rule,
    grade,
    severity,
    signals: spec.signals,
    subject: spec.subject,
    detail: spec.detail,
    obs,
    ts: spec.ts ?? obs.ts ?? ctx.session.examStartsAt,
    contexts: spec.contexts ?? [],
    evidence: { observations: spec.evidence ?? (obs.kind ? [obs] : []), ...(notes.length ? { notes } : {}) },
  };
  ctx.drafts.push(draft);
  return draft;
}

function applyEscalation(ctx) {
  const { state, th, drafts } = ctx;
  const crossed = [];
  for (const [key, rules] of Object.entries(state.subjectP1Rules)) {
    if (rules.length >= th.p1EscalationCount && !state.escalated[key]) {
      state.escalated[key] = true;
      crossed.push([key, rules]);
    }
  }
  // 이미 겹친 대상의 이번 배치 P1 이벤트는 crit 으로 올린다.
  for (const d of drafts) {
    if (d.grade === 'P1' && state.escalated[d.subject.key] && d.severity === 'warn') d.severity = 'crit';
  }
  for (const [key, rules] of crossed) {
    const label = drafts.find((d) => d.subject.key === key)?.subject.label ?? key;
    const anchor = drafts.find((d) => d.subject.key === key);
    ctx.drafts.push({
      rule: 'R-P1-ESCALATION',
      grade: 'P1',
      severity: 'crit',
      signals: ['S1'],
      subject: { kind: 'process', key, label },
      detail: DETAIL.escalation(label, rules),
      obs: anchor?.obs ?? {},
      ts: anchor?.ts ?? ctx.session.examStartsAt,
      contexts: [],
      evidence: { observations: [], escalatedFrom: rules },
    });
  }
}

// ── P0 규칙 ────────────────────────────────────────────────────

function ruleExec(ctx, o) {
  const verdict = classify(ctx.policy, asSubject(o), ctx.platform, o.ts);
  if (verdict.denied) {
    return push(ctx, {
      rule: 'R-DENY-PROCESS', grade: 'P0', severity: 'crit',
      signals: [verdict.denied.signal ?? 'S6'], obs: o,
      subject: { kind: 'process', key: procKey(o), label: o.path, pid: o.pid ?? null },
      detail: DETAIL.remote(o, verdict.denied),
      contexts: p2Contexts(asSubject(o), ctx.session, ctx.th),
    });
  }
  if (verdict.allowed) return null;
  return push(ctx, {
    rule: 'R-S9-UNKNOWN-EXEC', grade: 'P0', signals: ['S9'], obs: o,
    subject: { kind: 'process', key: procKey(o), label: o.path, pid: o.pid ?? null },
    detail: DETAIL.exec(o, qual(o)),
    contexts: p2Contexts(asSubject(o), ctx.session, ctx.th),
  });
}

function ruleTccGrant(ctx, o) {
  if (o.service !== 'ScreenCapture' || o.right !== 'allowed') return null;
  const verdict = classify(ctx.policy, { path: o.identity, signer: o.identity }, ctx.platform, o.ts);
  if (verdict.allowed) return null;
  return push(ctx, {
    rule: 'R-S10-SCREENCAPTURE-GRANT', grade: 'P0', signals: ['S10'], obs: o,
    subject: { kind: 'process', key: `proc:path:${(o.identity ?? '').toLowerCase()}`, label: o.identity },
    detail: DETAIL.tcc(o),
  });
}

const HID_CLASSES = ['IOHIDLibUserClient', 'IOHIDDeviceUserClient', 'AppleHIDKeyboardEventDriver'];

function ruleIokitOpen(ctx, o) {
  if (!HID_CLASSES.some((c) => (o.userClientClass ?? '').includes(c))) return null;
  const verdict = classify(ctx.policy, asSubject(o), ctx.platform, o.ts);
  if (verdict.allowed) return null;
  return push(ctx, {
    rule: 'R-S12-HID-OPEN', grade: 'P0', signals: ['S12'], obs: o,
    subject: { kind: 'device', key: procKey(o), label: o.path ?? `pid ${o.pid}`, pid: o.pid ?? null },
    detail: DETAIL.hid(o),
  });
}

function ruleCaptureGuard(ctx, o) {
  if (o.ok !== false) return null;
  return push(ctx, {
    rule: 'R-S13-CAPTURE-GUARD-FAIL', grade: 'P0', signals: ['S13'], obs: o,
    subject: { kind: 'guard', key: 'guard:capture', label: '시험 창 캡처 보호' },
    detail: DETAIL.guardFail(o),
  });
}

function ruleLockdown(ctx, o) {
  if (o.mode === 'none' || o.active !== false) return null;
  return push(ctx, {
    rule: 'R-S7-LOCKDOWN-EXIT', grade: 'P0', signals: ['S7'], obs: o,
    subject: { kind: 'session', key: `session:${ctx.session.sessionId}`, label: '평가 모드' },
    detail: DETAIL.lockdownExit(o),
  });
}

function ruleAttestation(ctx, o) {
  if (o.verified === false) {
    return push(ctx, {
      rule: 'R-S14-ATTESTATION-FAIL', grade: 'P0', signals: ['S14'], obs: o,
      subject: { kind: 'session', key: `session:${ctx.session.sessionId}`, label: '기기 키' },
      detail: DETAIL.attestFail(),
    });
  }
  // 소프트웨어 키 폴백은 알림이 아니라 표기다. 설계서 S14: "속이지 않는다".
  return null;
}

// ── P1 규칙 ────────────────────────────────────────────────────

function qual(o) {
  const q = [];
  if (o.signed === false) q.push('미서명');
  else if (o.notarized === false) q.push('미공증');
  else if (o.signer) q.push(`서명자 ${o.signer}`);
  if (o.source === 'kernel') q.push('커널 기록');
  else if (o.source === 'selfverify') q.push('자가검증');
  else if (o.source === 'userspace') q.push('사용자 공간 열거');
  return q.length ? `(${q.join(', ')})` : '';
}

function ruleProcess(ctx, o, seen) {
  const key = procKey(o);
  (seen.process ??= []).push(key);
  // "에이전트형"의 정의는 플랫폼마다 다르므로 수집기가 답한다(o.agentLike).
  // 알려주지 않으면 창 가시성으로 폴백한다 — 픽스처와 macOS 수집기가 이 경로를 쓴다.
  const agentLike = o.agentLike ?? (o.hasVisibleWindow === false);
  if (!agentLike) return null;
  const verdict = classify(ctx.policy, asSubject(o), ctx.platform, o.ts);
  if (verdict.denied) {
    return push(ctx, {
      rule: 'R-DENY-PROCESS', grade: 'P0', severity: 'crit',
      signals: [verdict.denied.signal ?? 'S6'], obs: o,
      subject: { kind: 'process', key, label: o.path, pid: o.pid ?? null },
      detail: DETAIL.remote(o, verdict.denied),
    });
  }
  if (verdict.allowed) return null;
  ctx.state.counters.unknownProcs++;
  return push(ctx, {
    rule: 'R-S1-UNKNOWN-AGENT-PROC', grade: 'P1', signals: ['S1'], obs: o,
    subject: { kind: 'process', key, label: o.path, pid: o.pid ?? null },
    detail: DETAIL.agentProc(o, qual(o)),
    contexts: p2Contexts(asSubject(o), ctx.session, ctx.th),
  });
}

function ruleStatusItem(ctx, o, seen) {
  const key = procKey(o);
  (seen.statusItem ??= []).push(key);
  ctx.state.counters.statusItems++;
  const verdict = classify(ctx.policy, asSubject(o), ctx.platform, o.ts);
  if (verdict.allowed || verdict.denied) return null;
  return push(ctx, {
    rule: 'R-S2-UNKNOWN-STATUS-ITEM', grade: 'P1', signals: ['S2'], obs: o,
    subject: { kind: 'process', key, label: o.ownerPath, pid: o.ownerPid ?? null },
    detail: DETAIL.statusItem(o, qual(o)),
    contexts: p2Contexts(asSubject(o), ctx.session, ctx.th),
  });
}

function ruleExcludedWindow(ctx, o, seen) {
  if (o.affinity === 'none') return null;
  if (o.ownerPid != null && o.ownerPid === ctx.session.agentPid) return null; // 우리 시험 창
  const key = procKey(o);
  (seen.captureExcludedWindow ??= []).push(key);
  const verdict = classify(ctx.policy, asSubject(o), ctx.platform, o.ts);
  if (verdict.allowed) return null;
  return push(ctx, {
    rule: 'R-S3-CAPTURE-EXCLUDED-WINDOW', grade: 'P1', signals: ['S3'], obs: o,
    subject: { kind: 'process', key, label: o.ownerPath, pid: o.ownerPid ?? null },
    detail: DETAIL.excludedWindow(o, qual(o)),
  });
}

function ruleCapsPattern(ctx) {
  const { state, th } = ctx;
  const buf = state.capsBuffer.sort((a, b) => a.tsMs - b.tsMs);
  let i = 0;
  const consumed = new Set();
  while (i < buf.length) {
    let j = i;
    while (j + 1 < buf.length && buf[j + 1].tsMs - buf[j].tsMs <= th.capsMaxIntervalMs) j++;
    const run = buf.slice(i, j + 1);
    const span = run[run.length - 1].tsMs - run[0].tsMs;
    if (run.length >= th.capsMinTogglesInWindow && span <= th.capsWindowMs) {
      state.counters.capsPatterns++;
      const gaps = [];
      for (let k = 1; k < run.length; k++) gaps.push(run[k].tsMs - run[k - 1].tsMs);
      const avg = Math.round(gaps.reduce((a, b) => a + b, 0) / gaps.length);
      push(ctx, {
        rule: 'R-S4-CAPS-PATTERN', grade: 'P1', signals: ['S4'], obs: run[0].o,
        subject: { kind: 'device', key: 'device:capslock', label: 'Caps Lock' },
        detail: DETAIL.caps(run.length, avg),
        evidence: run.map((r) => r.o),
      });
      for (const r of run) consumed.add(r);
    }
    i = j + 1;
  }
  const cutoff = buf.length ? buf[buf.length - 1].tsMs - th.capsWindowMs * 4 : 0;
  state.capsBuffer = buf.filter((b) => !consumed.has(b) && b.tsMs >= cutoff);
}

function ruleImageLoad(ctx, o) {
  const mods = (ctx.policy.captureStackModules ?? []).map((m) => m.toLowerCase());
  const bag = (ctx.state.__mods ??= {});
  const mod = (o.modulePath ?? '').split(/[\\/]/).pop().toLowerCase();
  if (!mods.includes(mod)) return null;
  const key = procKey(o);
  const set = (bag[key] ??= []);
  if (!set.includes(mod)) set.push(mod);
  if (set.length < 2) return null; // 단일 모듈은 신호가 아니다. 조합만 본다.
  const verdict = classify(ctx.policy, asSubject(o), ctx.platform, o.ts);
  if (verdict.allowed) return null;
  return push(ctx, {
    rule: 'R-S11-CAPTURE-STACK', grade: 'P1', signals: ['S11'], obs: o,
    subject: { kind: 'process', key, label: o.path, pid: o.pid ?? null },
    detail: DETAIL.captureStack(o, set),
  });
}

function ruleNetPosture(ctx, o) {
  let emitted = null;
  if (o.canary === true) {
    emitted = push(ctx, {
      rule: 'R-S5-CANARY-REACHED', grade: 'P1', severity: 'crit', signals: ['S5'], obs: o,
      subject: { kind: 'network', key: 'net:canary', label: '시험망 이탈' },
      detail: DETAIL.canary(),
      contexts: (o.ifaceCount ?? 1) > 1 ? ['multipleInterfaces'] : [],
    });
  }
  if (o.beacon === false) {
    // 설계서 07장 실패 모드: 학교망 장애로 40명이 동시에 빨간불이 되면 감독관이 시스템을 끈다.
    // 등급도 P2다 — 비콘 실패는 단독으로 아무 의미가 없고, 학교망 장애와 구분되지 않는다.
    push(ctx, {
      rule: 'R-S5-BEACON-MISS', grade: 'P2', severity: 'info', signals: ['S5'], obs: o,
      subject: { kind: 'network', key: 'net:beacon', label: '시험망 비콘' },
      detail: DETAIL.beaconMiss(),
    });
  }
  return emitted;
}

function ruleVm(ctx, o) {
  // 하이퍼바이저 비트는 호스트의 VBS 에서도 켜진다. 게스트 판정은 SMBIOS 를 함께 본
  // 수집기의 몫이고, 알려주지 않으면 비트로 폴백한다.
  const guest = o.vmGuestLikely ?? o.hypervisorPresent;
  if (guest !== true) return null;
  if (ctx.policy.policyNotes?.vmAllowed === true) return null;
  return push(ctx, {
    rule: 'R-S6-VM', grade: 'P1', signals: ['S6'], obs: o,
    subject: { kind: 'session', key: `session:${ctx.session.sessionId}:vm`, label: '가상머신' },
    detail: DETAIL.vm(o),
  });
}

function ruleRemote(ctx, o) {
  const verdict = classify(ctx.policy, asSubject(o), ctx.platform, o.ts);
  const d = verdict.denied ?? { id: o.matched ?? 'remote-unknown', signal: 'S6' };
  return push(ctx, {
    rule: 'R-DENY-PROCESS', grade: 'P0', severity: 'crit', signals: ['S6'], obs: o,
    subject: { kind: 'process', key: procKey(o), label: o.path, pid: o.pid ?? null },
    detail: DETAIL.remote(o, d),
  });
}

function ruleIntegrity(ctx, o) {
  const bad = o.selfSignatureValid === false || o.debuggerPresent === true ||
    Math.abs(o.clockSkewMs ?? 0) > (ctx.th.clockSkewToleranceMs ?? 30000);
  if (!bad) return null;
  // 설계서 05장 카탈로그는 S8을 P1로 둔다. 자가검증이라 P0 요건을 형식상 만족하지만,
  // 서명된 바이너리를 패치하면 무결성 검사도 함께 패치되므로 결정적이라고 말할 수 없다.
  return push(ctx, {
    rule: 'R-S8-INTEGRITY', grade: 'P1',
    severity: o.debuggerPresent === true ? 'crit' : 'warn',
    signals: ['S8'], obs: o,
    subject: { kind: 'session', key: `session:${ctx.session.sessionId}:agent`, label: '에이전트 무결성' },
    detail: DETAIL.integrity(o),
  });
}

// ── 상관 규칙 ──────────────────────────────────────────────────

function ruleLedgerCorrelation(ctx, observations, scanned, seen) {
  const { state, session } = ctx;
  if (session.ledger !== 'kernel') return; // 원장이 커널이 아니면 상관 자체가 성립하지 않는다

  // (1) 원장 우회: 화면(사용자 공간)에는 있는데 커널 실행 기록에 없다.
  for (const o of observations) {
    if (o.kind !== 'statusItem' && o.kind !== 'process') continue;
    if (o.source !== 'userspace') continue;
    const pid = o.ownerPid ?? o.pid;
    if (pid == null) continue;
    if (state.baselinePids[pid] || state.ledgerPids[pid]) continue;
    const verdict = classify(ctx.policy, asSubject(o), ctx.platform, o.ts);
    if (verdict.allowed) continue;
    push(ctx, {
      rule: 'R-CORR-LEDGER-BYPASS', grade: 'P1', severity: 'crit', signals: ['S9', 'S1'], obs: o,
      subject: { kind: 'process', key: procKey(o), label: o.ownerPath ?? o.path, pid },
      detail: DETAIL.ledgerBypass(o),
    });
  }

  // (2) 스캔 회피: 커널 기록에는 살아 있는데 사용자 공간 목록에 없다.
  if (!scanned.includes('process')) return;
  const alive = new Set((seen.process ?? []));
  // pid 오름차순으로 고정한다. JS 객체의 정수 키 순회 순서에 기대면 C# 포트와 이벤트 순서가
  // 갈리고, 순서가 갈리면 seq 와 체인 해시가 갈린다.
  const pids = Object.keys(state.ledgerPids).map(Number).sort((a, b) => a - b);
  for (const pid of pids) {
    const rec = state.ledgerPids[pid];
    if (state.ledgerExited[pid]) continue;
    const key = procKey(rec);
    if (alive.has(key)) continue;
    const verdict = classify(ctx.policy, rec, ctx.platform, session.examStartsAt);
    if (verdict.allowed) continue;
    push(ctx, {
      rule: 'R-CORR-SCAN-EVASION', grade: 'P1', severity: 'crit', signals: ['S9', 'S1'],
      obs: { ...rec, kind: 'exec', source: 'kernel', ts: lastTs(observations) ?? session.examStartsAt },
      subject: { kind: 'process', key, label: rec.path, pid },
      detail: DETAIL.scanEvasion(rec),
    });
  }
}

export { procKey, GRADE_LABEL };
