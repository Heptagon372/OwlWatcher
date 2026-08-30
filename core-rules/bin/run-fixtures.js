#!/usr/bin/env node
// 픽스처 실행기.
//
//   node bin/run-fixtures.js            검증 (CI · 기본)
//   node bin/run-fixtures.js --bless    기대값 갱신 (규칙을 의도적으로 바꿨을 때만)
//   node bin/run-fixtures.js --json     C# SpecRunner 와 대조할 정규화 결과를 stdout 으로
//
// 여기서 나온 expect.chainHead 가 agent-windows 포트의 합격선이다.

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluate, initialState } from '../src/engine.js';
import { mergePolicies } from '../src/policy.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SPEC = join(HERE, '..', '..', 'spec');
const FIXDIR = join(SPEC, 'fixtures');

const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

export function loadPolicy(refs = [], override) {
  const parts = refs.map((r) => readJson(join(SPEC, 'policy', `${r}.json`)));
  if (override) parts.push(override);
  return mergePolicies(...parts);
}

/** 픽스처 하나를 돌려 이벤트 전체와 최종 체인 헤드를 낸다. */
export function runFixture(fx) {
  const policy = loadPolicy(fx.policyRefs ?? ['school-common'], fx.policyOverride);
  const state = initialState();
  const all = [];
  for (const step of fx.steps ?? []) {
    const { events } = evaluate({
      observations: step.observations ?? [],
      scanned: step.scanned ?? [],
      policy,
      session: fx.session,
      state,
    });
    all.push(...events);
  }
  return { events: all, chainHead: state.prevHash, counters: state.counters };
}

/** 비교용 축약형 — 해시·문구 전체가 아니라 판정의 뼈대만 본다. */
export const compact = (e) => ({
  rule: e.rule,
  grade: e.grade,
  severity: e.severity,
  subjectKey: e.subject.key,
  contexts: e.contexts ?? [],
});

function main() {
  const bless = process.argv.includes('--bless');
  const asJson = process.argv.includes('--json');
  const files = readdirSync(FIXDIR).filter((f) => f.endsWith('.json')).sort();
  const report = [];
  let failed = 0;

  for (const f of files) {
    const p = join(FIXDIR, f);
    const fx = readJson(p);
    let got;
    try {
      got = runFixture(fx);
    } catch (err) {
      failed++;
      console.error(`✗ ${f}\n    실행 중 예외: ${err.message}`);
      continue;
    }
    const actual = got.events.map(compact);
    report.push({ fixture: f, events: actual, chainHead: got.chainHead, summaries: got.events.map((e) => e.summary) });

    if (bless) {
      fx.expect = { events: actual, chainHead: got.chainHead };
      writeFileSync(p, JSON.stringify(fx, null, 2) + '\n', 'utf8');
      console.log(`· ${f} 갱신 — 이벤트 ${actual.length}건, head ${got.chainHead.slice(0, 12)}`);
      continue;
    }

    const want = fx.expect;
    if (!want) { console.log(`? ${f} 기대값 없음 (--bless 로 생성)`); continue; }

    const problems = [];
    if (JSON.stringify(want.events) !== JSON.stringify(actual)) {
      problems.push('이벤트 불일치');
      const n = Math.max(want.events.length, actual.length);
      for (let i = 0; i < n; i++) {
        const w = JSON.stringify(want.events[i] ?? null);
        const a = JSON.stringify(actual[i] ?? null);
        if (w !== a) problems.push(`  [${i}] 기대 ${w}\n       실제 ${a}`);
      }
    }
    if (want.chainHead && want.chainHead !== got.chainHead) {
      problems.push(`체인 헤드 불일치\n  기대 ${want.chainHead}\n  실제 ${got.chainHead}`);
    }
    if (problems.length) { failed++; console.error(`✗ ${f}\n    ${problems.join('\n    ')}`); }
    else console.log(`✓ ${f}  이벤트 ${actual.length}건`);
  }

  if (asJson) writeFileSync(join(HERE, '..', 'fixture-report.json'), JSON.stringify(report, null, 2) + '\n', 'utf8');
  if (!bless) {
    console.log(`\n${files.length - failed}/${files.length} 통과`);
    if (failed) process.exit(1);
  }
}

// 직접 실행됐을 때만 돈다. import 로 불러 쓰는 쪽(테스트·SpecRunner 대조)에서는 조용해야 한다.
if ((process.argv[1] ?? '').endsWith('run-fixtures.js')) main();
