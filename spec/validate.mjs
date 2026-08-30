#!/usr/bin/env node
// 스펙 검증기 — 정책·픽스처가 스키마를 실제로 지키는지 본다.
//
//   node spec/validate.mjs
//
// 의존성 없이 이 저장소가 쓰는 JSON Schema 부분집합만 구현한다:
// type · required · enum · pattern · items · properties · additionalProperties ·
// anyOf · minimum · minItems · $ref(로컬 $id 사이).
//
// 왜 만드는가. school-common.json 에 설명용 항목을 끼워 넣었다가 additionalProperties:false 를
// 어겼는데 아무것도 실패하지 않았다 — 로더가 모르는 키를 조용히 무시했기 때문이다.
// 스펙이 강제되지 않으면 스펙이 아니라 주석이다.

import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const read = (p) => JSON.parse(readFileSync(p, 'utf8'));

const SCHEMAS = {};
for (const f of readdirSync(HERE).filter((f) => f.endsWith('.schema.json'))) {
  const s = read(join(HERE, f));
  SCHEMAS[s.$id] = s;
  SCHEMAS[f] = s;
}

function validate(value, schema, path = '$', errors = []) {
  if (schema.$ref) {
    const target = SCHEMAS[schema.$ref];
    if (!target) { errors.push(`${path}: 알 수 없는 $ref ${schema.$ref}`); return errors; }
    return validate(value, target, path, errors);
  }

  if (schema.enum && !schema.enum.includes(value)) {
    errors.push(`${path}: ${JSON.stringify(value)} 는 허용값이 아니다 (${schema.enum.join(' | ')})`);
    return errors;
  }

  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual =
      value === null ? 'null'
      : Array.isArray(value) ? 'array'
      : Number.isInteger(value) ? 'integer'
      : typeof value === 'number' ? 'number'
      : typeof value;
    const ok = types.some((t) => t === actual || (t === 'number' && actual === 'integer'));
    if (!ok) { errors.push(`${path}: 타입이 ${actual} 인데 ${types.join('|')} 이어야 한다`); return errors; }
  }

  if (typeof value === 'string' && schema.pattern && !new RegExp(schema.pattern).test(value))
    errors.push(`${path}: "${value}" 가 패턴 ${schema.pattern} 에 맞지 않는다`);

  if (typeof value === 'number' && schema.minimum !== undefined && value < schema.minimum)
    errors.push(`${path}: ${value} < 최소 ${schema.minimum}`);

  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems)
      errors.push(`${path}: 원소 ${value.length}개 < 최소 ${schema.minItems}`);
    if (schema.items) value.forEach((v, i) => validate(v, schema.items, `${path}[${i}]`, errors));
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const r of schema.required ?? [])
      if (!(r in value)) errors.push(`${path}: 필수 키 "${r}" 가 없다`);

    for (const [k, v] of Object.entries(value)) {
      const sub = schema.properties?.[k];
      if (sub) validate(v, sub, `${path}.${k}`, errors);
      else if (schema.additionalProperties === false)
        errors.push(`${path}: 스키마에 없는 키 "${k}" — additionalProperties:false`);
    }

    if (schema.anyOf) {
      const ok = schema.anyOf.some((s) => validate(value, s, path, []).length === 0);
      if (!ok) errors.push(`${path}: anyOf 중 어느 것도 만족하지 않는다`);
    }
  }

  return errors;
}

let failed = 0;
const check = (label, value, schema) => {
  const errs = validate(value, schema);
  if (errs.length) {
    failed++;
    console.error(`✗ ${label}`);
    for (const e of errs.slice(0, 12)) console.error(`    ${e}`);
    if (errs.length > 12) console.error(`    … 외 ${errs.length - 12}건`);
  } else {
    console.log(`✓ ${label}`);
  }
};

// 정책 파일
for (const f of readdirSync(join(HERE, 'policy')).filter((f) => f.endsWith('.json')))
  check(`policy/${f}`, read(join(HERE, 'policy', f)), SCHEMAS['policy.schema.json']);

// 픽스처의 관측
const obsSchema = SCHEMAS['observation.schema.json'];
for (const f of readdirSync(join(HERE, 'fixtures')).filter((f) => f.endsWith('.json'))) {
  const fx = read(join(HERE, 'fixtures', f));
  const errors = [];
  (fx.steps ?? []).forEach((step, si) =>
    (step.observations ?? []).forEach((o, oi) =>
      validate(o, obsSchema, `steps[${si}].observations[${oi}]`, errors)));
  if (errors.length) {
    failed++;
    console.error(`✗ fixtures/${f}`);
    for (const e of errors.slice(0, 12)) console.error(`    ${e}`);
    if (errors.length > 12) console.error(`    … 외 ${errors.length - 12}건`);
  } else {
    console.log(`✓ fixtures/${f}  관측 ${(fx.steps ?? []).reduce((n, s) => n + (s.observations?.length ?? 0), 0)}건`);
  }
}

// 신호 카탈로그와 규칙 엔진이 같은 등급을 말하는가
const signals = read(join(HERE, 'signals.json'));
const engine = readFileSync(join(HERE, '..', 'core-rules', 'src', 'engine.js'), 'utf8');
for (const s of signals.signals) {
  if (!engine.includes(`'${s.id}'`) && !engine.includes(`"${s.id}"`)) {
    const where = Object.entries(s.status ?? {}).map(([k, v]) => `${k}: ${v}`).join(' / ');
    console.log(`· ${s.id}(${s.name}) 는 아직 규칙 엔진에 없다 — ${where || '미구현'}`);
  }
}

console.log(failed === 0 ? '\n스펙 검증 통과' : `\n${failed}건 실패`);
process.exit(failed === 0 ? 0 : 1);
