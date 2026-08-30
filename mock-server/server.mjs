#!/usr/bin/env node
// OwlWatch 로컬 목 서버.
//
//   node mock-server/server.mjs [--port 8787]
//
// 설계서 08장의 계약을 그대로 구현한다 — 나중에 Supabase Edge Function 으로 옮길 때
// 검증 로직이 그대로 따라가도록.
//
//   POST /functions/v1/session/register   세션 등록 (기기 공개키 고정)
//   POST /functions/v1/heartbeat          하트비트: seq 단조 · 시각 편차 ±30s · 서명 검증
//   POST /functions/v1/session/:id/arm    감독관 시작 (ARMED 진입의 정식 경로)
//   GET  /b                               시험망 비콘 — 200 + 세션 salt
//   GET  /canary                          차단돼야 하는 목적지. 여기 닿으면 시험망 밖이다.
//   GET  /                                개발용 좌석 맵 (콘솔 MVP 는 M2)
//   GET  /api/state                       상태 JSON
//
// 서명 검증이 이 서버의 핵심이다. 통과하지 못한 하트비트는 S14(P0)가 되고, 그건
// "다른 기기가 대신 하트비트를 쏘고 있다"는 뜻이다. 검증을 흉내만 내면 그 신호가 죽는다.

import { createServer } from 'node:http';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../core-rules/src/canonical.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.argv[process.argv.indexOf('--port') + 1]) || 8787;
const BEACON_SALT = 'owlwatch-dev-salt';
const CLOCK_SKEW_MS = 30_000;

/** @type {Map<string, {seat:number|null, os:string, pub:import('node:crypto').KeyObject|null, attestation:string,
 *   examTitle:string, level:string, seq:number, state:string, posture:object, summary:object,
 *   events:object[], lastSeen:number, armPending:boolean, rejects:string[]}>} */
const sessions = new Map();
const netLogs = []; // S15 의 자리. 실제로는 게이트웨이가 적재한다.

const json = (res, code, body) => {
  const text = JSON.stringify(body);
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'cache-control': 'no-store',
  });
  res.end(text);
};

const readBody = (req) =>
  new Promise((resolve, reject) => {
    let n = 0;
    const chunks = [];
    req.on('data', (c) => {
      n += c.length;
      if (n > 8 * 1024 * 1024) { reject(new Error('본문이 너무 크다')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });

/**
 * 하트비트 서명 검증.
 * 서명 대상은 sig 를 제외한 본문의 정규화 JSON이고, .NET ECDsa.SignData 는
 * DER 이 아니라 IEEE P1363(r||s) 로 낸다 — dsaEncoding 을 맞추지 않으면 전부 실패한다.
 */
function verifySignature(body, pub) {
  if (!pub) return { ok: false, why: '등록된 공개키 없음' };
  const { sig, ...rest } = body;
  if (typeof sig !== 'string') return { ok: false, why: 'sig 없음' };
  let payload;
  try { payload = canonicalize(rest); }
  catch (e) { return { ok: false, why: `정규화 실패: ${e.message}` }; }

  try {
    const ok = cryptoVerify('sha256', Buffer.from(payload, 'utf8'),
      { key: pub, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'base64'));
    return ok ? { ok: true } : { ok: false, why: '서명 불일치' };
  } catch (e) {
    return { ok: false, why: `검증 오류: ${e.message}` };
  }
}

const routes = {
  async 'POST /functions/v1/session/register'(req, res) {
    const b = await readBody(req);
    if (!b.sessionId) return json(res, 400, { error: 'sessionId 필요' });

    let pub = null;
    try {
      if (b.hwKeyPub) pub = createPublicKey({ key: Buffer.from(b.hwKeyPub, 'base64'), format: 'der', type: 'spki' });
    } catch (e) {
      return json(res, 400, { error: `공개키를 읽지 못했다: ${e.message}` });
    }

    sessions.set(b.sessionId, {
      seat: b.seat ?? null,
      os: b.os ?? 'unknown',
      pub,
      attestation: b.attestation ?? 'sw',
      ledger: b.ledger ?? 'fallback',
      examId: b.examId ?? null,
      examTitle: b.examTitle ?? '',
      level: b.level ?? 'L1',
      seq: 0,
      state: 'precheck',
      posture: {},
      summary: {},
      events: [],
      lastSeen: Date.now(),
      armPending: false,
      rejects: [],
    });
    console.log(`· 등록 ${b.sessionId} 좌석 ${b.seat ?? '-'} · ` +
      `${b.attestation === 'hw' ? 'TPM' : '소프트웨어 키'} · ` +
      `${b.ledger === 'kernel' ? '커널 원장' : '폴링 원장'}`);
    json(res, 200, { ok: true });
  },

  async 'POST /functions/v1/heartbeat'(req, res) {
    const b = await readBody(req);
    const s = sessions.get(b.sessionId);
    if (!s) return json(res, 404, { error: '등록되지 않은 세션' });

    // 1) seq 단조 증가 — 재생 공격 차단
    if (typeof b.seq !== 'number' || b.seq <= s.seq) {
      s.rejects.push(`seq 역행 ${b.seq} <= ${s.seq}`);
      return json(res, 409, { error: 'seq 는 단조 증가해야 한다', expectedAbove: s.seq });
    }

    // 2) 시각 편차 ±30s
    const skew = Math.abs(Date.now() - Date.parse(b.ts));
    if (!Number.isFinite(skew) || skew > CLOCK_SKEW_MS) {
      s.rejects.push(`시각 편차 ${Math.round(skew / 1000)}s`);
      return json(res, 400, { error: '시각 편차가 허용 범위를 넘는다', skewMs: skew });
    }

    // 3) 기기 키 서명 — 실패는 S14(P0)다
    const v = verifySignature(b, s.pub);
    if (!v.ok) {
      s.rejects.push(`서명 검증 실패: ${v.why}`);
      console.error(`✗ ${b.sessionId} 서명 검증 실패 — ${v.why}  → S14 (P0)`);
      return json(res, 401, { error: '서명 검증 실패', why: v.why, signal: 'S14', grade: 'P0' });
    }

    s.seq = b.seq;
    s.state = b.state ?? s.state;
    s.posture = b.posture ?? {};
    s.summary = b.summary ?? {};
    s.attestation = b.attestation ?? s.attestation;
    s.lastSeen = Date.now();

    if (Array.isArray(b.events) && b.events.length) {
      s.events.push(...b.events);
      for (const e of b.events) {
        const badge = e.severity === 'crit' ? '!!' : e.severity === 'warn' ? ' !' : '  ';
        console.log(`${badge} [${e.grade}] ${e.summary}`);
      }
    }

    const command = s.armPending ? 'arm' : null;
    if (command) { s.armPending = false; console.log(`· ${b.sessionId} → ARMED (감독관 시작)`); }
    json(res, 200, { ok: true, command, serverTime: new Date().toISOString() });
  },

  async 'GET /b'(req, res) {
    // 시험망 비콘. 실제 배포에서는 시험 VLAN 에서만 라우팅된다.
    json(res, 200, { ok: true, salt: BEACON_SALT, t: new Date().toISOString() });
  },

  async 'GET /canary'(req, res) {
    // 게이트웨이가 차단해야 하는 목적지. 여기에 닿았다는 것은 시험망 밖이라는 뜻이다.
    netLogs.push({ ts: new Date().toISOString(), dst: 'canary', action: 'allow' });
    json(res, 200, { reached: true, note: '이 응답을 받았다면 시험망 이그레스 정책이 적용되지 않은 것이다' });
  },

  async 'GET /api/state'(req, res) {
    const out = [];
    for (const [id, s] of sessions) {
      out.push({
        sessionId: id, seat: s.seat, os: s.os, level: s.level, examTitle: s.examTitle,
        state: Date.now() - s.lastSeen > 30_000 ? 'offline' : s.state,
        attestation: s.attestation, ledger: s.ledger, posture: s.posture, summary: s.summary,
        seq: s.seq, rejects: s.rejects.slice(-5),
        counts: {
          crit: s.events.filter((e) => e.severity === 'crit').length,
          warn: s.events.filter((e) => e.severity === 'warn').length,
          info: s.events.filter((e) => e.severity === 'info').length,
        },
        events: s.events.slice(-40),
      });
    }
    json(res, 200, { sessions: out, netLogs: netLogs.slice(-50) });
  },

  async 'GET /'(req, res) {
    const html = readFileSync(join(HERE, 'public', 'index.html'));
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': html.length });
    res.end(html);
  },
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
  const key = `${req.method} ${url.pathname}`;

  // 감독관 시작: POST /functions/v1/session/:id/arm
  const arm = url.pathname.match(/^\/functions\/v1\/session\/([^/]+)\/arm$/);
  if (req.method === 'POST' && arm) {
    const s = sessions.get(decodeURIComponent(arm[1]));
    if (!s) return json(res, 404, { error: '없는 세션' });
    s.armPending = true;
    return json(res, 200, { ok: true, note: '다음 하트비트 응답으로 arm 명령이 내려간다' });
  }

  const handler = routes[key];
  if (!handler) return json(res, 404, { error: `없는 경로: ${key}` });

  try { await handler(req, res); }
  catch (e) { json(res, 400, { error: e.message }); }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`OwlWatch 목 서버 — http://127.0.0.1:${PORT}`);
  console.log(`  좌석 맵      http://127.0.0.1:${PORT}/`);
  console.log(`  비콘         GET  /b        (시험망 안이면 닿아야 한다)`);
  console.log(`  카나리       GET  /canary   (시험망 안이면 닿으면 안 된다)`);
  console.log(`  감독관 시작  POST /functions/v1/session/<id>/arm`);
  console.log('');
  console.log('  이건 개발용이다. 인증도, 권한 분리도, RLS 도 없다 — 콘솔은 M2 다.');
});
