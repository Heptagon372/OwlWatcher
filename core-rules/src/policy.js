// 허용목록·거부목록 판정.
//
// 설계서 05장: "허용목록 계층: OS 기본 → 학교 공용 → 강의별 → 세션 임시.
// 키는 이름이 아니라 Team ID / 인증서 주체 / cdhash."
// deny 는 allow 보다 우선한다 — 원격제어 도구가 정상 서명을 달고 있어도 금지는 금지다.

/** 여러 계층 정책을 하나로 합친다. 뒤에 오는 것이 더 좁은 범위(강의별 > 학교 공용). */
export function mergePolicies(...policies) {
  const merged = {
    id: policies.map((p) => p.id).join('+'),
    scope: policies[policies.length - 1]?.scope ?? 'school',
    version: Math.max(...policies.map((p) => p.version ?? 1)),
    allow: [],
    deny: [],
    thresholds: {},
    captureStackModules: [],
    policyNotes: {},
  };
  for (const p of policies) {
    merged.allow.push(...(p.allow ?? []));
    merged.deny.push(...(p.deny ?? []));
    Object.assign(merged.thresholds, p.thresholds ?? {});
    if (p.captureStackModules) merged.captureStackModules = p.captureStackModules;
    Object.assign(merged.policyNotes, p.policyNotes ?? {});
  }
  return merged;
}

function wildcardEq(pattern, value) {
  if (value == null) return false;
  if (pattern.endsWith('*')) {
    return value.toLowerCase().startsWith(pattern.slice(0, -1).toLowerCase());
  }
  return pattern.toLowerCase() === value.toLowerCase();
}

/**
 * 하나의 allow 항목이 대상과 맞는가. 항목에 적힌 키가 전부 맞아야 한다(AND).
 * 빈 문자열 키는 무시한다 — 초안 정책에 자리표시로 남아 있는 경우가 있다.
 */
function allowEntryMatches(entry, subject, platform, atTs) {
  if (entry.platform && entry.platform !== 'any' && entry.platform !== platform) return false;
  if (entry.expiresAt && atTs && new Date(atTs) > new Date(entry.expiresAt)) return false;

  let sawKey = false;
  for (const key of ['teamId', 'cdhash', 'sha256']) {
    if (entry[key]) {
      sawKey = true;
      if ((subject[key] ?? '').toLowerCase() !== entry[key].toLowerCase()) return false;
    }
  }
  if (entry.signer) {
    sawKey = true;
    if (!wildcardEq(entry.signer, subject.signer)) return false;
  }
  if (entry.path) {
    sawKey = true;
    if (!wildcardEq(entry.path, subject.path)) return false;
  }
  return sawKey;
}

/**
 * @param subject {{path?, sha256?, cdhash?, signer?, teamId?, signed?, platformBinary?}}
 * @returns {{allowed:boolean, layer?:string, note?:string, denied?:object}}
 */
export function classify(policy, subject, platform, atTs) {
  const name = (subject.path ?? '').toLowerCase();

  for (const d of policy.deny ?? []) {
    const m = d.match ?? {};
    const hit =
      (m.nameContains && name.includes(m.nameContains.toLowerCase())) ||
      (m.signer && wildcardEq(m.signer, subject.signer)) ||
      (m.sha256 && m.sha256.toLowerCase() === (subject.sha256 ?? '').toLowerCase());
    if (hit) return { allowed: false, denied: d };
  }

  // OS 플랫폼 바이너리는 서명 주체를 따로 보지 않아도 통과시킨다.
  // 커널이 is_platform_binary / Windows 서명 체인으로 이미 보증한 값이다.
  if (subject.platformBinary === true) {
    return { allowed: true, layer: 'os', note: 'platform binary' };
  }

  for (const e of policy.allow ?? []) {
    if (allowEntryMatches(e, subject, platform, atTs)) {
      return { allowed: true, layer: e.layer ?? 'school', note: e.note };
    }
  }
  return { allowed: false };
}

/** 미서명·미공증 등 P2 맥락. 알림을 만들지 않고 이벤트 본문에만 붙는다. */
export function p2Contexts(subject, session, thresholds) {
  const out = [];
  const p = (subject.path ?? '').replace(/\\/g, '/').toLowerCase();
  if (p.includes('/downloads/') || p.includes('/다운로드/')) out.push('downloadsPath');
  if (subject.signed === false) out.push('unsignedBinary');
  else if (subject.notarized === false) out.push('unnotarizedBinary');

  if (subject.startedAt && session?.examStartsAt) {
    const delta = new Date(session.examStartsAt) - new Date(subject.startedAt);
    const win = thresholds?.preExamContextMs ?? 900000;
    if (delta >= 0 && delta <= win) out.push('startedNearExamStart');
    if (delta < 0) out.push('startedDuringExam');
  }
  return out;
}
