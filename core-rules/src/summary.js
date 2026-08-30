// 알림 문구.
//
// 설계서 05장 규칙: "알림 문구는 등급을 먼저 말한다" · "아이콘 모양 추정·부정행위 단정 금지" ·
// G5 "알림은 '어디 가서 무엇을 확인하라'를 말한다".
//
// 여기서 만드는 문자열은 해시 대상에 들어가므로 C# 포트와 글자 단위로 같아야 한다.

export const GRADE_LABEL = { P0: '확정', P1: '정황', P2: '참고' };

/** ts 를 세션 표준시 기준 HH:mm 으로. 언어 간 동일 결과를 위해 오프셋을 직접 더한다. */
export function formatHm(ts, tzOffsetMinutes = 540) {
  const ms = Date.parse(ts) + tzOffsetMinutes * 60000;
  const d = new Date(ms);
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  return `${hh}:${mm}`;
}

function seatLabel(session) {
  return session?.seat != null ? `좌석 ${session.seat}` : '좌석 미지정';
}

/** 미서명/미공증 등 괄호 안 부연. 근거의 성질을 먼저 적는다. */
function qualifiers(obs, extra = []) {
  const q = [...extra];
  if (obs.signed === false) q.push('미서명');
  else if (obs.notarized === false) q.push('미공증');
  else if (obs.signer) q.push(`서명자 ${obs.signer}`);
  if (obs.source === 'kernel') q.push('커널 기록');
  else if (obs.source === 'server') q.push('서버 기록');
  else if (obs.source === 'selfverify') q.push('자가검증');
  else if (obs.source === 'userspace') q.push('사용자 공간 열거');
  return q.length ? `(${q.join(', ')})` : '';
}

const HINT = {
  'R-S9-UNKNOWN-EXEC': '화면 오른쪽 위 상태 영역과 작업표시줄 확인',
  'R-DENY-PROCESS': '해당 프로그램을 종료시키고 사유 확인',
  'R-S10-SCREENCAPTURE-GRANT': '화면 기록 권한을 받은 앱이 무엇인지 학생과 함께 확인',
  'R-S12-HID-OPEN': '키보드 표시등(Caps Lock) 확인',
  'R-S13-CAPTURE-GUARD-FAIL': '즉시 좌석으로 이동. 시험 창 보호가 꺼진 상태',
  'R-S14-ATTESTATION-FAIL': '기기 신원 확인. 다른 기기의 하트비트일 수 있음',
  'R-S7-LOCKDOWN-EXIT': '평가 모드 재진입 안내',
  'R-S1-UNKNOWN-AGENT-PROC': '작업표시줄에 보이지 않는 프로그램. 실행 목록 확인',
  'R-S2-UNKNOWN-STATUS-ITEM': '화면 오른쪽 위 상태 영역 확인',
  'R-S3-CAPTURE-EXCLUDED-WINDOW': '화면에 보이는 창과 캡처 결과가 다른지 확인',
  'R-S4-CAPS-PATTERN': '키보드 Caps Lock 표시등 점멸 확인',
  'R-S11-CAPTURE-STACK': '화면 녹화·회의 앱이 켜져 있는지 확인',
  'R-S6-VM': '가상머신 사용 여부 확인. 시험 정책 고지',
  'R-S5-CANARY-REACHED': '휴대폰 테더링·핫스팟 사용 여부 확인',
  'R-S5-BEACON-MISS': '네트워크 확인(조치 아님)',
  'R-S8-INTEGRITY': '기기 상태 확인',
  'R-CORR-LEDGER-BYPASS': '실행 기록에 없는 프로그램이 화면에 있다. 좌석 확인',
  'R-CORR-SCAN-EVASION': '실행 기록에는 있으나 목록에서 숨은 프로그램. 좌석 확인',
  'R-P1-ESCALATION': '정황이 겹쳤다. 좌석 확인',
  'R-SUBJECT-CLEARED': null,
};

/**
 * @returns {string} 예) "[확정] 좌석 17 · 09:58 ~/Downloads/helper 실행(미서명, 커널 기록) → 화면 오른쪽 위 상태 영역과 작업표시줄 확인"
 */
export function buildSummary(rule, { session, obs = {}, subject = {}, detail = '', extraQualifiers = [] }) {
  const grade = GRADE_LABEL[subject.__grade] ?? '정황';
  const head = `[${grade}] ${seatLabel(session)} · ${formatHm(obs.ts ?? session?.examStartsAt, session?.tzOffsetMinutes ?? 540)}`;
  const hint = HINT[rule];
  const body = detail || `${subject.label ?? '알 수 없는 대상'} ${qualifiers(obs, extraQualifiers)}`.trim();
  return hint ? `${head} ${body} → ${hint}` : `${head} ${body}`;
}

export const DETAIL = {
  exec: (obs, q) => `${obs.path} 실행${q}`,
  statusItem: (obs, q) => `상태 영역 항목의 소유 프로세스가 허용목록 밖 — ${obs.ownerPath}${q}`,
  agentProc: (obs, q) => `창 없이 상주하는 프로세스 ${obs.path}${q}`,
  excludedWindow: (obs, q) => `화면 캡처에서 제외된 창 — ${obs.ownerPath}${q}`,
  caps: (n, ms) => `Caps Lock이 ${ms}ms 간격으로 ${n}회 전환 — 사람의 타이핑으로 보기 어려운 주기`,
  captureStack: (obs, mods) => `화면 캡처 모듈 ${mods.join(', ')} 로드 — ${obs.path}`,
  vm: (obs) => `가상머신 안에서 응시 중${obs.vendor ? ` (${obs.vendor})` : ''} — 이 시험은 VM 응시를 금지한다`,
  remote: (obs, d) => `원격제어 도구로 분류된 프로세스 실행 — ${obs.path} [${d.id}]`,
  canary: () => '시험망 밖 목적지에 연결됨 — 테더링·핫스팟으로 시험망을 우회한 상태',
  beaconMiss: () => '시험망 비콘에 도달하지 못함 — 네트워크 확인 필요(조치 아님)',
  tcc: (obs) => `화면 기록 권한이 허용됨 — 대상 ${obs.identity}`,
  hid: (obs) => `키보드 HID 장치를 연 프로세스 — ${obs.path ?? `pid ${obs.pid}`} (${obs.userClientClass})`,
  guardFail: (obs) =>
    !obs.windowAffinityOk
      ? '시험 창의 캡처 제외 설정이 되돌려짐 — 누군가 보호를 껐다'
      : '시험 창 캡처 결과에 내용이 보임 — 캡처 차단이 무력화됐다',
  attestFail: () => '하트비트 서명 검증 실패 — 등록된 기기 키로 서명되지 않았다',
  lockdownExit: (obs) => `평가 모드(${obs.mode})에서 이탈 — 시험 시간 중 락다운이 풀렸다`,
  integrity: (obs) =>
    obs.debuggerPresent ? '에이전트에 디버거가 부착됨'
    : obs.selfSignatureValid === false ? '에이전트 자기 서명 검증 실패'
    : `시계 편차 ${obs.clockSkewMs}ms`,
  ledgerBypass: (obs) => `화면에는 있으나 커널 실행 기록에 없는 프로세스 — ${obs.ownerPath ?? obs.path}`,
  scanEvasion: (obs) => `커널 기록에는 살아 있으나 프로세스 목록에서 보이지 않음 — ${obs.path}`,
  escalation: (label, rules) => `${label} 에 정황 ${rules.length}건이 겹침 — ${rules.join(', ')}`,
  cleared: (label) => `${label} 이(가) 사라짐 — 상태 변화 기록`,
};
