// core-rules — OwlWatch 탐지 규칙의 레퍼런스 구현.
//
// 이 패키지는 시험장에서 돌지 않는다. 에이전트(C# / Swift)가 각자 포팅하고,
// spec/fixtures 의 같은 입력에서 같은 이벤트·같은 체인 해시가 나오는지로 패리티를 검증한다.
// 설계서 G3(플랫폼 패리티) · 12장 "같은 픽스처가 macOS·Windows 양쪽 수집기에서 나와야 하며,
// 등급이 어긋나면 실패로 처리한다".

export { evaluate, initialState, procKey, SOURCE_GRADE } from './src/engine.js';
export { classify, mergePolicies, p2Contexts } from './src/policy.js';
export { canonicalize, sha256Hex, hashEvent, verifyChain, GENESIS_HASH } from './src/canonical.js';
export { buildSummary, formatHm, GRADE_LABEL } from './src/summary.js';
