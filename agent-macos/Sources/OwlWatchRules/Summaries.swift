import Foundation
import OwlWatchCore

/// 알림 문구. core-rules/src/summary.js 의 포트 — 글자 하나만 달라도 체인 해시가 갈린다.
/// 설계서 05장: 등급을 먼저 말한다 · 아이콘 모양 추정·부정행위 단정 금지 ·
/// G5 알림은 "어디 가서 무엇을 확인하라"를 말한다.
public enum Summaries {

    public static func gradeLabel(_ grade: String) -> String {
        switch grade {
        case "P0": return "확정"
        case "P2": return "참고"
        default: return "정황"
        }
    }

    /// 세션 표준시 기준 HH:mm. 오프셋을 직접 더해 언어 간 결과를 고정한다.
    public static func formatHm(_ ts: String?, _ tzOffsetMinutes: Int = 540) -> String {
        guard let ts, !ts.isEmpty, let ms = Dates.ms(ts) else { return "--:--" }
        let shifted = ms + tzOffsetMinutes * 60_000
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(secondsFromGMT: 0)!
        let d = Date(timeIntervalSince1970: Double(shifted) / 1000)
        let c = cal.dateComponents([.hour, .minute], from: d)
        return String(format: "%02d:%02d", c.hour ?? 0, c.minute ?? 0)
    }

    private static func seatLabel(_ s: SessionInfo) -> String {
        s.seat.map { "좌석 \($0)" } ?? "좌석 미지정"
    }

    private static let hints: [String: String] = [
        "R-S9-UNKNOWN-EXEC": "화면 오른쪽 위 상태 영역과 작업표시줄 확인",
        "R-DENY-PROCESS": "해당 프로그램을 종료시키고 사유 확인",
        "R-S10-SCREENCAPTURE-GRANT": "화면 기록 권한을 받은 앱이 무엇인지 학생과 함께 확인",
        "R-S12-HID-OPEN": "키보드 표시등(Caps Lock) 확인",
        "R-S13-CAPTURE-GUARD-FAIL": "즉시 좌석으로 이동. 시험 창 보호가 꺼진 상태",
        "R-S14-ATTESTATION-FAIL": "기기 신원 확인. 다른 기기의 하트비트일 수 있음",
        "R-S7-LOCKDOWN-EXIT": "평가 모드 재진입 안내",
        "R-S1-UNKNOWN-AGENT-PROC": "작업표시줄에 보이지 않는 프로그램. 실행 목록 확인",
        "R-S2-UNKNOWN-STATUS-ITEM": "화면 오른쪽 위 상태 영역 확인",
        "R-S3-CAPTURE-EXCLUDED-WINDOW": "화면에 보이는 창과 캡처 결과가 다른지 확인",
        "R-S4-CAPS-PATTERN": "키보드 Caps Lock 표시등 점멸 확인",
        "R-S11-CAPTURE-STACK": "화면 녹화·회의 앱이 켜져 있는지 확인",
        "R-S6-VM": "가상머신 사용 여부 확인. 시험 정책 고지",
        "R-S5-CANARY-REACHED": "휴대폰 테더링·핫스팟 사용 여부 확인",
        "R-S5-BEACON-MISS": "네트워크 확인(조치 아님)",
        "R-S8-INTEGRITY": "기기 상태 확인",
        "R-CORR-LEDGER-BYPASS": "실행 기록에 없는 프로그램이 화면에 있다. 좌석 확인",
        "R-CORR-SCAN-EVASION": "실행 기록에는 있으나 목록에서 숨은 프로그램. 좌석 확인",
        "R-P1-ESCALATION": "정황이 겹쳤다. 좌석 확인",
        // R-SUBJECT-CLEARED 는 힌트가 없다. 조치를 요구하지 않는 상태 변화 기록이다.
    ]

    public static func build(rule: String, session: SessionInfo, grade: String,
                            obs: JSON?, detail: String) -> String {
        let ts = obs?.str("ts") ?? session.examStartsAt
        let head = "[\(gradeLabel(grade))] \(seatLabel(session)) · \(formatHm(ts, session.tzOffsetMinutes))"
        guard let hint = hints[rule] else { return "\(head) \(detail)" }
        return "\(head) \(detail) → \(hint)"
    }

    /// engine.js 의 qual(). 근거의 성질을 괄호로 덧붙인다.
    public static func qual(_ o: JSON) -> String {
        var q: [String] = []
        if o.bool("signed") == false { q.append("미서명") }
        else if o.bool("notarized") == false { q.append("미공증") }
        else if let signer = o.str("signer"), !signer.isEmpty { q.append("서명자 \(signer)") }

        switch o.str("source") {
        case "kernel": q.append("커널 기록")
        case "selfverify": q.append("자가검증")
        case "userspace": q.append("사용자 공간 열거")
        default: break
        }
        return q.isEmpty ? "" : "(\(q.joined(separator: ", ")))"
    }

    // ── DETAIL — summary.js 의 문자열과 한 글자도 달라선 안 된다.

    public static func exec(_ o: JSON, _ q: String) -> String { "\(o.str("path") ?? "") 실행\(q)" }
    public static func statusItem(_ o: JSON, _ q: String) -> String {
        "상태 영역 항목의 소유 프로세스가 허용목록 밖 — \(o.str("ownerPath") ?? "")\(q)"
    }
    public static func agentProc(_ o: JSON, _ q: String) -> String { "창 없이 상주하는 프로세스 \(o.str("path") ?? "")\(q)" }
    public static func excludedWindow(_ o: JSON, _ q: String) -> String {
        "화면 캡처에서 제외된 창 — \(o.str("ownerPath") ?? "")\(q)"
    }
    public static func caps(_ n: Int, _ ms: Int) -> String {
        "Caps Lock이 \(ms)ms 간격으로 \(n)회 전환 — 사람의 타이핑으로 보기 어려운 주기"
    }
    public static func captureStack(_ o: JSON, _ mods: [String]) -> String {
        "화면 캡처 모듈 \(mods.joined(separator: ", ")) 로드 — \(o.str("path") ?? "")"
    }
    public static func vm(_ o: JSON) -> String {
        let v = o.str("vendor")
        let tail = (v?.isEmpty == false) ? " (\(v!))" : ""
        return "가상머신 안에서 응시 중\(tail) — 이 시험은 VM 응시를 금지한다"
    }
    public static func remote(_ o: JSON, _ denyId: String) -> String {
        "원격제어 도구로 분류된 프로세스 실행 — \(o.str("path") ?? "") [\(denyId)]"
    }
    public static func canary() -> String { "시험망 밖 목적지에 연결됨 — 테더링·핫스팟으로 시험망을 우회한 상태" }
    public static func beaconMiss() -> String { "시험망 비콘에 도달하지 못함 — 네트워크 확인 필요(조치 아님)" }
    public static func tcc(_ o: JSON) -> String { "화면 기록 권한이 허용됨 — 대상 \(o.str("identity") ?? "")" }
    public static func hid(_ o: JSON) -> String {
        let who = o.str("path") ?? "pid \(o.int("pid").map { String($0) } ?? "")"
        return "키보드 HID 장치를 연 프로세스 — \(who) (\(o.str("userClientClass") ?? ""))"
    }
    public static func guardFail(_ o: JSON) -> String {
        o.bool("windowAffinityOk") == false
            ? "시험 창의 캡처 제외 설정이 되돌려짐 — 누군가 보호를 껐다"
            : "시험 창 캡처 결과에 내용이 보임 — 캡처 차단이 무력화됐다"
    }
    public static func attestFail() -> String { "하트비트 서명 검증 실패 — 등록된 기기 키로 서명되지 않았다" }
    public static func lockdownExit(_ o: JSON) -> String {
        "평가 모드(\(o.str("mode") ?? ""))에서 이탈 — 시험 시간 중 락다운이 풀렸다"
    }
    public static func integrity(_ o: JSON) -> String {
        if o.bool("debuggerPresent") == true { return "에이전트에 디버거가 부착됨" }
        if o.bool("selfSignatureValid") == false { return "에이전트 자기 서명 검증 실패" }
        return "시계 편차 \(o.int("clockSkewMs") ?? 0)ms"
    }
    public static func ledgerBypass(_ o: JSON) -> String {
        "화면에는 있으나 커널 실행 기록에 없는 프로세스 — \(o.str("ownerPath") ?? o.str("path") ?? "")"
    }
    public static func scanEvasion(_ path: String?) -> String {
        "커널 기록에는 살아 있으나 프로세스 목록에서 보이지 않음 — \(path ?? "")"
    }
    public static func escalation(_ label: String, _ rules: [String]) -> String {
        "\(label) 에 정황 \(rules.count)건이 겹침 — \(rules.joined(separator: ", "))"
    }
    public static func cleared(_ label: String) -> String { "\(label) 이(가) 사라짐 — 상태 변화 기록" }
}
