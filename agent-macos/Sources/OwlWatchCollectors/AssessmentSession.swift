import Foundation
import AutomaticAssessmentConfiguration
import AppKit
import OwlWatchCore

/// L2 · macOS 평가 모드(AAC) + S7 락다운 이탈 관측.
///
/// 설계서 06장: AEAssessmentSession 은 시스템이 Dock·메뉴바·알림·앱 전환을 막고
/// 화면 캡처를 차단하며 네트워크를 평가 앱에만 허용한다.
///
/// 선결: com.apple.developer.automatic-assessment-configuration 엔타이틀먼트를
/// Apple 에 신청·승인(SEB 가 이 방식). 승인 신청이 크리티컬 패스라 M0 에 넣는다.
///
/// **Windows 와 다른 점**: Take a Test 는 승인이 필요 없어 오늘 켤 수 있지만,
/// AAC 는 승인을 기다려야 한다. 그동안 macOS 는 키오스크 라이트(아래)로 버틴다.
public final class AssessmentSession: NSObject, AEAssessmentSessionDelegate {

    private var session: AEAssessmentSession?
    private var pending: [JSON] = []
    private let lock = NSLock()

    public private(set) var active = false
    public private(set) var failureReason: String?

    /// 이탈 사유. S7 이벤트의 증거에 들어간다.
    public private(set) var lastTerminationReason: String?

    public override init() { super.init() }

    /// 평가 모드 진입. 학생 동의와 사전 점검 통과 뒤에만 부른다(설계서 09장).
    public func begin() -> Bool {
        let configuration = AEAssessmentConfiguration()
        let s = AEAssessmentSession(configuration: configuration)
        s.delegate = self
        s.begin()
        session = s
        // begin() 은 비동기다. 실제 진입 여부는 delegate 가 알려 준다.
        return true
    }

    public func end() {
        session?.end()
        session = nil
        active = false
    }

    public func drain() -> [JSON] {
        lock.lock(); defer { lock.unlock() }
        let out = pending
        pending = []
        return out
    }

    /// S7 관측. active=false 로 바뀌면 규칙 엔진이 P0 crit 를 낸다.
    public func observe(now: Date = Date()) -> JSON {
        .object([
            "kind": .string("lockdownState"),
            "source": .string("selfverify"),
            "signal": .string("S7"),
            "collector": .string("aac-session"),
            "platform": .string("macos"),
            "ts": .string(Dates.iso(now)),
            "mode": .string("aac"),
            "active": .bool(active),
        ])
    }

    // ── AEAssessmentSessionDelegate

    public func assessmentSessionDidBegin(_ session: AEAssessmentSession) {
        active = true
        failureReason = nil
    }

    public func assessmentSession(_ session: AEAssessmentSession, failedToBeginWithError error: Error) {
        active = false
        failureReason = Self.explain(error)
    }

    public func assessmentSession(_ session: AEAssessmentSession, wasInterruptedWithError error: Error) {
        // 중단은 이탈이다. 설계서 S7: 정전·크래시와 구분하려면 원장(S9)의 종료 사유와 대조한다.
        active = false
        lastTerminationReason = error.localizedDescription
        emit(observe())
    }

    public func assessmentSessionDidEnd(_ session: AEAssessmentSession) {
        active = false
        emit(observe())
    }

    private func emit(_ o: JSON) {
        lock.lock(); defer { lock.unlock() }
        pending.append(o)
    }

    static func explain(_ error: Error) -> String {
        let ns = error as NSError
        if ns.domain == AEAssessmentErrorDomain {
            return "평가 모드에 들어가지 못했다 — 엔타이틀먼트 승인 또는 구성 문제 (\(ns.code)). " +
                   "승인 전에는 키오스크 라이트가 상한이다."
        }
        return "평가 모드 진입 실패: \(error.localizedDescription)"
    }
}

/// 승인 전 대안 — 키오스크 라이트.
///
/// 설계서 06장: "창 단위 캡처 차단은 없다 — NSWindow.sharingType = .none 은 Apple 이
/// 레거시로 규정했고 macOS 15.4+ ScreenCaptureKit 이 무시한다. **흉내 내지 않는다.**"
///
/// 그래서 이 타입은 캡처를 막는다고 말하지 않는다. Dock·메뉴바를 숨기고 앱 전환과
/// 강제 종료를 비활성화해 아이콘이 표시될 공간을 없앨 뿐이고, 차단이 아니라
/// P0 탐지(S9·S10·S12)로 같은 확신을 만든다.
public final class KioskLite {

    private var previousOptions: NSApplication.PresentationOptions?

    public init() {}

    public func enter() {
        previousOptions = NSApp.presentationOptions
        NSApp.presentationOptions = [
            .hideDock,
            .hideMenuBar,
            .disableProcessSwitching,
            .disableForceQuit,
            .disableSessionTermination,
            .disableHideApplication,
        ]
    }

    public func exit() {
        if let previousOptions { NSApp.presentationOptions = previousOptions }
        previousOptions = nil
    }

    /// 학생·감독관에게 그대로 보여 줄 문장. 할 수 없는 것을 할 수 있다고 말하지 않는다.
    public static let disclosure = """
        이 기기에서는 화면 캡처를 막지 못한다. macOS 는 창 단위 캡처 차단을 지원하지 않고,
        시스템 전체 차단(평가 모드)은 Apple 승인이 필요하다.

        대신 Dock·메뉴바를 숨기고 앱 전환을 막아 위장 아이콘이 표시될 공간을 없애며,
        시험 구간에 실행된 프로그램과 화면 기록 권한 부여를 커널 기록으로 남긴다.
        """
}
