import Foundation
import EndpointSecurity
import OwlWatchCore

/// S9 · 프로세스 원장 (커널) + S10 · S11 · S12.
///
/// 설계서 05장의 코드 스케치를 구현한 것이다. macOS 가 P0 등급을 만드는 유일한 경로이며,
/// **이 저장소에서 가장 무거운 선결 조건**을 갖는다:
///
///   com.apple.developer.endpoint-security.client  ← Apple 승인 필요 (설계서 M0)
///
/// 엔타이틀먼트 없이는 es_new_client 가 ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED 로 실패한다.
/// 그때는 아무 관측도 내지 않는다 — 호출자가 사용자 공간 수집기로 폴백하고, 그러면
/// source 가 userspace 가 되어 등급이 자동으로 P1 로 내려간다. 도는 척하는 경로는 없다.
///
/// ── 구독 범위가 곧 수집 범위다 (설계서 10장)
///
/// AUTH_* 는 구독하지 않는다. 우리는 차단하는 주체가 아니라 기록하는 주체다.
/// NOTIFY_OPEN / WRITE / READDIR 같은 파일 내용 계열도 구독하지 않는다.
/// 이 목록 자체가 감사 대상이라 상수로 박아 둔다.
public final class EndpointSecurityClient {

    /// 실제로 구독하는 이벤트. 이 배열 밖의 것은 우리에게 오지 않는다.
    static let subscriptions: [es_event_type_t] = {
        var events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,        // S9 — 시험 구간의 모든 실행
            ES_EVENT_TYPE_NOTIFY_FORK,        // S9
            ES_EVENT_TYPE_NOTIFY_EXIT,        // S9 — 종료 사유는 S7 대조에 쓴다
            ES_EVENT_TYPE_NOTIFY_MMAP,        // S11 — ScreenCaptureKit 매핑
            ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,  // S12 — HID 키보드/LED
            ES_EVENT_TYPE_NOTIFY_TRACE,       // S8 — 다른 프로세스가 우리에게 붙는 것
        ]
        // S10 은 macOS 15.4+ 에서만 존재한다. 없는 버전에서는 구독 자체가 실패하므로
        // 조건부로 넣는다 — 그 기기에서는 S10 이 없다는 사실이 UI 에 표기된다.
        if #available(macOS 15.4, *) {
            events.append(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY)
        }
        return events
    }()

    /// S11 이 보는 프레임워크. 정책의 captureStackModules 와 맞춘다.
    static let captureFrameworks = ["ScreenCaptureKit", "CoreMediaIO", "AVFoundation"]

    private var client: OpaquePointer?
    private let queue = DispatchQueue(label: "owlwatch.esf", qos: .userInitiated)
    private var pending: [JSON] = []
    private let lock = NSLock()
    private let selfPid = Int(ProcessInfo.processInfo.processIdentifier)

    public private(set) var running = false
    public private(set) var failureReason: String?
    /// macOS 15.4 미만이면 S10 이 없다. UI 와 리포트가 이 사실을 말해야 한다.
    public private(set) var tccAvailable = false

    public init() {}

    public func start() -> Bool {
        var newClient: OpaquePointer?
        let result = es_new_client(&newClient) { [weak self] _, message in
            self?.handle(message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient else {
            failureReason = Self.explain(result)
            return false
        }

        var events = Self.subscriptions
        guard es_subscribe(newClient, &events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
            es_delete_client(newClient)
            failureReason = "es_subscribe 실패 — 구독 목록을 확인하라"
            return false
        }

        client = newClient
        running = true
        if #available(macOS 15.4, *) { tccAvailable = true }
        return true
    }

    public func stop() {
        guard let client else { return }
        es_unsubscribe_all(client)
        es_delete_client(client)
        self.client = nil
        running = false
    }

    /// 쌓인 관측을 가져가고 비운다. 규칙 엔진이 등급을 매긴다 — 여기서는 사실만 낸다.
    public func drain() -> [JSON] {
        lock.lock(); defer { lock.unlock() }
        let out = pending
        pending = []
        return out
    }

    private func emit(_ o: JSON) {
        lock.lock(); defer { lock.unlock() }
        pending.append(o)
    }

    // ── 메시지 처리
    //
    // ES 콜백은 커널 큐를 막는다. 여기서 해시나 서명 검증 같은 파일 I/O 를 하면
    // 메시지가 드롭되고, 드롭된 exec 은 영영 못 본다. 그래서 문자열만 뽑아 두고
    // 무거운 작업은 drain 이후로 미룬다.

    private func handle(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        let ts = Self.iso(from: msg.time)

        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let target = msg.event.exec.target.pointee
            let pid = Int(audit_token_to_pid(target.audit_token))
            if pid == selfPid { return }

            var o: [String: JSON] = [
                "kind": .string("exec"),
                "source": .string("kernel"),      // ← P0 를 만드는 유일한 지점
                "signal": .string("S9"),
                "collector": .string("endpoint-security"),
                "platform": .string("macos"),
                "ts": .string(ts),
                "pid": .int(pid),
                "ppid": .int(Int(target.ppid)),
                "path": .string(Redaction.path(Self.string(target.executable.pointee.path))),
                "platformBinary": .bool(target.is_platform_binary),
                "startedAt": .string(ts),
            ]
            // 설계서 10장: 원장은 이름·경로·해시만 남기고 인자(argv)는 저장하지 않는다.
            o["cdhash"] = .string(Self.hex(target.cdhash))
            if let signingId = Self.optionalString(target.signing_id) { o["signingId"] = .string(signingId) }
            o["teamId"] = Self.optionalString(target.team_id).map { JSON.string($0) } ?? .null
            o["signer"] = Self.optionalString(target.team_id).map { JSON.string($0) } ?? .null
            emit(.object(o))

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            let pid = Int(audit_token_to_pid(msg.process.pointee.audit_token))
            emit(.object([
                "kind": .string("process"),
                "source": .string("kernel"),
                "signal": .string("S9"),
                "collector": .string("endpoint-security"),
                "platform": .string("macos"),
                "ts": .string(ts),
                "pid": .int(pid),
                "path": .string(Redaction.path(Self.string(msg.process.pointee.executable.pointee.path))),
                "note": .string("exit"),
            ]))

        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            // S12. macOS 에서는 HID 를 여는 행위가 그대로 커널에 남는다 —
            // Windows 에는 대응 관측이 없는 비대칭 지점이다(docs/limits.md).
            let cls = Self.string(msg.event.iokit_open.user_client_class)
            let pid = Int(audit_token_to_pid(msg.process.pointee.audit_token))
            if pid == selfPid { return }
            emit(.object([
                "kind": .string("iokitOpen"),
                "source": .string("kernel"),
                "signal": .string("S12"),
                "collector": .string("endpoint-security"),
                "platform": .string("macos"),
                "ts": .string(ts),
                "pid": .int(pid),
                "path": .string(Redaction.path(Self.string(msg.process.pointee.executable.pointee.path))),
                "userClientClass": .string(cls),
            ]))

        case ES_EVENT_TYPE_NOTIFY_MMAP:
            // S11. 캡처 프레임워크를 메모리에 올린 프로세스.
            let path = Self.string(msg.event.mmap.source.pointee.path)
            guard Self.captureFrameworks.contains(where: { path.contains($0) }) else { return }
            let pid = Int(audit_token_to_pid(msg.process.pointee.audit_token))
            if pid == selfPid { return }
            emit(.object([
                "kind": .string("imageLoad"),
                "source": .string("kernel"),
                "signal": .string("S11"),
                "collector": .string("endpoint-security"),
                "platform": .string("macos"),
                "ts": .string(ts),
                "pid": .int(pid),
                "path": .string(Redaction.path(Self.string(msg.process.pointee.executable.pointee.path))),
                "modulePath": .string(path),
            ]))

        case ES_EVENT_TYPE_NOTIFY_TRACE:
            // S8. 다른 프로세스가 우리에게 디버거로 붙었다.
            let targetPid = Int(audit_token_to_pid(msg.event.trace.target.pointee.audit_token))
            guard targetPid == selfPid else { return }
            emit(.object([
                "kind": .string("agentIntegrity"),
                "source": .string("selfverify"),
                "signal": .string("S8"),
                "collector": .string("endpoint-security"),
                "platform": .string("macos"),
                "ts": .string(ts),
                "selfSignatureValid": .bool(true),
                "debuggerPresent": .bool(true),
                "clockSkewMs": .int(0),
            ]))

        default:
            if #available(macOS 15.4, *), msg.event_type == ES_EVENT_TYPE_NOTIFY_TCC_MODIFY {
                handleTccModify(msg, ts: ts)
            }
        }
    }

    @available(macOS 15.4, *)
    private func handleTccModify(_ msg: es_message_t, ts: String) {
        // S10. 시험 직전·중에 어떤 앱이 화면 기록 권한을 받았는가.
        //
        // 한계는 설계서에 이미 적혀 있다 — 엔타이틀먼트를 가진 앱은 이 이벤트를 만들지 않는다.
        // 즉 S10 이 조용하다고 해서 아무도 화면을 못 읽는다는 뜻이 아니다.
        let event = msg.event.tcc_modify
        let service = Self.string(event.service)
        guard service == "ScreenCapture" else { return }

        let identity = Self.string(event.identity)
        let allowed = event.right == ES_TCC_AUTHORIZATION_RIGHT_ALLOWED
        emit(.object([
            "kind": .string("tccGrant"),
            "source": .string("kernel"),
            "signal": .string("S10"),
            "collector": .string("endpoint-security"),
            "platform": .string("macos"),
            "ts": .string(ts),
            "service": .string(service),
            "identity": .string(identity),
            "right": .string(allowed ? "allowed" : "denied"),
        ]))
    }

    // ── 도우미

    private static func string(_ token: es_string_token_t) -> String {
        guard token.length > 0, let data = token.data else { return "" }
        return String(cString: data)
    }

    private static func optionalString(_ token: es_string_token_t) -> String? {
        let s = string(token)
        return s.isEmpty ? nil : s
    }

    private static func hex(_ cdhash: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                                      UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                                      UInt8, UInt8, UInt8, UInt8)) -> String {
        let bytes = Mirror(reflecting: cdhash).children.compactMap { $0.value as? UInt8 }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func iso(from time: timespec) -> String {
        Dates.iso(Date(timeIntervalSince1970: Double(time.tv_sec) + Double(time.tv_nsec) / 1e9))
    }

    /// 실패 이유를 조치할 수 있는 말로 바꾼다. 승인 대기가 M0 의 크리티컬 패스다.
    static func explain(_ r: es_new_client_result_t) -> String {
        switch r {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return "com.apple.developer.endpoint-security.client 엔타이틀먼트가 없다. " +
                   "Apple 승인이 선결이다(설계서 M0). 승인 전에는 L0 + 키오스크 라이트가 상한이다."
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return "전체 디스크 접근 권한이 없다. 시스템 설정 > 개인정보 보호 및 보안에서 허용해야 한다."
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return "root 로 실행되지 않았다. 시스템 확장으로 배포해야 한다."
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return "ES 클라이언트가 이미 한도까지 떠 있다. 다른 보안 도구와 충돌한다."
        default:
            return "Endpoint Security 클라이언트를 만들지 못했다 (\(r))"
        }
    }
}

/// 저장 전 축약. 설계서 10장 "실행 파일 경로(홈은 ~로 치환)".
public enum Redaction {
    private static let home = NSHomeDirectory()

    public static func path(_ raw: String) -> String {
        guard !home.isEmpty, raw.hasPrefix(home) else { return raw }
        return "~" + String(raw.dropFirst(home.count))
    }
}
