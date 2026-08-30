import Foundation
import AppKit
import CoreGraphics
import Security
import OwlWatchCore

/// S1 · S2 · S3 · S4 — 사용자 공간 수집기.
///
/// 이 관측들의 source 는 전부 `userspace` 다. 규칙 엔진이 그것만 보고 등급 상한을 P1 로 정한다.
/// 수집기가 등급을 주장하지 않는 것이 이 설계의 요점이다.
public enum UserspaceCollectors {

    // ── S1 · 허용목록 밖 에이전트형 프로세스
    //
    // macOS 는 답이 명확하다. NSWorkspace 가 activationPolicy 를 준다 —
    // .accessory 는 Dock 에 안 뜨는 상태 항목 앱, .prohibited 는 UI 가 없는 앱.
    // Windows 에는 대응 개념이 없어 "최상위 창은 있는데 보이는 창이 없다"로 근사해야 했다.

    public static func processes(now: Date = Date()) -> [JSON] {
        let ts = Dates.iso(now)
        let selfPid = Int(ProcessInfo.processInfo.processIdentifier)
        var out: [JSON] = []

        for app in NSWorkspace.shared.runningApplications {
            let pid = Int(app.processIdentifier)
            if pid == selfPid { continue }
            guard let url = app.bundleURL ?? app.executableURL else { continue }
            let path = url.path

            let agentLike = app.activationPolicy != .regular
            let sig = CodeSigning.of(path)

            var o: [String: JSON] = [
                "kind": .string("process"),
                "source": .string("userspace"),
                "signal": .string("S1"),
                "collector": .string("nsworkspace"),
                "platform": .string("macos"),
                "ts": .string(ts),
                "pid": .int(pid),
                "path": .string(Redaction.path(path)),
                "signed": .bool(sig.valid),
                "platformBinary": .bool(sig.platformBinary),
                "hasVisibleWindow": .bool(app.activationPolicy == .regular),
                "agentLike": .bool(agentLike),
            ]
            o["teamId"] = sig.teamId.map { JSON.string($0) } ?? .null
            o["signer"] = sig.teamId.map { JSON.string($0) } ?? .null
            if let cdhash = sig.cdhash { o["cdhash"] = .string(cdhash) }
            if let notarized = sig.notarized { o["notarized"] = .bool(notarized) }
            if let launched = app.launchDate { o["startedAt"] = .string(Dates.iso(launched)) }
            out.append(.object(o))
        }
        return out.sorted { ($0.int("pid") ?? 0) < ($1.int("pid") ?? 0) }
    }

    // ── S2 · 메뉴바 상태 항목의 소유 프로세스
    //
    // 설계서: 앱별 kAXExtrasMenuBarAttribute(접근성) 또는 CGWindowListCopyWindowInfo 레이어 25.
    // AX 경로는 접근성 권한이 필요하고, macOS 26 에서 상태 항목이 Control Center 로 귀속되는
    // 회귀가 보고돼 있다(설계서 14장 미결 5번 — 실기기 확인 필요).
    // 여기서는 권한이 필요 없는 CGWindowList 경로를 기본으로 쓴다.

    /// 메뉴바 상태 항목이 사는 윈도우 레이어.
    private static let statusItemLayer = 25

    public static func statusItems(processes: [JSON], now: Date = Date()) -> [JSON] {
        let ts = Dates.iso(now)
        guard let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID)
                as? [[String: Any]] else { return [] }

        let byPid = Dictionary(uniqueKeysWithValues: processes.compactMap { p -> (Int, JSON)? in
            guard let pid = p.int("pid") else { return nil }
            return (pid, p)
        })

        var seen = Set<Int>()
        var out: [JSON] = []

        for w in list {
            guard let layer = w[kCGWindowLayer as String] as? Int, layer == statusItemLayer,
                  let pid = w[kCGWindowOwnerPID as String] as? Int,
                  !seen.contains(pid) else { continue }
            seen.insert(pid)

            var o: [String: JSON] = [
                "kind": .string("statusItem"),
                "source": .string("userspace"),
                "signal": .string("S2"),
                "collector": .string("cgwindowlist-layer25"),
                "method": .string("cgwindow"),
                "platform": .string("macos"),
                "ts": .string(ts),
                "ownerPid": .int(pid),
            ]

            if let proc = byPid[pid] {
                o["ownerPath"] = .string(proc.str("path") ?? "")
                o["signed"] = .bool(proc.bool("signed") ?? false)
                o["teamId"] = proc["teamId"] ?? .null
                o["signer"] = proc["signer"] ?? .null
                if let cdhash = proc.str("cdhash") { o["cdhash"] = .string(cdhash) }
                if let started = proc.str("startedAt") { o["startedAt"] = .string(started) }
            } else {
                // 창은 있는데 프로세스 목록에 없다. 경로 없이 알림을 만들지 않는다.
                o["ownerPath"] = .string("pid \(pid)")
                o["degraded"] = .bool(true)
            }
            out.append(.object(o))
        }
        return out
    }

    // ── S3 · 캡처에서 제외된 창 (Cluely 형 오버레이)

    public static func captureExcludedWindows(processes: [JSON], selfPid: Int, now: Date = Date()) -> [JSON] {
        let ts = Dates.iso(now)
        guard let list = CGWindowListCopyWindowInfo([.optionAll, .excludeDesktopElements], kCGNullWindowID)
                as? [[String: Any]] else { return [] }

        let byPid = Dictionary(uniqueKeysWithValues: processes.compactMap { p -> (Int, JSON)? in
            guard let pid = p.int("pid") else { return nil }
            return (pid, p)
        })

        var seen = Set<Int>()
        var out: [JSON] = []

        for w in list {
            // kCGWindowSharingNone == 0 — 이 창은 다른 프로세스가 캡처할 수 없다.
            guard let sharing = w[kCGWindowSharingState as String] as? Int, sharing == 0,
                  let pid = w[kCGWindowOwnerPID as String] as? Int,
                  pid != selfPid, !seen.contains(pid) else { continue }
            seen.insert(pid)

            var o: [String: JSON] = [
                "kind": .string("captureExcludedWindow"),
                "source": .string("userspace"),
                "signal": .string("S3"),
                "collector": .string("cgwindowlist-sharingstate"),
                "platform": .string("macos"),
                "ts": .string(ts),
                "ownerPid": .int(pid),
                "affinity": .string("excludeFromCapture"),
            ]
            if let proc = byPid[pid] {
                o["ownerPath"] = .string(proc.str("path") ?? "")
                o["signed"] = .bool(proc.bool("signed") ?? false)
                o["teamId"] = proc["teamId"] ?? .null
                o["signer"] = proc["signer"] ?? .null
            } else {
                o["ownerPath"] = .string("pid \(pid)")
                o["degraded"] = .bool(true)
            }
            out.append(.object(o))
        }
        return out
    }
}

// ── S4 · Caps Lock 상태 전이
//
// 50Hz 로 상태만 읽는다. 키보드 후킹이 아니다 — 어떤 키가 눌렸는지는 알 수 없고,
// 알 수도 없어야 한다(설계서 10장 비수집 목록). 접근성 권한도 필요 없다.

public final class CapsLockCollector {
    private var transitions: [Date] = []
    private let lock = NSLock()
    private var timer: DispatchSourceTimer?
    private var last = false

    public static let pollHz = 50

    public init() {}

    public func start() {
        last = Self.currentState()
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "owlwatch.caps"))
        t.schedule(deadline: .now(), repeating: .milliseconds(1000 / Self.pollHz))
        t.setEventHandler { [weak self] in
            guard let self else { return }
            let now = Self.currentState()
            guard now != self.last else { return }
            self.last = now
            self.lock.lock(); self.transitions.append(Date()); self.lock.unlock()
        }
        t.resume()
        timer = t
    }

    public func stop() {
        timer?.cancel()
        timer = nil
    }

    private static func currentState() -> Bool {
        CGEventSource.flagsState(.hidSystemState).contains(.maskAlphaShift)
    }

    /// 쌓인 전이를 가져가고 비운다. 주기 판정은 규칙 엔진이 한다.
    public func drain() -> [JSON] {
        lock.lock()
        let batch = transitions
        transitions = []
        lock.unlock()
        guard !batch.isEmpty else { return [] }

        let state = last
        return batch.enumerated().map { index, at in
            .object([
                "kind": .string("capsTransition"),
                "source": .string("userspace"),
                "signal": .string("S4"),
                "collector": .string("cgeventsource-50hz"),
                "platform": .string("macos"),
                "ts": .string(Dates.iso(at)),
                // 전이 후 상태. 마지막 표본에서 역산한다.
                "state": .bool(((batch.count - 1 - index) % 2 == 0) == state),
            ])
        }
    }
}

// ── 코드 서명
//
// 허용목록의 키는 이름이 아니라 Team ID 다(설계서 P2). Windows 의 인증서 주체에 대응한다.

public enum CodeSigning {
    public struct Info {
        public let valid: Bool
        public let teamId: String?
        public let cdhash: String?
        public let platformBinary: Bool
        public let notarized: Bool?
    }

    private static var cache: [String: Info] = [:]
    private static let lock = NSLock()

    public static func of(_ path: String) -> Info {
        lock.lock()
        if let hit = cache[path] { lock.unlock(); return hit }
        lock.unlock()

        let info = compute(path)
        lock.lock(); cache[path] = info; lock.unlock()
        return info
    }

    private static func compute(_ path: String) -> Info {
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return Info(valid: false, teamId: nil, cdhash: nil, platformBinary: false, notarized: nil)
        }

        // 서명이 유효한지와 서명이 있는지는 다르다. 만료·변조된 서명을 허용목록에 태우면
        // "정상 서명을 단 위장"이 그대로 통과한다.
        let valid = SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess

        var infoDict: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &infoDict) == errSecSuccess,
              let dict = infoDict as? [String: Any] else {
            return Info(valid: valid, teamId: nil, cdhash: nil, platformBinary: false, notarized: nil)
        }

        let teamId = dict[kSecCodeInfoTeamIdentifier as String] as? String
        let flags = dict[kSecCodeInfoFlags as String] as? UInt32 ?? 0
        let platformBinary = (flags & 0x4000000) != 0  // kSecCodeSignatureHost 계열 플랫폼 비트
        let cdhash = (dict[kSecCodeInfoUnique as String] as? Data)?
            .map { String(format: "%02x", $0) }.joined()

        return Info(valid: valid, teamId: teamId, cdhash: cdhash,
                    platformBinary: platformBinary, notarized: nil)
    }
}
