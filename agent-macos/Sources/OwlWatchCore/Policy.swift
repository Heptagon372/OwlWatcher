import Foundation

/// 판정 대상의 신원. 이름이 아니라 해시·서명자가 키다(설계서 P2 원칙).
public struct Subject {
    public var path: String?
    public var sha256: String?
    public var cdhash: String?
    public var signer: String?
    public var teamId: String?
    public var signed: Bool?
    public var notarized: Bool?
    public var platformBinary: Bool?
    public var startedAt: String?

    public init(path: String? = nil, sha256: String? = nil, cdhash: String? = nil,
                signer: String? = nil, teamId: String? = nil, signed: Bool? = nil,
                notarized: Bool? = nil, platformBinary: Bool? = nil, startedAt: String? = nil) {
        self.path = path; self.sha256 = sha256; self.cdhash = cdhash
        self.signer = signer; self.teamId = teamId; self.signed = signed
        self.notarized = notarized; self.platformBinary = platformBinary; self.startedAt = startedAt
    }

    /// 관측에서 판정용 신원을 뽑는다. statusItem 은 ownerPath 가 경로다.
    public static func from(_ o: JSON) -> Subject {
        Subject(
            path: o.str("path") ?? o.str("ownerPath"),
            sha256: o.str("sha256"),
            cdhash: o.str("cdhash"),
            signer: o.str("signer"),
            teamId: o.str("teamId"),
            signed: o.bool("signed"),
            notarized: o.bool("notarized"),
            platformBinary: o.bool("platformBinary"),
            startedAt: o.str("startedAt")
        )
    }
}

public struct DenyRule {
    public let id: String
    public let signal: String
    public let nameContains: String?
    public let signer: String?
    public let sha256: String?
}

public struct AllowRule {
    public let teamId: String?
    public let signer: String?
    public let cdhash: String?
    public let sha256: String?
    public let path: String?
    public let platform: String?
    public let layer: String?
    public let note: String?
    public let expiresAt: String?
}

public struct Verdict {
    public let allowed: Bool
    public let layer: String?
    public let note: String?
    public let denied: DenyRule?
}

/// 세션 문맥. 규칙 엔진은 이 값 말고 어떤 외부 상태도 읽지 않는다.
public struct SessionInfo {
    public var sessionId: String = ""
    public var seat: Int?
    public var platform: String = "macos"
    /// kernel | fallback | off. 커널 원장이 아니면 상관 규칙이 성립하지 않는다.
    public var ledger: String = "fallback"
    public var examStartsAt: String = ""
    public var examEndsAt: String = ""
    public var tzOffsetMinutes: Int = 540
    public var agentPid: Int?

    public init() {}

    public static func from(_ o: JSON) -> SessionInfo {
        var s = SessionInfo()
        s.sessionId = o.str("sessionId") ?? ""
        s.seat = o.int("seat")
        s.platform = o.str("platform") ?? "macos"
        s.ledger = o.str("ledger") ?? "fallback"
        s.examStartsAt = o.str("examStartsAt") ?? ""
        s.examEndsAt = o.str("examEndsAt") ?? ""
        s.tzOffsetMinutes = o.int("tzOffsetMinutes") ?? 540
        s.agentPid = o.int("agentPid")
        return s
    }
}

/// 허용목록·거부목록 판정. core-rules/src/policy.js 의 포트.
/// 설계서 05장: OS 기본 → 학교 공용 → 강의별 → 세션 임시. deny 는 allow 를 이긴다.
public final class Policy {
    public var id: String = ""
    public var allow: [AllowRule] = []
    public var deny: [DenyRule] = []
    public var thresholds: [String: Int] = [:]
    public var captureStackModules: [String] = []
    public var vmAllowed = false
    public var policyText: String?

    public init() {}

    public func th(_ key: String, _ fallback: Int) -> Int { thresholds[key] ?? fallback }

    public static func load(_ files: [String]) throws -> Policy {
        let p = Policy()
        p.id = files.map { URL(fileURLWithPath: $0).deletingPathExtension().lastPathComponent }
            .joined(separator: "+")
        for f in files { p.merge(try JSON.parseFile(f)) }
        return p
    }

    public func merge(_ src: JSON) {
        for n in src["allow"]?.arrayValue ?? [] {
            allow.append(AllowRule(
                teamId: n.str("teamId"), signer: n.str("signer"), cdhash: n.str("cdhash"),
                sha256: n.str("sha256"), path: n.str("path"), platform: n.str("platform"),
                layer: n.str("layer"), note: n.str("note"), expiresAt: n.str("expiresAt")))
        }
        for n in src["deny"]?.arrayValue ?? [] {
            let m = n.obj("match")
            deny.append(DenyRule(
                id: n.str("id") ?? "?", signal: n.str("signal") ?? "S6",
                nameContains: m?.str("nameContains"), signer: m?.str("signer"), sha256: m?.str("sha256")))
        }
        for (k, v) in src.obj("thresholds")?.objectValue ?? [:] {
            if let i = v.intValue { thresholds[k] = i }
        }
        if let mods = src["captureStackModules"]?.arrayValue {
            captureStackModules = mods.compactMap { $0.stringValue }
        }
        if let notes = src.obj("policyNotes") {
            vmAllowed = notes.bool("vmAllowed") ?? vmAllowed
            policyText = notes.str("text") ?? policyText
        }
    }

    private static func wildcardEq(_ pattern: String, _ value: String?) -> Bool {
        guard let value else { return false }
        if pattern.hasSuffix("*") {
            return value.lowercased().hasPrefix(String(pattern.dropLast()).lowercased())
        }
        return pattern.lowercased() == value.lowercased()
    }

    private static func keyEq(_ a: String?, _ b: String?) -> Bool {
        (a ?? "").lowercased() == (b ?? "").lowercased()
    }

    private static func matches(_ e: AllowRule, _ s: Subject, _ platform: String, _ atTs: String?) -> Bool {
        if let p = e.platform, !p.isEmpty, p != "any", p != platform { return false }
        if let exp = e.expiresAt, !exp.isEmpty, let at = atTs,
           let atDate = Dates.parse(at), let expDate = Dates.parse(exp), atDate > expDate { return false }

        var sawKey = false
        if let v = e.teamId, !v.isEmpty { sawKey = true; if !keyEq(s.teamId, v) { return false } }
        if let v = e.cdhash, !v.isEmpty { sawKey = true; if !keyEq(s.cdhash, v) { return false } }
        if let v = e.sha256, !v.isEmpty { sawKey = true; if !keyEq(s.sha256, v) { return false } }
        if let v = e.signer, !v.isEmpty { sawKey = true; if !wildcardEq(v, s.signer) { return false } }
        if let v = e.path, !v.isEmpty { sawKey = true; if !wildcardEq(v, s.path) { return false } }
        return sawKey
    }

    public func classify(_ s: Subject, _ platform: String, _ atTs: String? = nil) -> Verdict {
        let name = (s.path ?? "").lowercased()

        for d in deny {
            let hit =
                (d.nameContains.map { name.contains($0.lowercased()) } ?? false) ||
                (d.signer.map { Policy.wildcardEq($0, s.signer) } ?? false) ||
                (d.sha256.map { Policy.keyEq($0, s.sha256) } ?? false)
            if hit { return Verdict(allowed: false, layer: nil, note: nil, denied: d) }
        }

        // 커널이 is_platform_binary 로 이미 보증한 값이다.
        if s.platformBinary == true {
            return Verdict(allowed: true, layer: "os", note: "platform binary", denied: nil)
        }

        for e in allow where Policy.matches(e, s, platform, atTs) {
            return Verdict(allowed: true, layer: e.layer ?? "school", note: e.note, denied: nil)
        }
        return Verdict(allowed: false, layer: nil, note: nil, denied: nil)
    }

    /// P2 맥락. 순서까지 core-rules 와 같아야 한다 — 이벤트 본문에 그대로 들어가 해시가 된다.
    public func p2Contexts(_ s: Subject, _ session: SessionInfo) -> [String] {
        var out: [String] = []
        let p = (s.path ?? "").replacingOccurrences(of: "\\", with: "/").lowercased()
        if p.contains("/downloads/") || p.contains("/다운로드/") { out.append("downloadsPath") }
        if s.signed == false { out.append("unsignedBinary") }
        else if s.notarized == false { out.append("unnotarizedBinary") }

        if let started = s.startedAt, !started.isEmpty, !session.examStartsAt.isEmpty,
           let startedAt = Dates.parse(started), let examStart = Dates.parse(session.examStartsAt) {
            let delta = examStart.timeIntervalSince(startedAt) * 1000
            let win = Double(th("preExamContextMs", 900_000))
            if delta >= 0 && delta <= win { out.append("startedNearExamStart") }
            if delta < 0 { out.append("startedDuringExam") }
        }
        return out
    }
}

/// ISO 8601 파싱. 소수점 초가 있는 형식과 없는 형식을 모두 받는다 —
/// 픽스처가 둘 다 쓰고, 하나만 처리하면 조용히 nil 이 되어 맥락이 빠진다.
public enum Dates {
    private static let withFraction: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private static let plain: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    public static func parse(_ s: String) -> Date? {
        withFraction.date(from: s) ?? plain.date(from: s)
    }

    public static func ms(_ s: String) -> Int? {
        guard let d = parse(s) else { return nil }
        return Int((d.timeIntervalSince1970 * 1000).rounded())
    }

    public static func iso(_ d: Date) -> String { plain.string(from: d) }
}
