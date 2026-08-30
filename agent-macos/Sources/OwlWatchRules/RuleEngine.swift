import Foundation
import OwlWatchCore

/// 원장이 기록한 exec 하나. 원본 관측을 그대로 들고 있는다 —
/// path/sha256/signer 를 String 으로만 떼어 두면 "키가 없었다"와 "값이 null 이었다"를
/// 구분할 수 없고, 스캔 회피 이벤트가 그 값들을 증거로 다시 실으므로
/// 그 차이가 그대로 체인 해시 차이가 된다.
final class LedgerRec {
    let src: JSON
    init(_ src: JSON) { self.src = src }

    var path: String? { src.str("path") }
    var sha256: String? { src.str("sha256") }
    var signer: String? { src.str("signer") }

    /// {...rec, kind, source, ts} 를 재현한다. rec 는 path·sha256·signer 세 키만 갖는다.
    func synthetic(ts: String) -> JSON {
        var o: [String: JSON] = [:]
        for key in ["path", "sha256", "signer"] {
            if let v = src[key] { o[key] = v }
        }
        o["kind"] = .string("exec")
        o["source"] = .string("kernel")
        o["ts"] = .string(ts)
        return .object(o)
    }
}

public struct Counters {
    public var ledgerExecs = 0
    public var unknownProcs = 0
    public var statusItems = 0
    public var capsPatterns = 0

    public func toJSON() -> JSON {
        .object([
            "ledgerExecs": .int(ledgerExecs),
            "unknownProcs": .int(unknownProcs),
            "statusItems": .int(statusItems),
            "capsPatterns": .int(capsPatterns),
        ])
    }
}

/// 세션 하나의 누적 상태. core-rules 의 initialState() 와 같은 필드를 갖는다.
///
/// subjectOrder 가 따로 있는 이유: JS 객체는 문자열 키의 삽입 순서를 유지하지만
/// Swift Dictionary 는 순서가 없다. 에스컬레이션 이벤트의 발화 순서가 갈리면
/// seq 가 갈리고 체인 해시가 갈린다.
public final class EngineState {
    public var seq = 0
    public var prevHash = Canonical.genesis
    public var counters = Counters()

    var debounce: [String: Int] = [:]
    var subjectP1Rules: [String: [String]] = [:]
    var subjectOrder: [String] = []
    var escalated: Set<String> = []

    var ledgerPids: [Int: LedgerRec] = [:]
    var ledgerExited: Set<Int> = []
    var baselinePids: Set<Int> = []
    var baselineCaptured = false

    var presence: [String: [String]] = [:]
    var capsBuffer: [(tsMs: Int, obs: JSON)] = []
    var mods: [String: [String]] = [:]

    public init() {}

    func noteP1(_ subjectKey: String, _ rule: String) {
        if subjectP1Rules[subjectKey] == nil {
            subjectP1Rules[subjectKey] = []
            subjectOrder.append(subjectKey)
        }
        if !(subjectP1Rules[subjectKey]!.contains(rule)) {
            subjectP1Rules[subjectKey]!.append(rule)
        }
    }
}

/// 탐지 규칙 · 등급 판정. core-rules/src/engine.js 의 포트.
///
/// 순수 함수다 — 시계도, 파일도, 네트워크도 만지지 않는다. 모든 시각은 관측에서 온다.
/// 그래야 spec/fixtures 로 재현되고 다른 두 구현과 체인 해시가 맞는다(설계서 G3 · 12장).
public enum RuleEngine {

    /// 관측 출처가 등급의 상한을 정한다. 설계서 02장 "P0에는 휴리스틱을 넣지 않는다".
    public static func sourceGrade(_ source: String?) -> String {
        switch source {
        case "kernel", "server", "selfverify": return "P0"
        default: return "P1"
        }
    }

    static let hidClasses = ["IOHIDLibUserClient", "IOHIDDeviceUserClient", "AppleHIDKeyboardEventDriver"]

    public struct Result {
        public var events: [JSON] = []
        public var heartbeatSummary: JSON = .object([:])
    }

    final class Draft {
        var rule = ""
        var grade = ""
        var severity = ""
        var signals: [String] = []
        var subject: [String: JSON] = [:]
        var obs: JSON?
        var detail = ""
        var ts = ""
        var contexts: [String] = []
        var evidenceObs: [JSON] = []
        var notes: [String] = []
        var escalatedFrom: [String]?

        var subjectKey: String { subject["key"]?.stringValue ?? "" }
    }

    final class Ctx {
        let policy: Policy
        let session: SessionInfo
        let state: EngineState
        var drafts: [Draft] = []
        var seen: [String: [String]] = [:]

        init(policy: Policy, session: SessionInfo, state: EngineState) {
            self.policy = policy; self.session = session; self.state = state
        }

        func th(_ k: String, _ d: Int) -> Int { policy.th(k, d) }
        func see(_ kind: String, _ key: String) { seen[kind, default: []].append(key) }
    }

    /// engine.js procKey(). 이름이 아니라 해시가 대상의 키다.
    public static func procKey(_ o: JSON) -> String {
        if let sha = o.str("sha256"), !sha.isEmpty { return "proc:sha256:\(sha)" }
        if let cd = o.str("cdhash"), !cd.isEmpty { return "proc:cdhash:\(cd)" }
        let p = (o.str("path") ?? o.str("ownerPath") ?? "unknown")
            .replacingOccurrences(of: "\\", with: "/").lowercased()
        return "proc:path:\(p)"
    }

    static func procKey(_ r: LedgerRec) -> String {
        if let sha = r.sha256, !sha.isEmpty { return "proc:sha256:\(sha)" }
        let p = (r.path ?? "unknown").replacingOccurrences(of: "\\", with: "/").lowercased()
        return "proc:path:\(p)"
    }

    // ────────────────────────────────────────────────────────────

    public static func evaluate(observations: [JSON], scanned: [String],
                                policy: Policy, session: SessionInfo,
                                state: EngineState) -> Result {
        let ctx = Ctx(policy: policy, session: session, state: state)

        // ── 0단계 · 원장 색인
        for o in observations {
            let kind = o.str("kind")
            let source = o.str("source")
            if kind == "exec" && source == "kernel" {
                let pid = o.int("pid") ?? -1
                state.ledgerPids[pid] = LedgerRec(o)
                state.ledgerExited.remove(pid)
                state.counters.ledgerExecs += 1
            } else if kind == "exec" {
                state.counters.ledgerExecs += 1
            }
            if kind == "process" && o.str("note") == "exit" {
                state.ledgerExited.insert(o.int("pid") ?? -1)
            }
        }

        // PRECHECK 의 첫 완전열거가 기준선. 이전부터 돌던 프로세스를 "원장에 없다"는
        // 이유로 잡으면 좌석마다 오탐이 쏟아진다.
        if !state.baselineCaptured && scanned.contains("process") {
            for o in observations where o.str("kind") == "process" {
                state.baselinePids.insert(o.int("pid") ?? -1)
            }
            state.baselineCaptured = true
        }

        // ── 1단계 · 관측별 규칙
        for o in observations {
            switch o.str("kind") {
            case "exec": ruleExec(ctx, o)
            case "process": ruleProcess(ctx, o)
            case "statusItem": ruleStatusItem(ctx, o)
            case "captureExcludedWindow": ruleExcludedWindow(ctx, o)
            case "capsTransition":
                if let ts = o.str("ts"), let ms = Dates.ms(ts) {
                    state.capsBuffer.append((tsMs: ms, obs: o))
                }
            case "imageLoad": ruleImageLoad(ctx, o)
            case "iokitOpen": ruleIokitOpen(ctx, o)
            case "tccGrant": ruleTccGrant(ctx, o)
            case "netPosture": ruleNetPosture(ctx, o)
            case "procConnection": break  // 증거로만 보관
            case "vmIndicator": ruleVm(ctx, o)
            case "remoteControlProcess": ruleRemote(ctx, o)
            case "lockdownState": ruleLockdown(ctx, o)
            case "captureGuard": ruleCaptureGuard(ctx, o)
            case "agentIntegrity": ruleIntegrity(ctx, o)
            case "attestation": ruleAttestation(ctx, o)
            default: break
            }
        }

        // ── 2단계 · Caps Lock 주기
        ruleCapsPattern(ctx)

        // ── 3단계 · 원장 상관
        ruleLedgerCorrelation(ctx, observations, scanned)

        // ── 4단계 · 완전열거 대상의 소멸
        let lastTs = observations.last?.str("ts")
        for kind in scanned {
            let now = ctx.seen[kind] ?? []
            let before = state.presence[kind] ?? []
            for key in before where !now.contains(key) {
                let d = Draft()
                d.rule = "R-SUBJECT-CLEARED"
                d.grade = "P2"
                d.signals = ["S1"]
                d.subject = [
                    "kind": .string(kind == "statusItem" ? "process" : "window"),
                    "key": .string(key),
                    "label": .string(key),
                ]
                d.obs = .object(["ts": .string(lastTs ?? session.examStartsAt)])
                d.detail = Summaries.cleared(key)
                _ = push(ctx, d, severityOverride: "info", bypassDebounce: true)

                // 재등장 시 즉시 알리기 위해 디바운스를 푼다.
                for dk in state.debounce.keys where dk.hasSuffix("|" + key) {
                    state.debounce.removeValue(forKey: dk)
                }
            }
            state.presence[kind] = now
        }

        // ── 5단계 · P1 에스컬레이션
        applyEscalation(ctx)

        // ── 6단계 · 확정
        var result = Result()
        for d in ctx.drafts {
            state.seq += 1

            var evidence: [String: JSON] = ["observations": .array(d.evidenceObs)]
            if !d.notes.isEmpty { evidence["notes"] = .array(d.notes.map { .string($0) }) }
            if let esc = d.escalatedFrom { evidence["escalatedFrom"] = .array(esc.map { .string($0) }) }

            var evt: [String: JSON] = [
                "sessionId": .string(session.sessionId),
                "seq": .int(state.seq),
                "ts": .string(d.ts),
                "grade": .string(d.grade),
                "severity": .string(d.severity),
                "rule": .string(d.rule),
                "signals": .array(d.signals.map { .string($0) }),
                "summary": .string(Summaries.build(rule: d.rule, session: session,
                                                   grade: d.grade, obs: d.obs, detail: d.detail)),
                "subject": .object(d.subject),
                "evidence": .object(evidence),
                "contexts": .array(d.contexts.map { .string($0) }),
                "prevHash": .string(state.prevHash),
            ]
            let hash = Canonical.hashEvent(.object(evt))
            evt["hash"] = .string(hash)
            evt["sig"] = .null  // 에이전트가 Secure Enclave 키로 채운다 (S14)
            state.prevHash = hash
            result.events.append(.object(evt))
        }

        result.heartbeatSummary = state.counters.toJSON()
        return result
    }

    // ── 초안 등록 ────────────────────────────────────────────────

    @discardableResult
    static func push(_ ctx: Ctx, _ spec: Draft,
                     severityOverride: String? = nil, bypassDebounce: Bool = false) -> Draft? {
        let state = ctx.state
        let obs = spec.obs ?? .object([:])

        var grade = spec.grade
        if grade == "P0" {
            let cap = sourceGrade(obs.str("source"))
            let degraded = obs.bool("degraded") == true
            if cap != "P0" || degraded {
                grade = "P1"
                let src = obs.str("source") ?? "불명"
                let tail = degraded ? "(부분 실패)" : ""
                spec.notes.append(
                    "출처가 \(src)\(tail) 이므로 등급을 P0에서 P1로 낮춤. " +
                    "커널·서버·자가검증이 아닌 근거는 결정적이지 않다.")
            }
        }

        var severity = severityOverride ?? (grade == "P0" ? "crit" : grade == "P1" ? "warn" : "info")
        if grade == "P2" && severityOverride == nil { severity = "info" }

        let subjectKey = spec.subjectKey
        let tsText = !spec.ts.isEmpty ? spec.ts : (obs.str("ts") ?? ctx.session.examStartsAt)
        let tsMs = Dates.ms(tsText) ?? 0

        if !bypassDebounce {
            let dk = "\(spec.rule)|\(subjectKey)"
            if let last = state.debounce[dk], tsMs - last < ctx.th("debounceMs", 300_000) { return nil }
            state.debounce[dk] = tsMs
        }

        if grade == "P1" { state.noteP1(subjectKey, spec.rule) }

        spec.grade = grade
        spec.severity = severity
        spec.ts = tsText
        spec.obs = obs
        if spec.evidenceObs.isEmpty, obs["kind"] != nil { spec.evidenceObs = [obs] }

        ctx.drafts.append(spec)
        return spec
    }

    static func applyEscalation(_ ctx: Ctx) {
        let state = ctx.state
        let threshold = ctx.th("p1EscalationCount", 2)
        var crossed: [(String, [String])] = []

        for key in state.subjectOrder {
            guard let rules = state.subjectP1Rules[key] else { continue }
            if rules.count >= threshold && !state.escalated.contains(key) {
                state.escalated.insert(key)
                crossed.append((key, rules))
            }
        }

        for d in ctx.drafts where d.grade == "P1" && d.severity == "warn"
            && state.escalated.contains(d.subjectKey) {
            d.severity = "crit"
        }

        for (key, rules) in crossed {
            let anchor = ctx.drafts.first { $0.subjectKey == key }
            let label = anchor?.subject["label"]?.stringValue ?? key
            let d = Draft()
            d.rule = "R-P1-ESCALATION"
            d.grade = "P1"
            d.severity = "crit"
            d.signals = ["S1"]
            d.subject = ["kind": .string("process"), "key": .string(key), "label": .string(label)]
            d.detail = Summaries.escalation(label, rules)
            d.obs = anchor?.obs ?? .object([:])
            d.ts = anchor?.ts ?? ctx.session.examStartsAt
            d.escalatedFrom = rules
            ctx.drafts.append(d)
        }
    }

    static func subj(_ kind: String, _ key: String, _ label: String?, _ pid: Int?, withPid: Bool) -> [String: JSON] {
        var o: [String: JSON] = ["kind": .string(kind), "key": .string(key)]
        if let label { o["label"] = .string(label) }
        if withPid { o["pid"] = pid.map { JSON.int($0) } ?? .null }
        return o
    }

    // ── P0 규칙 ─────────────────────────────────────────────────

    static func ruleExec(_ ctx: Ctx, _ o: JSON) {
        let s = Subject.from(o)
        let v = ctx.policy.classify(s, ctx.session.platform, o.str("ts"))
        if let denied = v.denied {
            let d = Draft()
            d.rule = "R-DENY-PROCESS"; d.grade = "P0"; d.signals = [denied.signal]; d.obs = o
            d.subject = subj("process", procKey(o), o.str("path"), o.int("pid"), withPid: true)
            d.detail = Summaries.remote(o, denied.id)
            d.contexts = ctx.policy.p2Contexts(s, ctx.session)
            push(ctx, d, severityOverride: "crit")
            return
        }
        if v.allowed { return }

        let d = Draft()
        d.rule = "R-S9-UNKNOWN-EXEC"; d.grade = "P0"; d.signals = ["S9"]; d.obs = o
        d.subject = subj("process", procKey(o), o.str("path"), o.int("pid"), withPid: true)
        d.detail = Summaries.exec(o, Summaries.qual(o))
        d.contexts = ctx.policy.p2Contexts(s, ctx.session)
        push(ctx, d)
    }

    static func ruleTccGrant(_ ctx: Ctx, _ o: JSON) {
        guard o.str("service") == "ScreenCapture", o.str("right") == "allowed" else { return }
        let identity = o.str("identity")
        let v = ctx.policy.classify(Subject(path: identity, signer: identity),
                                    ctx.session.platform, o.str("ts"))
        if v.allowed { return }

        let d = Draft()
        d.rule = "R-S10-SCREENCAPTURE-GRANT"; d.grade = "P0"; d.signals = ["S10"]; d.obs = o
        d.subject = subj("process", "proc:path:\((identity ?? "").lowercased())", identity, nil, withPid: false)
        d.detail = Summaries.tcc(o)
        push(ctx, d)
    }

    static func ruleIokitOpen(_ ctx: Ctx, _ o: JSON) {
        let cls = o.str("userClientClass") ?? ""
        guard hidClasses.contains(where: { cls.contains($0) }) else { return }
        let v = ctx.policy.classify(Subject.from(o), ctx.session.platform, o.str("ts"))
        if v.allowed { return }

        let d = Draft()
        d.rule = "R-S12-HID-OPEN"; d.grade = "P0"; d.signals = ["S12"]; d.obs = o
        let label = o.str("path") ?? "pid \(o.int("pid").map(String.init) ?? "")"
        d.subject = subj("device", procKey(o), label, o.int("pid"), withPid: true)
        d.detail = Summaries.hid(o)
        push(ctx, d)
    }

    static func ruleCaptureGuard(_ ctx: Ctx, _ o: JSON) {
        guard o.bool("ok") == false else { return }
        let d = Draft()
        d.rule = "R-S13-CAPTURE-GUARD-FAIL"; d.grade = "P0"; d.signals = ["S13"]; d.obs = o
        d.subject = subj("guard", "guard:capture", "시험 창 캡처 보호", nil, withPid: false)
        d.detail = Summaries.guardFail(o)
        push(ctx, d)
    }

    static func ruleLockdown(_ ctx: Ctx, _ o: JSON) {
        guard o.str("mode") != "none", o.bool("active") == false else { return }
        let d = Draft()
        d.rule = "R-S7-LOCKDOWN-EXIT"; d.grade = "P0"; d.signals = ["S7"]; d.obs = o
        d.subject = subj("session", "session:\(ctx.session.sessionId)", "평가 모드", nil, withPid: false)
        d.detail = Summaries.lockdownExit(o)
        push(ctx, d)
    }

    static func ruleAttestation(_ ctx: Ctx, _ o: JSON) {
        // 소프트웨어 키 폴백은 알림이 아니라 표기다. 설계서 S14: "속이지 않는다".
        guard o.bool("verified") == false else { return }
        let d = Draft()
        d.rule = "R-S14-ATTESTATION-FAIL"; d.grade = "P0"; d.signals = ["S14"]; d.obs = o
        d.subject = subj("session", "session:\(ctx.session.sessionId)", "기기 키", nil, withPid: false)
        d.detail = Summaries.attestFail()
        push(ctx, d)
    }

    // ── P1 규칙 ─────────────────────────────────────────────────

    static func ruleProcess(_ ctx: Ctx, _ o: JSON) {
        let key = procKey(o)
        ctx.see("process", key)

        // "에이전트형"의 정의는 플랫폼마다 다르므로 수집기가 답한다(agentLike).
        // 알려주지 않으면 창 가시성으로 폴백한다 — 픽스처가 이 경로를 쓴다.
        let agentLike = o.bool("agentLike") ?? (o.bool("hasVisibleWindow") == false)
        guard agentLike else { return }

        let s = Subject.from(o)
        let v = ctx.policy.classify(s, ctx.session.platform, o.str("ts"))
        if let denied = v.denied {
            let d = Draft()
            d.rule = "R-DENY-PROCESS"; d.grade = "P0"; d.signals = [denied.signal]; d.obs = o
            d.subject = subj("process", key, o.str("path"), o.int("pid"), withPid: true)
            d.detail = Summaries.remote(o, denied.id)
            push(ctx, d, severityOverride: "crit")
            return
        }
        if v.allowed { return }

        ctx.state.counters.unknownProcs += 1
        let d = Draft()
        d.rule = "R-S1-UNKNOWN-AGENT-PROC"; d.grade = "P1"; d.signals = ["S1"]; d.obs = o
        d.subject = subj("process", key, o.str("path"), o.int("pid"), withPid: true)
        d.detail = Summaries.agentProc(o, Summaries.qual(o))
        d.contexts = ctx.policy.p2Contexts(s, ctx.session)
        push(ctx, d)
    }

    static func ruleStatusItem(_ ctx: Ctx, _ o: JSON) {
        let key = procKey(o)
        ctx.see("statusItem", key)
        ctx.state.counters.statusItems += 1

        let s = Subject.from(o)
        let v = ctx.policy.classify(s, ctx.session.platform, o.str("ts"))
        if v.allowed || v.denied != nil { return }

        let d = Draft()
        d.rule = "R-S2-UNKNOWN-STATUS-ITEM"; d.grade = "P1"; d.signals = ["S2"]; d.obs = o
        d.subject = subj("process", key, o.str("ownerPath"), o.int("ownerPid"), withPid: true)
        d.detail = Summaries.statusItem(o, Summaries.qual(o))
        d.contexts = ctx.policy.p2Contexts(s, ctx.session)
        push(ctx, d)
    }

    static func ruleExcludedWindow(_ ctx: Ctx, _ o: JSON) {
        guard o.str("affinity") != "none" else { return }
        let ownerPid = o.int("ownerPid")
        if let ownerPid, ownerPid == ctx.session.agentPid { return }  // 우리 시험 창

        let key = procKey(o)
        ctx.see("captureExcludedWindow", key)

        let v = ctx.policy.classify(Subject.from(o), ctx.session.platform, o.str("ts"))
        if v.allowed { return }

        let d = Draft()
        d.rule = "R-S3-CAPTURE-EXCLUDED-WINDOW"; d.grade = "P1"; d.signals = ["S3"]; d.obs = o
        d.subject = subj("process", key, o.str("ownerPath"), ownerPid, withPid: true)
        d.detail = Summaries.excludedWindow(o, Summaries.qual(o))
        push(ctx, d)
    }

    static func ruleCapsPattern(_ ctx: Ctx) {
        let state = ctx.state
        let maxInterval = ctx.th("capsMaxIntervalMs", 300)
        let minToggles = ctx.th("capsMinTogglesInWindow", 2)
        let window = ctx.th("capsWindowMs", 1500)

        // 안정 정렬. 같은 시각 표본의 순서가 갈리면 증거 배열이 달라지고 해시가 갈린다.
        let buf = state.capsBuffer.enumerated()
            .sorted { ($0.element.tsMs, $0.offset) < ($1.element.tsMs, $1.offset) }
            .map { $0.element }

        var consumed = Set<Int>()
        var i = 0
        while i < buf.count {
            var j = i
            while j + 1 < buf.count && buf[j + 1].tsMs - buf[j].tsMs <= maxInterval { j += 1 }
            let run = Array(buf[i...j])
            let span = run.last!.tsMs - run.first!.tsMs

            if run.count >= minToggles && span <= window {
                state.counters.capsPatterns += 1
                var total = 0
                for k in 1..<run.count { total += run[k].tsMs - run[k - 1].tsMs }
                let avg = Int((Double(total) / Double(run.count - 1)).rounded())

                let d = Draft()
                d.rule = "R-S4-CAPS-PATTERN"; d.grade = "P1"; d.signals = ["S4"]; d.obs = run[0].obs
                d.subject = subj("device", "device:capslock", "Caps Lock", nil, withPid: false)
                d.detail = Summaries.caps(run.count, avg)
                d.evidenceObs = run.map { $0.obs }
                push(ctx, d)

                for k in i...j { consumed.insert(k) }
            }
            i = j + 1
        }

        let cutoff = buf.last.map { $0.tsMs - window * 4 } ?? 0
        state.capsBuffer = buf.enumerated()
            .filter { !consumed.contains($0.offset) && $0.element.tsMs >= cutoff }
            .map { $0.element }
    }

    static func ruleImageLoad(_ ctx: Ctx, _ o: JSON) {
        let mods = ctx.policy.captureStackModules.map { $0.lowercased() }
        let modulePath = o.str("modulePath") ?? ""
        let mod = modulePath.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last.map(String.init)?.lowercased() ?? ""
        guard mods.contains(mod) else { return }

        let key = procKey(o)
        if ctx.state.mods[key] == nil { ctx.state.mods[key] = [] }
        if !ctx.state.mods[key]!.contains(mod) { ctx.state.mods[key]!.append(mod) }
        guard ctx.state.mods[key]!.count >= 2 else { return }  // 단일 모듈은 신호가 아니다

        let v = ctx.policy.classify(Subject.from(o), ctx.session.platform, o.str("ts"))
        if v.allowed { return }

        let d = Draft()
        d.rule = "R-S11-CAPTURE-STACK"; d.grade = "P1"; d.signals = ["S11"]; d.obs = o
        d.subject = subj("process", key, o.str("path"), o.int("pid"), withPid: true)
        d.detail = Summaries.captureStack(o, ctx.state.mods[key]!)
        push(ctx, d)
    }

    static func ruleNetPosture(_ ctx: Ctx, _ o: JSON) {
        if o.bool("canary") == true {
            let d = Draft()
            d.rule = "R-S5-CANARY-REACHED"; d.grade = "P1"; d.signals = ["S5"]; d.obs = o
            d.subject = subj("network", "net:canary", "시험망 이탈", nil, withPid: false)
            d.detail = Summaries.canary()
            if (o.int("ifaceCount") ?? 1) > 1 { d.contexts = ["multipleInterfaces"] }
            push(ctx, d, severityOverride: "crit")
        }

        if o.bool("beacon") == false {
            // 설계서 07장 실패 모드: 학교망 장애로 40명이 동시에 빨간불이 되면 감독관이 시스템을 끈다.
            let d = Draft()
            d.rule = "R-S5-BEACON-MISS"; d.grade = "P2"; d.signals = ["S5"]; d.obs = o
            d.subject = subj("network", "net:beacon", "시험망 비콘", nil, withPid: false)
            d.detail = Summaries.beaconMiss()
            push(ctx, d, severityOverride: "info")
        }
    }

    static func ruleVm(_ ctx: Ctx, _ o: JSON) {
        // 하이퍼바이저 비트는 호스트의 가상화 기능에서도 켜진다. 게스트 판정은 수집기의 몫이다.
        let guest = o.bool("vmGuestLikely") ?? o.bool("hypervisorPresent")
        guard guest == true, !ctx.policy.vmAllowed else { return }

        let d = Draft()
        d.rule = "R-S6-VM"; d.grade = "P1"; d.signals = ["S6"]; d.obs = o
        d.subject = subj("session", "session:\(ctx.session.sessionId):vm", "가상머신", nil, withPid: false)
        d.detail = Summaries.vm(o)
        push(ctx, d)
    }

    static func ruleRemote(_ ctx: Ctx, _ o: JSON) {
        let v = ctx.policy.classify(Subject.from(o), ctx.session.platform, o.str("ts"))
        let id = v.denied?.id ?? o.str("matched") ?? "remote-unknown"
        let d = Draft()
        d.rule = "R-DENY-PROCESS"; d.grade = "P0"; d.signals = ["S6"]; d.obs = o
        d.subject = subj("process", procKey(o), o.str("path"), o.int("pid"), withPid: true)
        d.detail = Summaries.remote(o, id)
        push(ctx, d, severityOverride: "crit")
    }

    static func ruleIntegrity(_ ctx: Ctx, _ o: JSON) {
        let skew = abs(o.int("clockSkewMs") ?? 0)
        let bad = o.bool("selfSignatureValid") == false
            || o.bool("debuggerPresent") == true
            || skew > ctx.th("clockSkewToleranceMs", 30_000)
        guard bad else { return }

        // 설계서 05장 카탈로그는 S8을 P1로 둔다. 자가검증이라 형식상 P0 요건을 만족하지만,
        // 서명된 바이너리를 패치하면 무결성 검사도 함께 패치되므로 결정적이라고 말할 수 없다.
        let d = Draft()
        d.rule = "R-S8-INTEGRITY"; d.grade = "P1"; d.signals = ["S8"]; d.obs = o
        d.subject = subj("session", "session:\(ctx.session.sessionId):agent", "에이전트 무결성", nil, withPid: false)
        d.detail = Summaries.integrity(o)
        push(ctx, d, severityOverride: o.bool("debuggerPresent") == true ? "crit" : "warn")
    }

    // ── 상관 규칙 ────────────────────────────────────────────────

    static func ruleLedgerCorrelation(_ ctx: Ctx, _ observations: [JSON], _ scanned: [String]) {
        let state = ctx.state
        guard ctx.session.ledger == "kernel" else { return }

        // (1) 원장 우회: 화면에는 있는데 커널 실행 기록에 없다.
        for o in observations {
            let kind = o.str("kind")
            guard kind == "statusItem" || kind == "process" else { continue }
            guard o.str("source") == "userspace" else { continue }
            guard let pid = o.int("ownerPid") ?? o.int("pid") else { continue }
            if state.baselinePids.contains(pid) || state.ledgerPids[pid] != nil { continue }

            let v = ctx.policy.classify(Subject.from(o), ctx.session.platform, o.str("ts"))
            if v.allowed { continue }

            let d = Draft()
            d.rule = "R-CORR-LEDGER-BYPASS"; d.grade = "P1"; d.signals = ["S9", "S1"]; d.obs = o
            d.subject = subj("process", procKey(o), o.str("ownerPath") ?? o.str("path"), pid, withPid: true)
            d.detail = Summaries.ledgerBypass(o)
            push(ctx, d, severityOverride: "crit")
        }

        // (2) 스캔 회피: 커널 기록에는 살아 있는데 사용자 공간 목록에 없다.
        guard scanned.contains("process") else { return }
        let alive = Set(ctx.seen["process"] ?? [])
        let lastTs = observations.last?.str("ts")

        // pid 오름차순 — 다른 두 구현과 이벤트 순서를 맞춘다.
        for pid in state.ledgerPids.keys.sorted() {
            if state.ledgerExited.contains(pid) { continue }
            let rec = state.ledgerPids[pid]!
            let key = procKey(rec)
            if alive.contains(key) { continue }

            let v = ctx.policy.classify(
                Subject(path: rec.path, sha256: rec.sha256, signer: rec.signer),
                ctx.session.platform, ctx.session.examStartsAt)
            if v.allowed { continue }

            let d = Draft()
            d.rule = "R-CORR-SCAN-EVASION"; d.grade = "P1"; d.signals = ["S9", "S1"]
            d.obs = rec.synthetic(ts: lastTs ?? ctx.session.examStartsAt)
            d.subject = subj("process", key, rec.path, pid, withPid: true)
            d.detail = Summaries.scanEvasion(rec.path)
            push(ctx, d, severityOverride: "crit")
        }
    }
}
