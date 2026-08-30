import Foundation
import OwlWatchCore
import OwlWatchRules

// 패리티 테스트. 설계서 12장:
// "같은 픽스처가 macOS·Windows 양쪽 수집기에서 나와야 하며, 등급이 어긋나면 실패로 처리한다."
//
//   swift run owlwatch-specrunner [spec 경로]
//
// core-rules(JS)가 구운 spec/fixtures/*.json 의 expect 를 이 Swift 엔진이 재현하는지 본다.
// 이벤트의 규칙·등급·심각도·대상·맥락뿐 아니라 최종 체인 해시까지 맞아야 통과다 —
// 해시가 맞는다는 건 알림 문구 한 글자까지 JS·C# 구현과 같다는 뜻이다.
//
// Apple 엔타이틀먼트 없이도 오늘 돌릴 수 있는 유일한 검증이다.

func findSpecDir() -> String? {
    var dir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    for _ in 0..<8 {
        let candidate = dir.appendingPathComponent("spec/fixtures")
        if FileManager.default.fileExists(atPath: candidate.path) {
            return dir.appendingPathComponent("spec").path
        }
        dir = dir.deletingLastPathComponent()
    }
    return nil
}

/// run-fixtures.js 의 compact() 와 같은 축약형.
func compact(_ e: JSON) -> JSON {
    .object([
        "rule": .string(e.str("rule") ?? ""),
        "grade": .string(e.str("grade") ?? ""),
        "severity": .string(e.str("severity") ?? ""),
        "subjectKey": .string(e.obj("subject")?.str("key") ?? ""),
        "contexts": e["contexts"] ?? .array([]),
    ])
}

func run(fixture fx: JSON, specDir: String) throws -> (events: [JSON], chainHead: String) {
    let refs = fx["policyRefs"]?.arrayValue?.compactMap { $0.stringValue } ?? ["school-common"]
    let policy = try Policy.load(refs.map { "\(specDir)/policy/\($0).json" })
    if let ov = fx.obj("policyOverride") { policy.merge(ov) }

    let session = SessionInfo.from(fx.obj("session") ?? .object([:]))
    let state = EngineState()
    var all: [JSON] = []

    for step in fx["steps"]?.arrayValue ?? [] {
        let obs = step["observations"]?.arrayValue ?? []
        let scanned = step["scanned"]?.arrayValue?.compactMap { $0.stringValue } ?? []
        all += RuleEngine.evaluate(observations: obs, scanned: scanned,
                                   policy: policy, session: session, state: state).events
    }
    return (all, state.prevHash)
}

// ── 실행

let args = CommandLine.arguments
let specDir = args.count > 1 ? args[1] : findSpecDir()

guard let specDir else {
    FileHandle.standardError.write("spec/ 디렉터리를 찾지 못했다. 경로를 인자로 넘겨라.\n".data(using: .utf8)!)
    exit(2)
}

let fixDir = "\(specDir)/fixtures"
let files = ((try? FileManager.default.contentsOfDirectory(atPath: fixDir)) ?? [])
    .filter { $0.hasSuffix(".json") }
    .sorted()

print("spec: \(specDir)")
print("픽스처 \(files.count)건 — Swift 엔진 vs core-rules 레퍼런스\n")

var failed = 0

for name in files {
    let path = "\(fixDir)/\(name)"
    guard let fx = try? JSON.parseFile(path) else {
        failed += 1
        print("✗ \(name)  픽스처를 읽지 못했다")
        continue
    }

    guard let expect = fx.obj("expect") else {
        print("? \(name) 기대값 없음 — core-rules 에서 npm run bless")
        continue
    }

    let events: [JSON]
    let chainHead: String
    do {
        (events, chainHead) = try run(fixture: fx, specDir: specDir)
    } catch {
        failed += 1
        print("✗ \(name)\n    실행 중 예외: \(error)")
        continue
    }

    var problems: [String] = []
    let actual = events.map(compact)
    let wanted = expect["events"]?.arrayValue ?? []

    if actual.count != wanted.count {
        problems.append("이벤트 수 불일치 — 기대 \(wanted.count)건, 실제 \(actual.count)건")
    }
    for i in 0..<max(actual.count, wanted.count) {
        let a = i < actual.count ? Canonical.write(actual[i]) : "(없음)"
        let w = i < wanted.count ? Canonical.write(wanted[i]) : "(없음)"
        if a != w { problems.append("  [\(i)] 기대 \(w)\n       실제 \(a)") }
    }

    if let wantHead = expect.str("chainHead"), wantHead != chainHead {
        problems.append("""
            체인 헤드 불일치 — 알림 문구나 증거 내용이 레퍼런스와 다르다
              기대 \(wantHead)
              실제 \(chainHead)
            """)
    }

    let chain = Canonical.verifyChain(events)
    if !chain.ok { problems.append("자체 체인 검증 실패 seq=\(chain.brokenAt) (\(chain.reason))") }

    if problems.isEmpty {
        print("✓ \(name)  이벤트 \(actual.count)건  head \(String(chainHead.prefix(12)))")
    } else {
        failed += 1
        print("✗ \(name)\n    " + problems.joined(separator: "\n    "))
    }
}

print("\n\(files.count - failed)/\(files.count) 통과")
exit(failed == 0 ? 0 : 1)
