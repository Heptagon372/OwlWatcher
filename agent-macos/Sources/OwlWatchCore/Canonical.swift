import Foundation
import CryptoKit

/// 정규화 JSON + 해시체인.
///
/// core-rules/src/canonical.js 와 agent-windows/…/Canonical.cs 의 세 번째 구현이다.
/// 셋의 출력 바이트가 같아야 spec/fixtures 의 체인 해시가 맞는다.
///
/// 언어 표준 직렬화기를 쓰지 않는 이유: JSONSerialization 은 키를 정렬하지 않고
/// (.sortedKeys 를 줘도 UTF-16 코드 단위 순서가 아니다), .NET 기본 직렬화기는 비ASCII 를
/// 이스케이프한다. 한글이 들어간 summary 하나로 세 구현이 전부 어긋난다.
public enum Canonical {

    public static let genesis = String(repeating: "0", count: 64)

    // ── 문자열 이스케이프. " \ 와 U+0020 미만만. 비ASCII는 원문 유지.

    public static func string(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{09}": out += "\\t"
            case "\u{0A}": out += "\\n"
            case "\u{0C}": out += "\\f"
            case "\u{0D}": out += "\\r"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }

    public static func write(_ value: JSON) -> String {
        switch value {
        case .null:
            return "null"
        case .bool(let b):
            return b ? "true" : "false"
        case .int(let i):
            return String(i)
        case .string(let s):
            return string(s)
        case .array(let a):
            return "[" + a.map(write).joined(separator: ",") + "]"
        case .object(let o):
            // JS: Object.keys(...).sort() 는 UTF-16 코드 단위 오름차순.
            // Swift 의 String `<` 는 유니코드 스칼라 비교라 BMP 밖 문자에서 갈린다.
            // 키는 전부 ASCII 지만, 규칙을 코드로 고정해 두는 편이 안전하다.
            let keys = o.keys.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
            let body = keys.map { string($0) + ":" + write(o[$0]!) }.joined(separator: ",")
            return "{" + body + "}"
        }
    }

    public static func sha256Hex(_ text: String) -> String {
        let digest = SHA256.hash(data: Data(text.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    public static func sha256HexOfFile(_ path: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// 이벤트 해시. sig 와 hash 자신은 대상에서 뺀다. hashEvent() 와 같은 필드 집합.
    public static func hashEvent(_ evt: JSON) -> String {
        var core: [String: JSON] = [:]
        for key in ["sessionId", "seq", "ts", "grade", "severity", "rule",
                    "signals", "summary", "subject", "evidence", "prevHash"] {
            if let v = evt[key] { core[key] = v }
        }
        core["contexts"] = evt["contexts"] ?? .array([])
        return sha256Hex(write(.object(core)))
    }

    public struct ChainResult {
        public let ok: Bool
        public let brokenAt: Int
        public let reason: String
        public let head: String
    }

    /// 체인 검증. 설계서 08장 events append-only.
    public static func verifyChain(_ events: [JSON], genesis: String = Canonical.genesis) -> ChainResult {
        var prev = genesis
        for e in events {
            let seq = e.int("seq") ?? -1
            if (e.str("prevHash") ?? "") != prev {
                return ChainResult(ok: false, brokenAt: seq, reason: "prevHash 불일치", head: prev)
            }
            if hashEvent(e) != (e.str("hash") ?? "") {
                return ChainResult(ok: false, brokenAt: seq, reason: "hash 불일치(내용 변조)", head: prev)
            }
            prev = e.str("hash")!
        }
        return ChainResult(ok: true, brokenAt: 0, reason: "", head: prev)
    }

    // ── 사람이 읽을 출력. 해시 대상이 아니다.

    static func pretty(_ value: JSON, indent: Int) -> String {
        let pad = String(repeating: "  ", count: indent)
        let padIn = String(repeating: "  ", count: indent + 1)
        switch value {
        case .array(let a) where !a.isEmpty:
            return "[\n" + a.map { padIn + pretty($0, indent: indent + 1) }.joined(separator: ",\n") + "\n\(pad)]"
        case .object(let o) where !o.isEmpty:
            let keys = o.keys.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
            return "{\n" + keys.map { padIn + string($0) + ": " + pretty(o[$0]!, indent: indent + 1) }
                .joined(separator: ",\n") + "\n\(pad)}"
        default:
            return write(value)
        }
    }
}
