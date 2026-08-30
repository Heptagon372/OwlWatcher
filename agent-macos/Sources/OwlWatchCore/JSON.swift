import Foundation

/// 관측·이벤트를 담는 JSON 값.
///
/// Swift 의 `[String: Any]` 를 쓰지 않는 이유가 있다. JSONSerialization 은 숫자를 NSNumber 로
/// 주는데 그건 Bool 과 Int 를 구분하지 못한다 — `"signed": true` 가 `1` 이 되면 정규화 바이트가
/// 달라지고 체인 해시가 갈린다. 타입을 명시적으로 들고 다녀야 그 사고가 안 난다.
///
/// 부동소수는 아예 없다. 언어마다 표현이 갈려 해시가 어긋나기 때문에 정수만 허용한다.
public enum JSON: Equatable {
    case null
    case bool(Bool)
    case int(Int)
    case string(String)
    case array([JSON])
    case object([String: JSON])

    // ── 접근자. 없으면 nil — 없는 값을 지어내지 않는다.

    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var intValue: Int? { if case .int(let i) = self { return i }; return nil }
    public var boolValue: Bool? { if case .bool(let b) = self { return b }; return nil }
    public var arrayValue: [JSON]? { if case .array(let a) = self { return a }; return nil }
    public var objectValue: [String: JSON]? { if case .object(let o) = self { return o }; return nil }

    public subscript(key: String) -> JSON? {
        guard case .object(let o) = self else { return nil }
        return o[key]
    }

    public func str(_ key: String) -> String? { self[key]?.stringValue }
    public func int(_ key: String) -> Int? { self[key]?.intValue }
    public func bool(_ key: String) -> Bool? { self[key]?.boolValue }
    public func obj(_ key: String) -> JSON? {
        guard let v = self[key], case .object = v else { return nil }
        return v
    }

    /// 명시적 null 과 키 없음은 다르다 — 정규화에서 전자는 남고 후자는 빠진다.
    public var isNull: Bool { self == .null }
}

// ── 파싱 · 직렬화

public enum JSONError: Error, CustomStringConvertible {
    case notAnObject
    case unsupportedNumber(String)
    case parse(String)

    public var description: String {
        switch self {
        case .notAnObject: return "객체가 아닌 JSON"
        case .unsupportedNumber(let s):
            return "정규화 JSON은 정수만 허용한다 (받은 값: \(s)). 부동소수는 언어마다 표현이 갈려 체인 해시가 어긋난다."
        case .parse(let m): return "JSON 파싱 실패: \(m)"
        }
    }
}

extension JSON {
    public static func parse(_ data: Data) throws -> JSON {
        let any = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        return try from(any)
    }

    public static func parse(_ text: String) throws -> JSON {
        guard let d = text.data(using: .utf8) else { throw JSONError.parse("UTF-8 이 아니다") }
        return try parse(d)
    }

    public static func parseFile(_ path: String) throws -> JSON {
        try parse(Data(contentsOf: URL(fileURLWithPath: path)))
    }

    static func from(_ any: Any) throws -> JSON {
        switch any {
        case is NSNull:
            return .null

        case let n as NSNumber:
            // NSNumber 는 Bool 과 Int 를 같은 타입으로 담는다. CFTypeID 로만 구분된다.
            if CFGetTypeID(n) == CFBooleanGetTypeID() { return .bool(n.boolValue) }
            let d = n.doubleValue
            guard d == d.rounded(), let i = Int(exactly: d) else {
                throw JSONError.unsupportedNumber("\(n)")
            }
            return .int(i)

        case let s as String:
            return .string(s)

        case let a as [Any]:
            return .array(try a.map(from))

        case let o as [String: Any]:
            var out: [String: JSON] = [:]
            for (k, v) in o { out[k] = try from(v) }
            return .object(out)

        default:
            throw JSONError.parse("알 수 없는 타입 \(type(of: any))")
        }
    }

    /// 사람이 읽을 출력용. 해시 대상에는 절대 쓰지 않는다 — 그건 Canonical.write 다.
    public func prettyPrinted() -> String {
        Canonical.pretty(self, indent: 0)
    }
}
