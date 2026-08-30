using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace OwlWatch.Core;

/// <summary>
/// 정규화 JSON + 해시체인. core-rules/src/canonical.js 와 바이트 단위로 같아야 한다.
///
/// System.Text.Json 의 기본 직렬화기를 쓰지 않는 이유: .NET 은 기본으로 비ASCII를
/// \uXXXX 로 이스케이프하고 JS 는 그대로 둔다. 그대로 두면 한글이 들어간 summary 에서
/// 체인 해시가 갈리고, 패리티 테스트가 아니라 배포 후에야 드러난다.
/// </summary>
public static class Canonical
{
    public const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    public static string Write(JsonNode? node)
    {
        var sb = new StringBuilder();
        WriteTo(sb, node);
        return sb.ToString();
    }

    private static void WriteTo(StringBuilder sb, JsonNode? node)
    {
        switch (node)
        {
            case null:
                sb.Append("null");
                return;

            case JsonObject obj:
            {
                // JS: Object.keys(...).sort() 는 UTF-16 코드 단위 오름차순.
                // C#: string.CompareOrdinal 이 같은 순서를 준다.
                var keys = new List<string>();
                foreach (var kv in obj) keys.Add(kv.Key);
                keys.Sort(string.CompareOrdinal);

                sb.Append('{');
                for (int i = 0; i < keys.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    WriteString(sb, keys[i]);
                    sb.Append(':');
                    WriteTo(sb, obj[keys[i]]);
                }
                sb.Append('}');
                return;
            }

            case JsonArray arr:
            {
                sb.Append('[');
                for (int i = 0; i < arr.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    WriteTo(sb, arr[i]);
                }
                sb.Append(']');
                return;
            }

            case JsonValue val:
            {
                if (val.TryGetValue<bool>(out var b)) { sb.Append(b ? "true" : "false"); return; }
                if (val.TryGetValue<string>(out var s)) { WriteString(sb, s); return; }
                if (val.TryGetValue<long>(out var l)) { sb.Append(l.ToString(System.Globalization.CultureInfo.InvariantCulture)); return; }
                if (val.TryGetValue<int>(out var i32)) { sb.Append(i32.ToString(System.Globalization.CultureInfo.InvariantCulture)); return; }
                if (val.TryGetValue<double>(out var d))
                {
                    if (d == Math.Floor(d) && !double.IsInfinity(d))
                    {
                        sb.Append(((long)d).ToString(System.Globalization.CultureInfo.InvariantCulture));
                        return;
                    }
                    throw new InvalidOperationException(
                        $"정규화 JSON은 정수만 허용한다 (받은 값: {d}). 부동소수는 JS와 .NET의 표현이 갈려 체인 해시가 어긋난다.");
                }
                throw new InvalidOperationException($"정규화할 수 없는 값: {val.ToJsonString()}");
            }

            default:
                throw new InvalidOperationException($"정규화할 수 없는 노드: {node.GetType().Name}");
        }
    }

    /// <summary>JS canonicalString 과 동일: " \ 와 U+0020 미만만 이스케이프. 비ASCII는 원문 유지.</summary>
    private static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\t': sb.Append("\\t"); break;
                case '\n': sb.Append("\\n"); break;
                case '\f': sb.Append("\\f"); break;
                case '\r': sb.Append("\\r"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    public static string Sha256Hex(string text)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static string Sha256HexOfFile(string path)
    {
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
    }

    /// <summary>이벤트 해시. sig 와 hash 자신은 대상에서 뺀다. hashEvent() 와 동일한 필드 집합.</summary>
    public static string HashEvent(JsonObject evt)
    {
        var core = new JsonObject
        {
            ["sessionId"] = evt["sessionId"]?.DeepClone(),
            ["seq"] = evt["seq"]?.DeepClone(),
            ["ts"] = evt["ts"]?.DeepClone(),
            ["grade"] = evt["grade"]?.DeepClone(),
            ["severity"] = evt["severity"]?.DeepClone(),
            ["rule"] = evt["rule"]?.DeepClone(),
            ["signals"] = evt["signals"]?.DeepClone(),
            ["summary"] = evt["summary"]?.DeepClone(),
            ["subject"] = evt["subject"]?.DeepClone(),
            ["evidence"] = evt["evidence"]?.DeepClone(),
            ["contexts"] = evt["contexts"]?.DeepClone() ?? new JsonArray(),
            ["prevHash"] = evt["prevHash"]?.DeepClone(),
        };
        return Sha256Hex(Write(core));
    }

    public readonly record struct ChainResult(bool Ok, int BrokenAt, string Reason, string Head);

    /// <summary>체인 검증. 설계서 08장 events append-only.</summary>
    public static ChainResult VerifyChain(IEnumerable<JsonObject> events, string genesis = Genesis)
    {
        var prev = genesis;
        foreach (var e in events)
        {
            var seq = e["seq"]?.GetValue<int>() ?? -1;
            if ((e["prevHash"]?.GetValue<string>() ?? "") != prev)
                return new ChainResult(false, seq, "prevHash 불일치", prev);
            if (HashEvent(e) != (e["hash"]?.GetValue<string>() ?? ""))
                return new ChainResult(false, seq, "hash 불일치(내용 변조)", prev);
            prev = e["hash"]!.GetValue<string>();
        }
        return new ChainResult(true, 0, "", prev);
    }
}
