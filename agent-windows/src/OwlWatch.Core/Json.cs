using System.Text.Json;
using System.Text.Json.Nodes;

namespace OwlWatch.Core;

/// <summary>
/// 관측·이벤트는 POCO 가 아니라 JsonObject 로 다룬다.
/// 이유: 픽스처에서 읽은 관측을 그대로 증거에 실어야 core-rules 와 같은 바이트가 나온다.
/// POCO 로 왕복시키면 "없던 필드가 null 로 생기는" 차이가 조용히 끼어들고, 체인 해시가 갈린다.
/// </summary>
public static class J
{
    public static readonly JsonSerializerOptions Pretty = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static readonly JsonSerializerOptions Compact = new()
    {
        WriteIndented = false,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string? Str(this JsonObject? o, string key)
    {
        if (o is null) return null;
        var n = o[key];
        if (n is null) return null;
        try { return n.GetValue<string>(); } catch { return null; }
    }

    public static bool? Bool(this JsonObject? o, string key)
    {
        if (o is null) return null;
        var n = o[key];
        if (n is null) return null;
        try { return n.GetValue<bool>(); } catch { return null; }
    }

    public static int? Int(this JsonObject? o, string key)
    {
        if (o is null) return null;
        var n = o[key];
        if (n is null) return null;
        try { return n.GetValue<int>(); } catch { return null; }
    }

    public static JsonObject? Obj(this JsonObject? o, string key) => o?[key] as JsonObject;

    /// <summary>
    /// 문자열 배열. JsonValue.Create 를 명시적으로 부르는 이유가 있다 —
    /// JsonArray.Add(s) 는 제네릭 오버로드 Add&lt;T&gt; 로 잡혀 JsonValueCustomized&lt;string&gt; 를
    /// 만들고, 그건 TypeInfoResolver 없이 ToJsonString 하면 던진다. 정규화·해시는 멀쩡히
    /// 지나가고 전송·저장 단계에서만 터져서, 픽스처 테스트로는 안 잡힌다.
    /// </summary>
    public static JsonArray Arr(params string[] items) => Arr((IEnumerable<string>)items);

    public static JsonArray Arr(IEnumerable<string> items)
    {
        var a = new JsonArray();
        foreach (var s in items) a.Add(JsonValue.Create(s));
        return a;
    }

    /// <summary>
    /// BOM 없는 UTF-8. Encoding.UTF8 은 BOM 을 붙이고, 그러면 Node 의 JSON.parse 와
    /// 다른 도구들이 파일을 읽지 못한다 — spec 과 리포트를 주고받는 저장소에서는 치명적이다.
    /// </summary>
    public static readonly System.Text.UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    public static void WriteFile(string path, string content) =>
        File.WriteAllText(path, content, Utf8NoBom);

    public static JsonObject Parse(string json) =>
        JsonNode.Parse(json) as JsonObject ?? throw new InvalidDataException("객체가 아닌 JSON");

    public static JsonObject ParseFile(string path) => Parse(File.ReadAllText(path).TrimStart('﻿'));

    /// <summary>null 값은 넣지 않는다(JS 의 undefined 와 같은 취급). 명시적 null 은 SetNull 로.</summary>
    public static JsonObject Set(this JsonObject o, string key, string? v)
    {
        if (v is not null) o[key] = v;
        return o;
    }

    public static JsonObject Set(this JsonObject o, string key, bool? v)
    {
        if (v.HasValue) o[key] = v.Value;
        return o;
    }

    public static JsonObject Set(this JsonObject o, string key, int? v)
    {
        if (v.HasValue) o[key] = v.Value;
        return o;
    }

    public static JsonObject SetNull(this JsonObject o, string key)
    {
        o[key] = null;
        return o;
    }
}
