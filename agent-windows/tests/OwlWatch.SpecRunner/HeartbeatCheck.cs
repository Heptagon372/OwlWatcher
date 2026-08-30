using System.Text;
using System.Text.Json.Nodes;
using OwlWatch.Collectors;
using OwlWatch.Core;

namespace OwlWatch.SpecRunner;

/// <summary>
/// 하트비트 서명 상호운용 검사.
///
///   owlwatch-specrunner --heartbeat [http://127.0.0.1:8787]
///
/// 여기가 가장 조용히 깨지는 지점이다. .NET 의 ECDsa.SignData 는 DER 이 아니라
/// IEEE P1363(r||s) 로 서명을 내고, Node 의 기본 검증기는 DER 을 기대한다.
/// 맞추지 않으면 모든 하트비트가 서명 실패로 떨어지고 — 그건 S14(P0), 즉
/// "다른 기기가 대신 하트비트를 쏘고 있다"는 최고 등급 경보가 좌석마다 뜬다는 뜻이다.
///
/// 그래서 세 가지를 실제로 확인한다.
///   1) 정상 하트비트를 서버가 받아들이는가
///   2) 본문을 한 글자 바꾼 하트비트를 거부하는가 (거부 못 하면 S14 는 장식이다)
///   3) seq 를 되돌린 재생 하트비트를 거부하는가
/// </summary>
public static class HeartbeatCheck
{
    public static async Task<int> RunAsync(string baseUrl)
    {
        Console.WriteLine($"하트비트 상호운용 검사 → {baseUrl}\n");

        var workDir = Path.Combine(Path.GetTempPath(), "owlwatch-hbcheck");
        Directory.CreateDirectory(workDir);
        var sessionId = "hbcheck-" + DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        using var attest = Attestation.Create($"OwlWatch-{sessionId}", workDir);
        Console.WriteLine($"기기 키: {attest.Kind} ({attest.Provider})");
        if (attest.Kind == "sw")
            Console.WriteLine("  → TPM 을 쓸 수 없는 환경이다. 실제 배포에서는 등급이 P1 로 표기된다.\n");
        else
            Console.WriteLine("");

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        var failed = 0;

        // 등록
        var reg = new JsonObject
        {
            ["sessionId"] = sessionId,
            ["seat"] = 17,
            ["os"] = "windows",
            ["agentVersion"] = "0.2.0",
            ["hwKeyPub"] = attest.PublicKeyB64,
            ["attestation"] = attest.Kind,
            ["examTitle"] = "하트비트 상호운용 검사",
            ["level"] = "L1",
        };
        try
        {
            using var res = await http.PostAsync($"{baseUrl}/functions/v1/session/register",
                new StringContent(reg.ToJsonString(J.Compact), Encoding.UTF8, "application/json"));
            if (!res.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"✗ 등록 실패 HTTP {(int)res.StatusCode} — 목 서버가 떠 있는가?");
                return 2;
            }
            Console.WriteLine("✓ 세션 등록 · 공개키 고정");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"✗ 목 서버에 닿지 못했다: {ex.Message}");
            Console.Error.WriteLine("   node mock-server/server.mjs 를 먼저 띄워라.");
            return 2;
        }

        JsonObject Body(int seq) => new()
        {
            ["sessionId"] = sessionId,
            ["seq"] = seq,
            ["ts"] = Redaction.IsoSec(DateTimeOffset.UtcNow),
            ["state"] = "armed",
            ["posture"] = new JsonObject
            {
                ["beacon"] = true, ["canary"] = false, ["ifaces"] = 1, ["captureGuard"] = "ok",
            },
            ["summary"] = new JsonObject
            {
                ["ledgerExecs"] = 3, ["unknownProcs"] = 0, ["statusItems"] = 4, ["capsPatterns"] = 0,
            },
            ["attestation"] = attest.Kind,
            ["agentVersion"] = "0.2.0",
        };

        async Task<(int Code, string Why)> Post(JsonObject body)
        {
            using var res = await http.PostAsync($"{baseUrl}/functions/v1/heartbeat",
                new StringContent(body.ToJsonString(J.Compact), Encoding.UTF8, "application/json"));
            var text = await res.Content.ReadAsStringAsync();
            string why = "";
            try { why = J.Parse(text).Str("why") ?? J.Parse(text).Str("error") ?? ""; } catch { }
            return ((int)res.StatusCode, why);
        }

        // 1) 정상 하트비트
        var b1 = Body(1);
        b1["sig"] = attest.Sign(Canonical.Write(b1));
        var r1 = await Post(b1);
        if (r1.Code == 200) Console.WriteLine("✓ 정상 하트비트를 받아들인다 (.NET P1363 ↔ Node ieee-p1363)");
        else { failed++; Console.Error.WriteLine($"✗ 정상 하트비트가 거부됐다 — HTTP {r1.Code} {r1.Why}"); }

        // 2) 본문 변조 — 서명은 그대로 두고 내용만 바꾼다
        var b2 = Body(2);
        b2["sig"] = attest.Sign(Canonical.Write(b2));
        ((JsonObject)b2["posture"]!)["captureGuard"] = "failed"; // 보호가 깨진 사실을 지우려는 시도
        var r2 = await Post(b2);
        if (r2.Code == 401) Console.WriteLine($"✓ 변조된 본문을 거부한다 — {r2.Why} (S14 · P0)");
        else { failed++; Console.Error.WriteLine($"✗ 변조를 잡지 못했다 — HTTP {r2.Code}. 서명 검증이 무의미하다."); }

        // 3) 재생 — 이미 쓴 seq
        var b3 = Body(1);
        b3["sig"] = attest.Sign(Canonical.Write(b3));
        var r3 = await Post(b3);
        if (r3.Code == 409) Console.WriteLine($"✓ seq 재생을 거부한다 — {r3.Why}");
        else { failed++; Console.Error.WriteLine($"✗ 재생을 잡지 못했다 — HTTP {r3.Code}"); }

        // 4) 이벤트를 실은 하트비트 — 실제 흐름
        var b4 = Body(3);
        var evt = new JsonObject
        {
            ["sessionId"] = sessionId,
            ["seq"] = 1,
            ["ts"] = Redaction.IsoSec(DateTimeOffset.UtcNow),
            ["grade"] = "P0",
            ["severity"] = "crit",
            ["rule"] = "R-S13-CAPTURE-GUARD-FAIL",
            ["signals"] = J.Arr("S13"),
            ["summary"] = "[확정] 좌석 17 · 10:10 시험 창의 캡처 제외 설정이 되돌려짐 — 누군가 보호를 껐다 → 즉시 좌석으로 이동. 시험 창 보호가 꺼진 상태",
            ["subject"] = new JsonObject { ["kind"] = "guard", ["key"] = "guard:capture", ["label"] = "시험 창 캡처 보호" },
            ["evidence"] = new JsonObject { ["observations"] = new JsonArray() },
            ["contexts"] = new JsonArray(),
            ["prevHash"] = Canonical.Genesis,
        };
        evt["hash"] = Canonical.HashEvent(evt);
        evt["sig"] = null;
        b4["events"] = new JsonArray { evt };
        b4["sig"] = attest.Sign(Canonical.Write(b4));
        var r4 = await Post(b4);
        if (r4.Code == 200) Console.WriteLine("✓ 이벤트를 실은 하트비트 (한글 문구 포함 — 정규화 JSON 이 양쪽에서 같다)");
        else { failed++; Console.Error.WriteLine($"✗ 이벤트 하트비트 거부 — HTTP {r4.Code} {r4.Why}"); }

        Console.WriteLine(failed == 0 ? "\n하트비트 상호운용 통과" : $"\n{failed}건 실패");
        return failed == 0 ? 0 : 1;
    }
}
