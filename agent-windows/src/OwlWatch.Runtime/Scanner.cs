using System.Text.Json.Nodes;
using OwlWatch.Collectors;
using OwlWatch.Core;

namespace OwlWatch.Runtime;

/// <summary>한 번의 점검 결과.</summary>
public sealed record ScanResult(
    List<JsonObject> Observations,
    List<string> Scanned,
    List<ProcInfo> Processes,
    List<string> Notes,
    TimeSpan Elapsed);

/// <summary>
/// L0 ExamCheck 의 본체 — 설치 없이 30초 안에 끝나는 점검.
///
/// 수집기는 관측만 만든다. 등급은 여기서도 매기지 않는다. 그 분리가 이 설계의 요점이고,
/// 덕분에 같은 관측을 spec/fixtures 로 얼려 두고 규칙만 따로 회귀할 수 있다(설계서 12장).
/// </summary>
public static class Scanner
{
    public static async Task<ScanResult> RunAsync(SessionConfig cfg, Policy policy, int selfPid, CancellationToken ct = default)
    {
        var started = DateTimeOffset.UtcNow;
        var obs = new List<JsonObject>();
        var notes = new List<string>();

        // 네트워크 프로브를 먼저 띄워 두고 그 사이에 프로세스를 훑는다.
        var netTask = NetworkCollector.PostureAsync(
            new NetConfig(cfg.BeaconUrl, cfg.CanaryUrl, cfg.ExpectedSalt), started);

        // S1 · 프로세스
        var processes = ProcessCollector.Snapshot();
        var now = DateTimeOffset.UtcNow;
        foreach (var p in processes) obs.Add(ProcessCollector.ToObservation(p, now, selfPid));

        // S2 · 트레이
        obs.AddRange(TrayCollector.Collect(processes, now, out var trayNote));
        if (trayNote is not null) notes.Add(trayNote);

        // S3 · 캡처 제외 창
        obs.AddRange(WindowCollector.Collect(processes, now, selfPid));

        // S6 · VM · 원격제어
        obs.Add(HostCollector.VmIndicator(now));
        obs.AddRange(HostCollector.RemoteControlCandidates(processes, policy, now));

        // S5 · 네트워크 (프로세스별 연결 포함)
        obs.Add(await netTask.ConfigureAwait(false));
        obs.AddRange(NetworkCollector.Connections(processes, now));

        ct.ThrowIfCancellationRequested();

        return new ScanResult(
            obs,
            new List<string> { "process", "statusItem", "captureExcludedWindow" },
            processes,
            notes,
            DateTimeOffset.UtcNow - started);
    }

    /// <summary>
    /// 오탐 코퍼스 도구. 지금 이 기기에서 도는 상주 앱을 허용목록 초안으로 뽑는다.
    /// 설계서 12장: "상주 앱 30종 → 학교 공용 허용목록 초안이 여기서 나온다."
    /// 서명이 검증된 것만 담는다 — 미서명 프로세스를 허용목록에 올리면 그게 곧 구멍이다.
    /// </summary>
    public static JsonObject EmitAllowlistDraft(IReadOnlyList<ProcInfo> processes, string machineLabel)
    {
        var allow = new JsonArray();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var p in processes.Where(p => p.Signed && p.Signer is not null).OrderBy(p => p.Signer, StringComparer.Ordinal))
        {
            if (!seen.Add(p.Signer!)) continue;
            allow.Add(new JsonObject
            {
                ["signer"] = p.Signer,
                ["platform"] = "windows",
                ["layer"] = "school",
                ["note"] = $"{machineLabel} 에서 관측 — 예: {p.Path}",
            });
        }

        var unsigned = new JsonArray();
        foreach (var p in processes.Where(p => !p.Signed).OrderBy(p => p.Path, StringComparer.Ordinal))
            unsigned.Add(new JsonObject { ["path"] = p.Path, ["sha256"] = p.Sha256 });

        // policy 는 spec/policy.schema.json 을 그대로 만족해야 한다(추가 필드 금지).
        // 검토 대상 목록은 정책이 아니므로 형제 키로 뺀다.
        return new JsonObject
        {
            ["policy"] = new JsonObject
            {
                ["id"] = "draft-from-" + machineLabel,
                ["scope"] = "school",
                ["version"] = 1,
                ["note"] = "ExamCheck --emit-allowlist 초안. 서명 검증된 프로세스의 인증서 주체만 담았다. " +
                           "여러 기기에서 모아 교차 확인한 뒤 school-common.json 에 합쳐라.",
                ["allow"] = allow,
                ["deny"] = new JsonArray(),
                ["thresholds"] = new JsonObject(),
            },
            ["review"] = new JsonObject
            {
                ["note"] = "미서명 프로세스. 허용목록이 아니라 검토 대상이다 — " +
                           "서명 없는 바이너리를 허용목록에 올리면 그게 곧 구멍이 된다.",
                ["unsigned"] = unsigned,
            },
        };
    }
}
