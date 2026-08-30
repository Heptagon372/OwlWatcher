using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using OwlWatch.Collectors.Etw;
using OwlWatch.Core;

namespace OwlWatch.Collectors;

/// <summary>
/// S9 · 프로세스 원장 — 커널 경로. **여기서 Windows 가 P0 등급에 도달한다.**
///
/// Microsoft-Windows-Kernel-Process 실시간 세션이 시험 구간의 모든 exec 을 기록하므로
/// "사전점검 직전에 종료했다가 시험 중에 재실행"하는 회피가 성립하지 않는다.
/// 그게 v0.1 의 최대 구멍이었고 v0.2 가 고친 것이다(설계서 05장 S9).
///
/// 이 수집기가 내는 관측은 source=kernel 이라 규칙 엔진이 P0 로 다룬다.
/// 세션을 열지 못하면 **아무 관측도 내지 않는다** — LedgerPoller 로 폴백하는 판단은
/// 호출자(AgentSession)가 하고, 그때는 source 가 userspace 가 되어 등급이 자동으로 내려간다.
/// 원장이 안 도는데 도는 척하는 경로는 코드에 없다.
///
/// S11(캡처 스택 로드)도 같은 세션의 이미지 로드 이벤트에서 나온다.
/// </summary>
public sealed class EtwLedgerCollector : IDisposable
{
    /// <summary>콜백 안에서 뽑은 원시 사실. 해시·서명은 Drain 에서 붙인다.</summary>
    private readonly record struct Raw(
        string Kind, int Pid, int Ppid, string? ImagePath, string? ModulePath, DateTimeOffset Ts);

    private readonly ConcurrentQueue<Raw> _queue = new();
    private readonly EtwSession _session;
    private readonly HashSet<string> _captureModules;
    private readonly int _selfPid = Environment.ProcessId;

    public bool Running => _session.Running;
    public string? FailureReason => _session.FailureReason;
    public int LastError => _session.LastError;

    public EtwLedgerCollector(IEnumerable<string> captureStackModules)
    {
        _session = new EtwSession($"OwlWatch-Ledger-{Environment.ProcessId}");
        _captureModules = new HashSet<string>(
            captureStackModules.Select(m => m.ToLowerInvariant()), StringComparer.Ordinal);
    }

    /// <summary>세션을 열고 소비를 시작한다. 실패하면 false — 호출자가 폴백을 결정한다.</summary>
    public bool Start()
    {
        if (!_session.Start(NativeEtw.KernelProcessProvider,
                NativeEtw.KeywordProcess | NativeEtw.KeywordImage))
            return false;

        _session.Consume(OnRecord);
        return _session.Running;
    }

    private void OnRecord(ref NativeEtw.EVENT_RECORD record)
    {
        var id = record.EventHeader.EventDescriptor.Id;
        if (id is not (NativeEtw.EventProcessStart or NativeEtw.EventProcessStop or NativeEtw.EventImageLoad))
            return;

        var pid = (int)(TdhReader.GetUInt32(ref record, "ProcessID") ?? 0);
        if (pid == 0 || pid == _selfPid) return;

        // 콜백 안에서만 UserData 가 유효하다. 여기서 문자열까지 뽑아 두고 나머지는 뒤로 미룬다.
        var imageName = TdhReader.GetString(ref record, "ImageName");
        var ts = DateTimeOffset.FromFileTime(record.EventHeader.TimeStamp);

        switch (id)
        {
            case NativeEtw.EventProcessStart:
                _queue.Enqueue(new Raw("exec", pid,
                    (int)(TdhReader.GetUInt32(ref record, "ParentProcessID") ?? 0),
                    imageName, null, ts));
                break;

            case NativeEtw.EventProcessStop:
                _queue.Enqueue(new Raw("exit", pid, 0, imageName, null, ts));
                break;

            case NativeEtw.EventImageLoad:
                // S11 은 조합만 본다. 관심 없는 모듈까지 큐에 넣으면 초당 수백 건이 쌓인다.
                var file = FileNameOf(imageName);
                if (file is not null && _captureModules.Contains(file))
                    _queue.Enqueue(new Raw("imageLoad", pid, 0, null, imageName, ts));
                break;
        }
    }

    private static string? FileNameOf(string? path) =>
        string.IsNullOrEmpty(path) ? null : path.Split('\\', '/')[^1].ToLowerInvariant();

    /// <summary>
    /// 쌓인 사실에 해시·서명을 붙여 관측으로 만든다.
    /// 이 작업은 파일 I/O 라서 ETW 콜백 안에서 하면 소비 스레드가 막히고 버퍼가 유실된다.
    /// </summary>
    public List<JsonObject> Drain()
    {
        var outp = new List<JsonObject>();
        while (_queue.TryDequeue(out var raw))
        {
            switch (raw.Kind)
            {
                case "exec": outp.Add(Exec(raw)); break;
                case "exit": outp.Add(Exit(raw)); break;
                case "imageLoad": outp.Add(ImageLoad(raw)); break;
            }
        }
        return outp;
    }

    private JsonObject Exec(Raw raw)
    {
        // 커널이 준 것은 NT 경로(\Device\HarddiskVolume3\...)라 서명 검증·해시에 바로 못 쓴다.
        // 프로세스가 아직 살아 있으면 pid 로 DOS 경로를 받는 편이 정확하다.
        var full = ProcessCollector.QueryImagePath(raw.Pid) ?? DosPath(raw.ImagePath);
        var degraded = full is null;

        var o = new JsonObject
        {
            ["kind"] = "exec",
            ["source"] = "kernel",                 // ← P0 를 만드는 유일한 지점
            ["signal"] = "S9",
            ["collector"] = "etw-kernel-process",
            ["platform"] = "windows",
            ["ts"] = Redaction.IsoSec(raw.Ts),
            ["pid"] = raw.Pid,
            ["path"] = full is null ? (raw.ImagePath ?? $"pid {raw.Pid}") : Redaction.Path(full),
        };
        if (raw.Ppid > 0) o["ppid"] = raw.Ppid;

        if (full is not null)
        {
            var sig = Signing.Of(full);
            o["signed"] = sig.Signed && sig.Verified;
            o["platformBinary"] = IsPlatformBinary(full, sig);
            if (sig.Signer is null) o["signer"] = null; else o["signer"] = sig.Signer;
            o.Set("sha256", Redaction.Sha256OfFile(full));
        }
        else
        {
            // 경로를 확정하지 못했다. 사실은 남기되 P0 로 올리지 않는다.
            o["degraded"] = true;
        }

        o["startedAt"] = Redaction.IsoSec(raw.Ts);
        if (degraded) o["note"] = "프로세스가 이미 종료돼 실행 파일 경로를 확정하지 못했다";
        return o;
    }

    private static JsonObject Exit(Raw raw) => new()
    {
        ["kind"] = "process",
        ["source"] = "kernel",
        ["signal"] = "S9",
        ["collector"] = "etw-kernel-process",
        ["platform"] = "windows",
        ["ts"] = Redaction.IsoSec(raw.Ts),
        ["pid"] = raw.Pid,
        ["path"] = raw.ImagePath is null ? $"pid {raw.Pid}" : Redaction.Path(DosPath(raw.ImagePath) ?? raw.ImagePath),
        ["note"] = "exit",
    };

    private JsonObject ImageLoad(Raw raw)
    {
        var full = ProcessCollector.QueryImagePath(raw.Pid);
        var o = new JsonObject
        {
            ["kind"] = "imageLoad",
            ["source"] = "kernel",
            ["signal"] = "S11",
            ["collector"] = "etw-kernel-process",
            ["platform"] = "windows",
            ["ts"] = Redaction.IsoSec(raw.Ts),
            ["pid"] = raw.Pid,
            ["modulePath"] = raw.ModulePath ?? "",
        };
        if (full is not null)
        {
            var sig = Signing.Of(full);
            o["path"] = Redaction.Path(full);
            o["signed"] = sig.Signed && sig.Verified;
            if (sig.Signer is null) o["signer"] = null; else o["signer"] = sig.Signer;
            o.Set("sha256", Redaction.Sha256OfFile(full));
        }
        return o;
    }

    private static bool IsPlatformBinary(string fullPath, Signing.Info sig)
    {
        if (!sig.Signed || !sig.Verified || sig.Signer is null) return false;
        if (!sig.Signer.StartsWith("Microsoft Windows", StringComparison.OrdinalIgnoreCase)) return false;
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).Replace('\\', '/');
        return fullPath.Replace('\\', '/').StartsWith(win, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>NT 장치 경로를 DOS 경로로. 실패하면 null — 추측한 경로를 내지 않는다.</summary>
    private static string? DosPath(string? ntPath)
    {
        if (string.IsNullOrEmpty(ntPath)) return null;
        if (!ntPath.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) return ntPath;

        foreach (var drive in DriveInfo.GetDrives())
        {
            var letter = drive.Name.TrimEnd('\\');           // "C:"
            var target = Native.QueryDosDeviceSafe(letter);  // "\Device\HarddiskVolume3"
            if (target is null) continue;
            if (ntPath.StartsWith(target + @"\", StringComparison.OrdinalIgnoreCase))
                return letter + ntPath[target.Length..];
        }
        return null;
    }

    public void Dispose() => _session.Dispose();
}
