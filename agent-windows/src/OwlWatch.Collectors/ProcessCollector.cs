using System.Diagnostics;
using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Collectors;

/// <summary>프로세스 하나의 관측 재료. 수집기 사이에서 공유한다.</summary>
public sealed record ProcInfo(
    int Pid, string Path, string FullPath, string? Sha256, bool Signed, string? Signer,
    bool Verified, bool PlatformBinary, bool HasVisibleWindow, bool HasTopLevelWindow,
    DateTimeOffset? StartedAt, bool Degraded);

/// <summary>
/// S1 · 허용목록 밖 에이전트형 프로세스.
///
/// "에이전트형"의 정의가 이 수집기의 전부다. macOS 는 NSWorkspace 가
/// activationPolicy .accessory/.prohibited 로 답을 주지만, Windows 에는 대응 개념이 없다.
///
/// 실기기에서 "보이는 창이 없는 프로세스"로 잡아 봤더니 conhost·ctfmon·sihost·cmd·bash
/// 까지 수십 건이 걸렸다. 그건 신호가 아니라 잡음이다. 그래서 조건을 좁혔다 —
/// 최상위 창을 하나라도 만들었지만 보이는 창은 하나도 없는 프로세스.
/// GUI 로 등록됐으면서 작업표시줄에 나타나지 않는다는 뜻이고, .accessory 에 가장 가깝다.
/// 콘솔 프로그램은 자기 최상위 창이 없어(콘솔 창은 conhost 소유) 자연히 빠진다.
///
/// 트레이 아이콘만 있고 메시지 전용 창만 가진 도구는 이 조건에서 빠질 수 있다.
/// 그건 S2(트레이 소유자)가 독립적으로 잡는다 — 두 신호가 서로의 사각을 메운다.
/// </summary>
public static class ProcessCollector
{
    private static readonly HashSet<int> SkipPids = new() { 0, 4 };

    private static readonly string WindowsDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).Replace('\\', '/');

    public static List<ProcInfo> Snapshot()
    {
        var outp = new List<ProcInfo>();
        var (visible, topLevel) = WindowPids();

        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (SkipPids.Contains(p.Id)) continue;

                string? full = null;
                DateTimeOffset? started = null;
                var degraded = false;

                try { full = p.MainModule?.FileName; }
                catch { degraded = true; }

                if (full is null)
                {
                    full = QueryImagePath(p.Id);
                    if (full is null) degraded = true;
                }

                try { started = new DateTimeOffset(p.StartTime.ToUniversalTime(), TimeSpan.Zero); }
                catch { degraded = true; }

                if (string.IsNullOrEmpty(full)) continue; // 경로를 모르면 판정할 근거가 없다

                var sig = Signing.Of(full);
                var sha = Redaction.Sha256OfFile(full);
                if (sha is null) degraded = true;

                outp.Add(new ProcInfo(
                    Pid: p.Id,
                    Path: Redaction.Path(full),
                    FullPath: full,
                    Sha256: sha,
                    Signed: sig.Signed && sig.Verified,
                    Signer: sig.Signer,
                    Verified: sig.Verified,
                    PlatformBinary: IsPlatformBinary(full, sig),
                    HasVisibleWindow: visible.Contains(p.Id),
                    HasTopLevelWindow: topLevel.Contains(p.Id),
                    StartedAt: started,
                    Degraded: degraded));
            }
        }

        return outp.OrderBy(x => x.Pid).ToList();
    }

    /// <summary>
    /// macOS 의 is_platform_binary 대응물: Windows 디렉터리 안에 있고 Microsoft Windows 가
    /// 서명한 것. 서명자만 보면 위장에 약하고, 경로만 보면 시스템 폴더에 떨군 파일이 통과한다.
    /// </summary>
    private static bool IsPlatformBinary(string fullPath, Signing.Info sig)
    {
        if (!sig.Signed || !sig.Verified || sig.Signer is null) return false;
        if (!sig.Signer.StartsWith("Microsoft Windows", StringComparison.OrdinalIgnoreCase)) return false;
        var p = fullPath.Replace('\\', '/');
        return p.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>보이는 최상위 창을 가진 pid, 그리고 최상위 창을 하나라도 가진 pid.</summary>
    private static (HashSet<int> Visible, HashSet<int> TopLevel) WindowPids()
    {
        var visible = new HashSet<int>();
        var top = new HashSet<int>();
        Native.EnumWindows((h, _) =>
        {
            Native.GetWindowThreadProcessId(h, out var pid);
            top.Add((int)pid);
            if (Native.IsWindowVisible(h)) visible.Add((int)pid);
            return true;
        }, IntPtr.Zero);
        return (visible, top);
    }

    /// <summary>pid 로 실행 파일 경로. ETW 원장이 NT 경로 대신 이걸 먼저 쓴다.</summary>
    public static string? QueryImagePath(int pid)
    {
        var h = Native.OpenProcess(Native.ProcessAccess.QueryLimitedInformation, false, (uint)pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var buf = new char[1024];
            var size = (uint)buf.Length;
            return Native.QueryFullProcessImageName(h, 0, buf, ref size) ? new string(buf, 0, (int)size) : null;
        }
        finally { Native.CloseHandle(h); }
    }

    public static JsonObject ToObservation(ProcInfo p, DateTimeOffset now, int selfPid)
    {
        // agentLike 가 S1 의 실제 판정 대상이다. hasVisibleWindow 는 사실 그대로 남긴다.
        var agentLike = p.HasTopLevelWindow && !p.HasVisibleWindow && p.Pid != selfPid;

        var o = new JsonObject
        {
            ["kind"] = "process",
            ["source"] = "userspace",
            ["signal"] = "S1",
            ["collector"] = "process-enum",
            ["platform"] = "windows",
            ["ts"] = Redaction.IsoSec(now),
            ["pid"] = p.Pid,
            ["path"] = p.Path,
            ["signed"] = p.Signed,
            ["platformBinary"] = p.PlatformBinary,
            ["hasVisibleWindow"] = p.HasVisibleWindow,
            ["agentLike"] = agentLike,
        };
        o.Set("sha256", p.Sha256);
        if (p.Signer is null) o["signer"] = null; else o["signer"] = p.Signer;
        if (p.StartedAt.HasValue) o["startedAt"] = Redaction.IsoSec(p.StartedAt.Value);
        if (p.Degraded) o["degraded"] = true;
        return o;
    }
}
