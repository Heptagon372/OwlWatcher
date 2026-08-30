using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Collectors;

/// <summary>
/// S3 · 캡처에서 제외된 창(Cluely형 오버레이).
/// EnumWindows → GetWindowDisplayAffinity != WDA_NONE → GetWindowThreadProcessId.
///
/// 정상 사례가 분명히 있다 — 비밀번호 관리자, DRM 플레이어. 그래서 P1 이고
/// 허용목록으로 걸러낸다. 우리 시험 창은 세션의 agentPid 로 규칙 엔진이 제외한다.
/// </summary>
public static class WindowCollector
{
    public static List<JsonObject> Collect(IReadOnlyList<ProcInfo> processes, DateTimeOffset now, int selfPid)
    {
        var byPid = processes.ToDictionary(p => p.Pid);
        var outp = new List<JsonObject>();
        var seen = new HashSet<int>();

        Native.EnumWindows((h, _) =>
        {
            if (!Native.GetWindowDisplayAffinity(h, out var affinity)) return true;
            if (affinity == Native.WDA_NONE) return true;

            Native.GetWindowThreadProcessId(h, out var raw);
            var pid = (int)raw;
            if (pid == selfPid) return true;          // 우리 시험 창
            if (!seen.Add(pid)) return true;          // 프로세스당 한 번

            var label = affinity switch
            {
                Native.WDA_EXCLUDEFROMCAPTURE => "excludeFromCapture",
                Native.WDA_MONITOR => "monitor",
                _ => "monitor",
            };

            var o = new JsonObject
            {
                ["kind"] = "captureExcludedWindow",
                ["source"] = "userspace",
                ["signal"] = "S3",
                ["collector"] = "enumwindows-displayaffinity",
                ["platform"] = "windows",
                ["ts"] = Redaction.IsoSec(now),
                ["ownerPid"] = pid,
                ["affinity"] = label,
            };

            if (byPid.TryGetValue(pid, out var p))
            {
                o["ownerPath"] = p.Path;
                o["signed"] = p.Signed;
                o.Set("sha256", p.Sha256);
                if (p.Signer is null) o["signer"] = null; else o["signer"] = p.Signer;
            }
            else
            {
                // 창은 있는데 프로세스 목록에 없다. 경로 없이 알림을 만들지 않는다.
                o["ownerPath"] = $"pid {pid}";
                o["degraded"] = true;
            }

            outp.Add(o);
            return true;
        }, IntPtr.Zero);

        return outp;
    }
}
