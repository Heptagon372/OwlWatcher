using System.Text.Json.Nodes;
using Microsoft.Win32;
using OwlWatch.Core;

namespace OwlWatch.Collectors;

/// <summary>
/// S2 · 트레이(상태 영역) 항목의 소유 프로세스.
/// 설계서: HKCU\Control Panel\NotifyIconSettings + Shell_TrayWnd/NotifyIconOverflowWindow 툴바 열거.
///
/// 레지스트리만 읽으면 오탐이 난다 — NotifyIconSettings 는 한 번이라도 아이콘을 띄운 앱의
/// 설정을 남겨 두고, 지운 앱의 항목도 그대로 있다. 그래서 "지금 돌고 있는 프로세스"와
/// 교집합을 취한다. 덤으로 S1 의 프로세스 목록과 대상 키가 자연스럽게 합쳐져
/// 같은 프로세스에 겹친 정황이 에스컬레이션으로 올라간다.
///
/// 라이브 툴바는 버튼 개수만 읽는다. 버튼의 dwData 를 따라가 소유 창을 알아내는 방법은
/// 문서화되지 않은 셸 내부 구조체에 의존해서 Windows 빌드마다 깨지고, 틀린 pid 를
/// 조용히 만들어 낸다 — P0 근거를 다루는 도구에서 그건 최악의 실패다.
/// 대신 개수 차이를 degraded 로 남겨 "레지스트리에 없는 아이콘이 떠 있다"를 알린다.
/// </summary>
public static class TrayCollector
{
    private const string NotifyIconKey = @"Control Panel\NotifyIconSettings";

    public readonly record struct TrayItem(string ExecutablePath, bool? Promoted);

    public static List<TrayItem> ReadRegistry()
    {
        var items = new List<TrayItem>();
        try
        {
            using var root = Registry.CurrentUser.OpenSubKey(NotifyIconKey);
            if (root is null) return items;

            foreach (var name in root.GetSubKeyNames())
            {
                using var sub = root.OpenSubKey(name);
                if (sub?.GetValue("ExecutablePath") is not string exe || string.IsNullOrWhiteSpace(exe)) continue;
                bool? promoted = sub.GetValue("IsPromoted") is int p ? p != 0 : null;
                items.Add(new TrayItem(exe, promoted));
            }
        }
        catch
        {
            // 레지스트리 접근 실패는 관측 없음으로 처리한다. 없는 사실을 지어내지 않는다.
        }
        return items;
    }

    /// <summary>표시 중인 트레이 버튼 수(주 영역 + 오버플로). 실패하면 null.</summary>
    public static int? LiveButtonCount()
    {
        try
        {
            var total = 0;
            var any = false;

            var tray = Native.FindWindow("Shell_TrayWnd", null);
            if (tray != IntPtr.Zero)
            {
                var notify = Native.FindWindowEx(tray, IntPtr.Zero, "TrayNotifyWnd", null);
                var pager = notify != IntPtr.Zero ? Native.FindWindowEx(notify, IntPtr.Zero, "SysPager", null) : IntPtr.Zero;
                var bar = pager != IntPtr.Zero ? Native.FindWindowEx(pager, IntPtr.Zero, "ToolbarWindow32", null) : IntPtr.Zero;
                if (bar != IntPtr.Zero)
                {
                    total += (int)Native.SendMessage(bar, Native.TB_BUTTONCOUNT, IntPtr.Zero, IntPtr.Zero);
                    any = true;
                }
            }

            var overflow = Native.FindWindow("NotifyIconOverflowWindow", null);
            if (overflow != IntPtr.Zero)
            {
                var bar = Native.FindWindowEx(overflow, IntPtr.Zero, "ToolbarWindow32", null);
                if (bar != IntPtr.Zero)
                {
                    total += (int)Native.SendMessage(bar, Native.TB_BUTTONCOUNT, IntPtr.Zero, IntPtr.Zero);
                    any = true;
                }
            }

            return any ? total : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 레지스트리 항목 ∩ 현재 프로세스. 살아 있지 않은 항목은 상태 영역에 아이콘이 없다.
    /// </summary>
    public static List<JsonObject> Collect(IReadOnlyList<ProcInfo> processes, DateTimeOffset now, out string? note)
    {
        var reg = ReadRegistry();
        var byPath = new Dictionary<string, ProcInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in processes) byPath.TryAdd(p.FullPath, p);

        var outp = new List<JsonObject>();
        foreach (var item in reg)
        {
            if (!byPath.TryGetValue(item.ExecutablePath, out var proc)) continue;

            var o = new JsonObject
            {
                ["kind"] = "statusItem",
                ["source"] = "userspace",
                ["signal"] = "S2",
                ["collector"] = "notifyicon-registry",
                ["method"] = "registry",
                ["platform"] = "windows",
                ["ts"] = Redaction.IsoSec(now),
                ["ownerPid"] = proc.Pid,
                ["ownerPath"] = proc.Path,
                ["signed"] = proc.Signed,
            };
            o.Set("sha256", proc.Sha256);
            if (proc.Signer is null) o["signer"] = null; else o["signer"] = proc.Signer;
            if (item.Promoted.HasValue) o["promoted"] = item.Promoted.Value;
            if (proc.StartedAt.HasValue) o["startedAt"] = Redaction.IsoSec(proc.StartedAt.Value);
            outp.Add(o);
        }

        var live = LiveButtonCount();
        note = null;
        if (live is int n && n > outp.Count)
        {
            // 레지스트리로 설명되지 않는 아이콘이 떠 있다. 소유자를 특정할 수 없으므로
            // 알림을 만들지 않고 사실만 남긴다 — 추측한 pid 로 학생을 부르는 것보다 낫다.
            note = $"표시 중인 트레이 아이콘 {n}개 중 {outp.Count}개만 소유 프로세스를 특정했다";
            foreach (var o in outp) o["degraded"] = true;
        }
        return outp;
    }
}
