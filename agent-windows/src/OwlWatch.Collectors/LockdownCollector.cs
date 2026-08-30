using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.Win32;
using OwlWatch.Core;

namespace OwlWatch.Collectors;

/// <summary>
/// L2 · Windows Take a Test 연동과 S7(락다운 이탈) 관측.
///
/// 설계서 06장: <c>ms-edu-secureassessment:&lt;시험 URL&gt;#enforceLockdown</c> 로 진입하면
/// 잠금 화면 위 전체화면, 캡처 결과 검은 화면, 클립보드 초기화, PrintScreen 비활성,
/// 다른 앱 접근 불가. **승인이 필요 없다** — macOS 의 AAC 가 Apple 엔타이틀먼트를 기다리는
/// 동안 Windows 는 오늘 켤 수 있는 이유가 이것이다.
///
/// 한계도 그대로다. 백그라운드 프로세스는 계속 돈다 — 볼 화면이 없어 무력할 뿐이다.
/// 그래서 진입 전 L0 스캔을 강제하고, 창이 사라지면 S7 crit 를 낸다.
///
/// 이 클래스는 스스로 Take a Test 를 띄우지 않는다. 띄우면 기기가 전체화면 잠금으로 들어가므로,
/// 호출자가 명시적으로 Launch 를 불러야 한다.
/// </summary>
public static class LockdownCollector
{
    private const string ProtocolKey = "ms-edu-secureassessment";
    private const string PackageName = "Microsoft.Windows.SecureAssessmentBrowser";

    public sealed record Availability(bool Available, bool ProtocolRegistered, bool PackagePresent, string Detail);

    /// <summary>
    /// 이 기기에서 Take a Test 를 쓸 수 있는가. 시험 전에 알아야 하는 값이라
    /// ExamCheck 가 결과 화면에 표시한다.
    /// </summary>
    public static Availability Probe()
    {
        var protocol = false;
        try
        {
            using var k = Registry.ClassesRoot.OpenSubKey(ProtocolKey);
            protocol = k is not null;
        }
        catch { /* 접근 실패는 미등록과 같이 다룬다 */ }

        var package = PackageDirectory() is not null;

        var detail = (protocol, package) switch
        {
            (true, true) => "Take a Test 를 쓸 수 있다 — 승인 없이 L2 락다운이 가능하다",
            (true, false) => "프로토콜은 등록됐으나 SecureAssessmentBrowser 패키지가 없다",
            (false, true) => "패키지는 있으나 프로토콜이 등록되지 않았다",
            _ => "이 기기에는 Take a Test 가 없다 — Windows 10/11 교육용 구성 요소가 필요하다",
        };

        return new Availability(protocol && package, protocol, package, detail);
    }

    private static string? PackageDirectory()
    {
        try
        {
            var systemApps = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SystemApps");
            if (!Directory.Exists(systemApps)) return null;

            return Directory.GetDirectories(systemApps)
                .FirstOrDefault(d => Path.GetFileName(d)
                    .StartsWith(PackageName, StringComparison.OrdinalIgnoreCase));
        }
        catch { return null; }
    }

    /// <summary>
    /// Take a Test 진입. 화면이 전체화면 잠금으로 바뀌므로 호출자가 학생 동의와
    /// 사전 점검 통과를 먼저 확인해야 한다(설계서 06장: 진입 전 L0 스캔을 강제).
    /// </summary>
    public static bool Launch(string examUrl, out string error)
    {
        error = "";
        var probe = Probe();
        if (!probe.Available) { error = probe.Detail; return false; }

        // #enforceLockdown 이 있어야 잠금 화면 위 전체화면으로 들어간다. 없으면 그냥 브라우저다.
        var uri = $"{ProtocolKey}:{examUrl}#enforceLockdown";
        try
        {
            using var p = Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true });
            return true;
        }
        catch (Exception ex)
        {
            error = $"Take a Test 를 띄우지 못했다: {ex.Message}";
            return false;
        }
    }

    /// <summary>Take a Test 프로세스가 살아 있는가. 경로로 확인한다 — 이름은 위장될 수 있다.</summary>
    public static bool IsRunning()
    {
        var dir = PackageDirectory();
        if (dir is null) return false;

        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                var path = ProcessCollector.QueryImagePath(p.Id);
                if (path is null) continue;
                if (path.StartsWith(dir, StringComparison.OrdinalIgnoreCase)) return true;
            }
        }
        return false;
    }

    /// <summary>
    /// S7 · 락다운 상태. active=false 로 바뀌면 규칙 엔진이 P0 crit 를 낸다.
    ///
    /// 정전·크래시와 구분하려면 원장(S9)의 종료 사유와 대조해야 한다(설계서 05장 S7).
    /// 그 대조는 규칙 엔진이 아니라 리포트 단계의 몫으로 남겨 뒀다.
    /// </summary>
    public static JsonObject Observe(DateTimeOffset now, string mode = "takeatest") => new()
    {
        ["kind"] = "lockdownState",
        ["source"] = "selfverify",
        ["signal"] = "S7",
        ["collector"] = "takeatest-process",
        ["platform"] = "windows",
        ["ts"] = Redaction.IsoSec(now),
        ["mode"] = mode,
        ["active"] = IsRunning(),
    };
}
