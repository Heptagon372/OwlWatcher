using System.Reflection;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Win32;
using OwlWatch.Core;

namespace OwlWatch.Collectors;

/// <summary>
/// S6 · VM·원격제어, S8 · 에이전트 무결성.
/// 둘 다 "이 기기가 시험을 볼 상태인가"에 대한 관측이라 한 파일에 둔다.
/// </summary>
public static class HostCollector
{
    // ── S6 · 가상머신

    /// <summary>
    /// CPUID leaf 1 의 ECX 비트 31 이 하이퍼바이저 존재 비트다. leaf 0x40000000 은
    /// 벤더 문자열(EBX·ECX·EDX)을 준다. macOS 의 sysctl kern.hv_vmm_present 에 대응한다.
    ///
    /// 그런데 이 비트만으로는 오탐이 난다. Windows 11 은 VBS/HVCI 가 기본으로 켜져 있어
    /// 실기기에서도 하이퍼바이저 위에서 돌고, 벤더 문자열은 "Microsoft Hv" 가 나온다.
    /// 실기기에서 바로 확인한 문제다 — 그대로 두면 노트북 대부분이 "VM 응시"로 잡힌다.
    ///
    /// 그래서 게스트 판정은 SMBIOS 를 함께 본다. hypervisorPresent 는 사실 그대로 두고,
    /// 규칙이 쓰는 값은 vmGuestLikely 로 따로 낸다.
    /// 중첩 가상화·베어메탈 위장은 여전히 못 잡는다(설계서 11장에 한계로 명시).
    /// </summary>
    public static JsonObject VmIndicator(DateTimeOffset now)
    {
        var present = false;
        string? vendor = null;

        if (X86Base.IsSupported)
        {
            var (_, _, ecx, _) = X86Base.CpuId(1, 0);
            present = (ecx & (1 << 31)) != 0;

            if (present)
            {
                var (_, ebx, vcx, edx) = X86Base.CpuId(unchecked((int)0x40000000), 0);
                var sb = new StringBuilder();
                foreach (var reg in new[] { ebx, vcx, edx })
                    for (var i = 0; i < 4; i++)
                    {
                        var c = (char)((reg >> (i * 8)) & 0xFF);
                        if (c is >= ' ' and < (char)127) sb.Append(c);
                    }
                vendor = sb.ToString().Trim();
                if (vendor.Length == 0) vendor = null;
            }
        }

        var (manufacturer, model) = Bios();
        var guest = LooksLikeGuest(vendor, manufacturer, model);

        var o = new JsonObject
        {
            ["kind"] = "vmIndicator",
            ["source"] = "userspace",
            ["signal"] = "S6",
            ["collector"] = "cpuid-smbios",
            ["platform"] = "windows",
            ["ts"] = Redaction.IsoSec(now),
            ["hypervisorPresent"] = present,
            ["vmGuestLikely"] = present && guest,
        };
        if (vendor is null) o["vendor"] = null; else o["vendor"] = vendor;
        if (manufacturer is not null) o["manufacturer"] = manufacturer;
        if (model is not null) o["model"] = model;
        if (present && !guest)
            o["note"] = "하이퍼바이저 비트는 켜져 있으나 SMBIOS 가 실기기를 가리킨다 — VBS/Hyper-V 호스트로 본다";
        return o;
    }

    /// <summary>게스트 전용 CPUID 벤더 문자열. "Microsoft Hv" 는 호스트의 VBS 에서도 나오므로 뺀다.</summary>
    private static readonly string[] GuestOnlyVendors =
    {
        "VMwareVMware", "VBoxVBoxVBox", "KVMKVMKVM", "XenVMMXenVMM",
        "TCGTCGTCGTCG", "prl hyperv", "ACRNACRNACRN", "bhyve bhyve",
    };

    private static readonly string[] GuestSmbiosMarkers =
    {
        "vmware", "innotek", "virtualbox", "qemu", "kvm", "xen", "parallels",
        "bochs", "bhyve", "virtual machine", "hyper-v", "red hat",
    };

    private static bool LooksLikeGuest(string? vendor, string? manufacturer, string? model)
    {
        if (vendor is not null &&
            GuestOnlyVendors.Any(v => vendor.Contains(v, StringComparison.OrdinalIgnoreCase)))
            return true;

        // "Microsoft Hv" 는 게스트일 수도, 호스트의 VBS 일 수도 있다. SMBIOS 가 가른다.
        var smbios = $"{manufacturer} {model}".ToLowerInvariant();
        return GuestSmbiosMarkers.Any(m => smbios.Contains(m, StringComparison.Ordinal));
    }

    private static (string? Manufacturer, string? Model) Bios()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            return (k?.GetValue("SystemManufacturer") as string, k?.GetValue("SystemProductName") as string);
        }
        catch { return (null, null); }
    }

    /// <summary>
    /// 원격제어 도구. 이름 문자열이 아니라 정책의 deny 프리셋이 판정하지만,
    /// 관측 단계에서 후보를 좁혀 두면 규칙 엔진이 볼 관측 수가 줄어든다.
    /// 최종 판정은 언제나 Policy.Classify 가 한다.
    /// </summary>
    public static List<JsonObject> RemoteControlCandidates(
        IReadOnlyList<ProcInfo> processes, Policy policy, DateTimeOffset now)
    {
        var outp = new List<JsonObject>();
        foreach (var p in processes)
        {
            var v = policy.Classify(new Subject
            {
                Path = p.Path, Sha256 = p.Sha256, Signer = p.Signer, Signed = p.Signed,
            }, "windows", Redaction.IsoSec(now));

            if (v.Denied is null) continue;

            var o = new JsonObject
            {
                ["kind"] = "remoteControlProcess",
                ["source"] = "userspace",
                ["signal"] = "S6",
                ["collector"] = "process-enum",
                ["platform"] = "windows",
                ["ts"] = Redaction.IsoSec(now),
                ["pid"] = p.Pid,
                ["path"] = p.Path,
                ["signed"] = p.Signed,
                ["matched"] = v.Denied.Id,
            };
            o.Set("sha256", p.Sha256);
            if (p.Signer is null) o["signer"] = null; else o["signer"] = p.Signer;
            outp.Add(o);
        }
        return outp;
    }

    // ── S8 · 에이전트 무결성

    /// <summary>
    /// 자기 서명 검증 · 디버거 부착 · 시계 편차.
    /// 서명된 바이너리를 패치하면 이 검사도 함께 패치되므로 결정적 근거가 아니다(P1).
    /// 최종적으로는 감독관 육안과 서버측 로그(S15)에 의존한다 — 설계서 11장.
    /// </summary>
    public static JsonObject Integrity(DateTimeOffset now, long clockSkewMs)
    {
        var self = Assembly.GetEntryAssembly()?.Location;
        if (string.IsNullOrEmpty(self))
            self = Environment.ProcessPath ?? "";

        var sigOk = false;
        if (!string.IsNullOrEmpty(self))
        {
            var info = Signing.Of(self);
            sigOk = info.Signed && info.Verified;
        }

        var remote = false;
        try { Native.CheckRemoteDebuggerPresent(Native.GetCurrentProcess(), ref remote); } catch { /* 무시 */ }
        var debugger = remote || Native.IsDebuggerPresent();

        return new JsonObject
        {
            ["kind"] = "agentIntegrity",
            ["source"] = "selfverify",
            ["signal"] = "S8",
            ["collector"] = "authenticode-self",
            ["platform"] = "windows",
            ["ts"] = Redaction.IsoSec(now),
            ["selfSignatureValid"] = sigOk,
            ["debuggerPresent"] = debugger,
            ["clockSkewMs"] = (int)Math.Clamp(clockSkewMs, int.MinValue, int.MaxValue),
        };
    }
}
