using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Collectors;

public sealed record NetConfig(string? BeaconUrl, string? CanaryUrl, string? ExpectedSalt);

/// <summary>
/// S5 · 네트워크 포스처.
///
/// 설계서 07장의 두 축:
///   beacon — 시험 VLAN 에서만 라우팅되는 내부 호스트. 닿으면 "시험망에 있다"가 증명된다.
///            위치 권한도, SSID 읽기도 필요 없다(설계서 10장 비수집: 위치·SSID).
///   canary — 게이트웨이가 차단해야 하는 공용 호스트. 닿으면 핫스팟·테더링이다.
///
/// 실패 모드가 중요하다. beacon 실패는 학교망 장애와 구분되지 않으므로 P2/info 다.
/// crit 는 canary 성공에만 — 40명이 동시에 빨간불이 되면 감독관이 시스템을 꺼 버린다.
/// </summary>
public static class NetworkCollector
{
    private static readonly HttpClient Http = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseProxy = false, // 프록시를 타면 "시험망에 있는가"라는 질문 자체가 무의미해진다
    })
    { Timeout = TimeSpan.FromSeconds(2) };

    public static async Task<JsonObject> PostureAsync(NetConfig cfg, DateTimeOffset now)
    {
        var beacon = await ProbeAsync(cfg.BeaconUrl, cfg.ExpectedSalt).ConfigureAwait(false);
        var canary = await ProbeAsync(cfg.CanaryUrl, null).ConfigureAwait(false);
        var ifaces = Interfaces();

        var arr = new JsonArray();
        foreach (var i in ifaces)
            arr.Add(new JsonObject { ["name"] = i.Name, ["type"] = i.Type, ["up"] = i.Up });

        var o = new JsonObject
        {
            ["kind"] = "netPosture",
            ["source"] = "userspace",
            ["signal"] = "S5",
            ["collector"] = "beacon-canary",
            ["platform"] = "windows",
            ["ts"] = Redaction.IsoSec(now),
            ["beacon"] = beacon,
            ["canary"] = canary,
            ["ifaceCount"] = ifaces.Count(i => i.Up),
            ["ifaces"] = arr,
        };
        if (cfg.BeaconUrl is null || cfg.CanaryUrl is null) o["degraded"] = true;
        return o;
    }

    private static async Task<bool> ProbeAsync(string? url, string? expectSalt)
    {
        if (string.IsNullOrEmpty(url)) return false;
        try
        {
            using var res = await Http.GetAsync(url, HttpCompletionOption.ResponseContentRead).ConfigureAwait(false);
            if (!res.IsSuccessStatusCode) return false;
            if (expectSalt is null) return true;
            var body = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
            return body.Contains(expectSalt, StringComparison.Ordinal);
        }
        catch
        {
            return false; // 도달 실패. beacon 이면 info, canary 면 기대한 결과다.
        }
    }

    public readonly record struct Iface(string Name, string Type, bool Up);

    /// <summary>
    /// 휴대폰 USB 테더링(RNDIS)과 Bluetooth PAN 은 종류가 Ethernet 으로 보고되므로
    /// 설명 문자열로 구분한다. 인터페이스가 둘 이상인 것 자체는 P2 맥락일 뿐이다.
    /// </summary>
    public static List<Iface> Interfaces()
    {
        var outp = new List<Iface>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            var desc = (ni.Description + " " + ni.Name).ToLowerInvariant();
            var type = ni.NetworkInterfaceType switch
            {
                NetworkInterfaceType.Wireless80211 => "wifi",
                NetworkInterfaceType.Ppp => "ppp",
                NetworkInterfaceType.Tunnel => "tunnel",
                _ when desc.Contains("rndis") || desc.Contains("ncm") => "rndis",
                _ when desc.Contains("bluetooth") => "bluetoothPan",
                NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet => "ethernet",
                _ => "other",
            };
            outp.Add(new Iface(ni.Name, type, ni.OperationalStatus == OperationalStatus.Up));
        }
        return outp;
    }

    /// <summary>
    /// 프로세스별 원격 연결. 설계서 10장 수집 항목: "프로세스별 원격 host:port".
    /// 내용은 보지 않는다 — 목적지만 본다.
    /// </summary>
    public static List<JsonObject> Connections(IReadOnlyList<ProcInfo> processes, DateTimeOffset now)
    {
        var outp = new List<JsonObject>();
        var byPid = processes.ToDictionary(p => p.Pid);
        var size = 0;

        Native.GetExtendedTcpTable(IntPtr.Zero, ref size, false, Native.AF_INET, Native.TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return outp;

        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (Native.GetExtendedTcpTable(buf, ref size, false, Native.AF_INET, Native.TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return outp;

            var count = Marshal.ReadInt32(buf);
            var rowSize = Marshal.SizeOf<Native.MIB_TCPROW_OWNER_PID>();
            var cursor = buf + 4;

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<Native.MIB_TCPROW_OWNER_PID>(cursor + i * rowSize);
                if (row.remoteAddr == 0) continue;         // LISTEN
                if (row.state != 5) continue;              // ESTABLISHED 만

                var pid = (int)row.owningPid;
                var o = new JsonObject
                {
                    ["kind"] = "procConnection",
                    ["source"] = "userspace",
                    ["signal"] = "S5",
                    ["collector"] = "getextendedtcptable",
                    ["platform"] = "windows",
                    ["ts"] = Redaction.IsoSec(now),
                    ["pid"] = pid,
                    ["remoteHost"] = new IPAddress(row.remoteAddr).ToString(),
                    ["remotePort"] = NetworkPort(row.remotePort),
                };
                if (byPid.TryGetValue(pid, out var p)) o["path"] = p.Path;
                outp.Add(o);
            }
        }
        finally { Marshal.FreeHGlobal(buf); }

        return outp;
    }

    private static int NetworkPort(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));
}
