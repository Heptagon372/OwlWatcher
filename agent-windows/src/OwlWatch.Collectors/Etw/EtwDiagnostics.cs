using System.Runtime.InteropServices;

namespace OwlWatch.Collectors.Etw;

/// <summary>
/// ETW 원장의 자가 진단.
///
/// 실시간 세션은 관리자 권한이 필요해서, 권한 없는 환경에서는 배관 전체를 실행해 볼 수 없다.
/// 그렇다고 "안 해봤다"로 두면 승격된 서비스에서 처음 돌 때 레이아웃 오류가 터진다 —
/// 그건 시험 중에 드러난다는 뜻이다.
///
/// 그래서 권한 없이도 검증 가능한 것을 최대한 검증한다.
///   1) 구조체 레이아웃 — 하나라도 어긋나면 OpenTrace 가 조용히 이상하게 동작한다
///   2) TDH 배관과 매니페스트 조회 — 세션 없이 합성 EVENT_RECORD 로 확인할 수 있다
///   3) 세션 개시 — 실제로 시도하고 정확한 Win32 오류를 남긴다
/// </summary>
public static class EtwDiagnostics
{
    public sealed record LayoutCheck(string Name, int Actual, int Expected)
    {
        public bool Ok => Actual == Expected;
    }

    /// <summary>
    /// 알려진 x64 크기와 대조한다. 이 값들이 맞아야 OpenTrace 에 넘기는 버퍼가 올바르다.
    ///
    /// 기대값은 Windows SDK 헤더에서 손으로 계산한 것이다. 처음 두 개(120 · 112)를
    /// 128 · 104 로 잘못 적었다가 이 검사가 잡아냈다 — 검사가 구현이 아니라 기대값을
    /// 틀리게 잡아도 신호가 뜬다는 뜻이고, 그래서 2번(TDH 매니페스트 해석)이 같이 필요하다.
    /// 매니페스트가 해석된다는 것은 EVENT_RECORD 레이아웃이 실제로 맞다는 독립적 증거다.
    /// </summary>
    public static List<LayoutCheck> CheckLayouts() =>
    [
        new("WNODE_HEADER", Marshal.SizeOf<NativeEtw.WNODE_HEADER>(), 48),
        new("EVENT_TRACE_PROPERTIES", Marshal.SizeOf<NativeEtw.EVENT_TRACE_PROPERTIES>(), 120),
        new("EVENT_DESCRIPTOR", Marshal.SizeOf<NativeEtw.EVENT_DESCRIPTOR>(), 16),
        new("EVENT_HEADER", Marshal.SizeOf<NativeEtw.EVENT_HEADER>(), 80),
        new("EVENT_RECORD", Marshal.SizeOf<NativeEtw.EVENT_RECORD>(), 112),
        new("EVENT_TRACE_HEADER", Marshal.SizeOf<NativeEtw.EVENT_TRACE_HEADER>(), 48),
        new("EVENT_TRACE", Marshal.SizeOf<NativeEtw.EVENT_TRACE>(), 88),
        new("TIME_ZONE_INFORMATION", Marshal.SizeOf<NativeEtw.TIME_ZONE_INFORMATION>(), 172),
        new("TRACE_LOGFILE_HEADER", Marshal.SizeOf<NativeEtw.TRACE_LOGFILE_HEADER>(), 280),
        new("EVENT_TRACE_LOGFILE", Marshal.SizeOf<NativeEtw.EVENT_TRACE_LOGFILE>(), 448),
        new("PROPERTY_DATA_DESCRIPTOR", Marshal.SizeOf<NativeEtw.PROPERTY_DATA_DESCRIPTOR>(), 16),
    ];

    public sealed record ManifestProbe(int EventId, int Version, List<string> Properties);

    /// <summary>
    /// 세션 없이 매니페스트를 조회한다. 합성 EVENT_RECORD 에 프로바이더 GUID 와 이벤트 서술자만
    /// 채우면 TDH 가 시스템에 등록된 매니페스트를 찾아 속성 목록을 돌려준다.
    ///
    /// 이게 성공한다는 것은 (a) tdh.dll P/Invoke 서명이 맞고 (b) EVENT_RECORD 레이아웃이 맞고
    /// (c) 이 기기에 Kernel-Process 매니페스트가 있다는 뜻이다. 실제 세션에서 남는 미검증 변수는
    /// "커널이 실제로 이벤트를 보내는가" 하나뿐이 된다.
    /// </summary>
    public static ManifestProbe? ProbeManifest(int eventId)
    {
        // 매니페스트 버전은 Windows 빌드마다 다르다. 해석되는 첫 버전을 쓴다.
        for (byte version = 0; version <= 6; version++)
        {
            var record = new NativeEtw.EVENT_RECORD
            {
                EventHeader = new NativeEtw.EVENT_HEADER
                {
                    Size = (ushort)Marshal.SizeOf<NativeEtw.EVENT_HEADER>(),
                    Flags = 0x0040, // EVENT_HEADER_FLAG_64_BIT_HEADER
                    ProviderId = NativeEtw.KernelProcessProvider,
                    EventDescriptor = new NativeEtw.EVENT_DESCRIPTOR
                    {
                        Id = (ushort)eventId,
                        Version = version,
                        Level = 4,
                        Keyword = NativeEtw.KeywordProcess | NativeEtw.KeywordImage,
                    },
                },
            };

            var names = TdhReader.PropertyNames(ref record);
            if (names.Count > 0) return new ManifestProbe(eventId, version, names);
        }
        return null;
    }

    public sealed record SessionProbe(bool Started, int Win32Error, string Message);

    /// <summary>
    /// 실제로 실시간 세션을 열어 본다. 실패하면 정확한 이유를 남긴다 —
    /// 설계서 14장 미결 2번(관리자 대신 Performance Log Users 로 충분한가)이 여기 걸려 있다.
    /// </summary>
    public static SessionProbe ProbeSession()
    {
        using var session = new EtwSession($"OwlWatch-Probe-{Environment.ProcessId}");
        var ok = session.Start(NativeEtw.KernelProcessProvider,
            NativeEtw.KeywordProcess | NativeEtw.KeywordImage);

        return ok
            ? new SessionProbe(true, 0, "실시간 세션을 열었다 — 이 계정으로 커널 원장을 돌릴 수 있다")
            : new SessionProbe(false, session.LastError, session.FailureReason ?? "알 수 없는 실패");
    }

    /// <summary>설계서 05장 S9 · S11 이 쓰는 이벤트.</summary>
    public static readonly (int Id, string Name)[] LedgerEvents =
    [
        (NativeEtw.EventProcessStart, "ProcessStart — S9 exec"),
        (NativeEtw.EventProcessStop, "ProcessStop — S9 exit"),
        (NativeEtw.EventImageLoad, "ImageLoad — S11 캡처 스택"),
    ];
}
