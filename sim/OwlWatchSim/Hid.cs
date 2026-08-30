using System.Runtime.InteropServices;
using System.Text;

namespace OwlWatchSim;

/// <summary>
/// HID 키보드 장치 탐색 — 시나리오 (c) 이자 설계서 14장 미결 3번의 실험.
///
/// 묻는 것은 하나다. 비관리자 앱이 Caps Lock 의 <em>상태</em>를 바꾸지 않고
/// <em>LED 만</em> 켤 수 있는가?
///
/// 가능하다면 Windows 의 S12 에 구멍이 생긴다 — 커닝 도구가 상태를 토글하지 않고
/// LED 로만 신호를 보낼 수 있고, 그러면 S4(Caps Lock 상태 폴링)가 아무것도 못 본다.
/// 설계서 05장 S12 의 Windows 칸은 "실사용 도구는 실제 상태를 토글하게 된다"를
/// 전제로 쓰였으므로, 그 전제가 틀리면 설계서를 고쳐야 한다.
///
/// 그래서 이 코드는 "된다/안 된다"를 추측하지 않고 실제로 열고 실제로 써 본다.
/// </summary>
internal static class Hid
{
    public sealed record ProbeResult(
        int Total, int Keyboards, int Opened, int LedWrites,
        List<IntPtr> Handles, List<string> Notes);

    public static ProbeResult ProbeKeyboards()
    {
        var handles = new List<IntPtr>();
        var notes = new List<string>();
        int total = 0, keyboards = 0, opened = 0, ledWrites = 0;

        Native.HidD_GetHidGuid(out var hidGuid);
        var set = Native.SetupDiGetClassDevs(ref hidGuid, IntPtr.Zero, IntPtr.Zero,
            Native.DIGCF_PRESENT | Native.DIGCF_DEVICEINTERFACE);
        if (set == Native.INVALID_HANDLE_VALUE)
        {
            notes.Add("SetupDiGetClassDevs 실패 — HID 인터페이스를 열거하지 못했다");
            return new ProbeResult(0, 0, 0, 0, handles, notes);
        }

        try
        {
            for (uint i = 0; ; i++)
            {
                var did = new Native.SP_DEVICE_INTERFACE_DATA
                {
                    cbSize = Marshal.SizeOf<Native.SP_DEVICE_INTERFACE_DATA>(),
                };
                if (!Native.SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref hidGuid, i, ref did)) break;
                total++;

                var path = InterfacePath(set, ref did);
                if (path is null) continue;

                // 읽기/쓰기로 연다. 키보드 인터페이스는 배타 접근이 걸려 있는 경우가 많아
                // 실패하는 것이 정상이며, 그 실패 자체가 답의 일부다.
                var h = Native.CreateFile(path, Native.GENERIC_READ | Native.GENERIC_WRITE,
                    Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, IntPtr.Zero,
                    Native.OPEN_EXISTING, 0, IntPtr.Zero);

                if (h == Native.INVALID_HANDLE_VALUE)
                {
                    // 읽기 전용으로는 열릴 수 있다. 여는 행위 자체가 macOS 라면 S12 로 잡히는 사건이다.
                    h = Native.CreateFile(path, 0,
                        Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, IntPtr.Zero,
                        Native.OPEN_EXISTING, 0, IntPtr.Zero);
                    if (h == Native.INVALID_HANDLE_VALUE) continue;
                }
                opened++;

                if (!IsKeyboard(h, out var caps)) { Native.CloseHandle(h); continue; }
                keyboards++;

                var product = ProductString(h);
                if (product is not null) notes.Add($"키보드: {product}");

                if (TryBlinkLed(h, caps)) ledWrites++;
                handles.Add(h);
            }
        }
        finally
        {
            Native.SetupDiDestroyDeviceInfoList(set);
        }

        return new ProbeResult(total, keyboards, opened, ledWrites, handles, notes);
    }

    /// <summary>
    /// SP_DEVICE_INTERFACE_DETAIL_DATA 는 가변 길이라 직접 버퍼를 잡는다.
    /// cbSize 는 구조체 전체 크기가 아니라 헤더 크기다 — 64비트에서 8, 32비트에서 6.
    /// 여기를 틀리면 ERROR_INVALID_USER_BUFFER 가 나고 아무것도 열거되지 않는다.
    /// </summary>
    private static string? InterfacePath(IntPtr set, ref Native.SP_DEVICE_INTERFACE_DATA did)
    {
        Native.SetupDiGetDeviceInterfaceDetail(set, ref did, IntPtr.Zero, 0, out var required, IntPtr.Zero);
        if (required == 0) return null;

        var buffer = Marshal.AllocHGlobal((int)required);
        try
        {
            Marshal.WriteInt32(buffer, IntPtr.Size == 8 ? 8 : 4 + Marshal.SystemDefaultCharSize);
            if (!Native.SetupDiGetDeviceInterfaceDetail(set, ref did, buffer, required, out _, IntPtr.Zero))
                return null;
            return Marshal.PtrToStringUni(buffer + 4);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static bool IsKeyboard(IntPtr h, out Native.HIDP_CAPS caps)
    {
        caps = default;
        if (!Native.HidD_GetPreparsedData(h, out var pre) || pre == IntPtr.Zero) return false;
        try
        {
            var c = new Native.HIDP_CAPS { Reserved = new ushort[17] };
            if (Native.HidP_GetCaps(pre, ref c) != 0x00110000) return false; // HIDP_STATUS_SUCCESS
            caps = c;
            return c.UsagePage == Native.UsagePageGenericDesktop && c.Usage == Native.UsageKeyboard;
        }
        finally { Native.HidD_FreePreparsedData(pre); }
    }

    private static string? ProductString(IntPtr h)
    {
        var buf = new byte[254];
        if (!Native.HidD_GetProductString(h, buf, buf.Length)) return null;
        var s = Encoding.Unicode.GetString(buf).TrimEnd('\0');
        return string.IsNullOrWhiteSpace(s) ? null : s;
    }

    /// <summary>
    /// LED 출력 리포트를 실제로 보낸다. 현재 상태를 반전했다가 200ms 뒤 되돌린다 —
    /// 눈으로 확인할 수 있으면서 끝나고 나면 원래 상태로 남는다.
    /// 성공하면 "비관리자 앱이 Caps Lock 상태를 바꾸지 않고 LED 만 제어할 수 있다"가 증명된다.
    /// </summary>
    private static bool TryBlinkLed(IntPtr h, Native.HIDP_CAPS caps)
    {
        var len = caps.OutputReportByteLength;
        if (len < 2) return false;

        var capsOn = (Native.GetKeyState(Native.VK_CAPITAL) & 1) != 0;
        const byte capsLockBit = 0x02; // HID LED usage: 1=NumLock, 2=CapsLock, 4=ScrollLock

        var report = new byte[len];
        report[0] = 0;                                    // report ID
        report[1] = (byte)(capsOn ? 0 : capsLockBit);     // 현재와 반대로

        if (!Native.HidD_SetOutputReport(h, report, len)) return false;

        Thread.Sleep(200);
        report[1] = (byte)(capsOn ? capsLockBit : 0);     // 원래대로
        Native.HidD_SetOutputReport(h, report, len);
        return true;
    }
}
