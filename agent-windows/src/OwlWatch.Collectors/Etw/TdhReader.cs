using System.Runtime.InteropServices;
using System.Text;

namespace OwlWatch.Collectors.Etw;

/// <summary>
/// EVENT_RECORD 에서 이름으로 속성을 뽑는다.
///
/// 매니페스트 레이아웃을 손으로 파싱하지 않는 이유: Kernel-Process 의 ProcessStart 는
/// Windows 버전마다 필드가 붙었다(ImageChecksum · TimeDateStamp · PackageFullName …).
/// 오프셋을 박아 두면 다른 빌드에서 **조용히 틀린 pid** 를 만들어 낸다.
/// 원장은 P0 근거이므로, 틀린 값을 내느니 값을 못 내는 편이 낫다.
/// </summary>
internal static class TdhReader
{
    public static uint? GetUInt32(ref NativeEtw.EVENT_RECORD evt, string property)
    {
        var bytes = GetBytes(ref evt, property);
        return bytes is { Length: >= 4 } ? BitConverter.ToUInt32(bytes, 0) : null;
    }

    public static ulong? GetUInt64(ref NativeEtw.EVENT_RECORD evt, string property)
    {
        var bytes = GetBytes(ref evt, property);
        return bytes is { Length: >= 8 } ? BitConverter.ToUInt64(bytes, 0) : null;
    }

    public static string? GetString(ref NativeEtw.EVENT_RECORD evt, string property)
    {
        var bytes = GetBytes(ref evt, property);
        if (bytes is null || bytes.Length < 2) return null;
        var s = Encoding.Unicode.GetString(bytes);
        var nul = s.IndexOf('\0');
        if (nul >= 0) s = s[..nul];
        return string.IsNullOrEmpty(s) ? null : s;
    }

    public static byte[]? GetBytes(ref NativeEtw.EVENT_RECORD evt, string property)
    {
        var name = Marshal.StringToHGlobalUni(property);
        try
        {
            var desc = new NativeEtw.PROPERTY_DATA_DESCRIPTOR
            {
                PropertyName = (ulong)name.ToInt64(),
                ArrayIndex = uint.MaxValue,
            };

            if (NativeEtw.TdhGetPropertySize(ref evt, 0, IntPtr.Zero, 1, ref desc, out var size) != 0) return null;
            if (size == 0 || size > 64 * 1024) return null;

            var buffer = new byte[size];
            return NativeEtw.TdhGetProperty(ref evt, 0, IntPtr.Zero, 1, ref desc, size, buffer) == 0
                ? buffer
                : null;
        }
        finally { Marshal.FreeHGlobal(name); }
    }

    /// <summary>
    /// 이 이벤트가 어떤 속성을 가지고 있는지 매니페스트에서 읽는다.
    /// 세션 없이도 부를 수 있어서, 자가검사가 TDH 배관과 매니페스트 조회를 확인하는 데 쓴다.
    /// </summary>
    public static List<string> PropertyNames(ref NativeEtw.EVENT_RECORD evt)
    {
        var names = new List<string>();
        uint size = 0;
        var rc = NativeEtw.TdhGetEventInformation(ref evt, 0, IntPtr.Zero, IntPtr.Zero, ref size);
        if (rc != NativeEtw.ERROR_INSUFFICIENT_BUFFER || size == 0) return names;

        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            if (NativeEtw.TdhGetEventInformation(ref evt, 0, IntPtr.Zero, buffer, ref size) != 0) return names;

            var info = Marshal.PtrToStructure<NativeEtw.TRACE_EVENT_INFO>(buffer);
            var propSize = Marshal.SizeOf<NativeEtw.EVENT_PROPERTY_INFO>();
            var arrayStart = buffer + Marshal.SizeOf<NativeEtw.TRACE_EVENT_INFO>();

            for (var i = 0; i < info.TopLevelPropertyCount && i < 128; i++)
            {
                var p = Marshal.PtrToStructure<NativeEtw.EVENT_PROPERTY_INFO>(arrayStart + i * propSize);
                if (p.NameOffset == 0 || p.NameOffset >= size) continue;
                var name = Marshal.PtrToStringUni(buffer + (int)p.NameOffset);
                if (!string.IsNullOrEmpty(name)) names.Add(name);
            }
        }
        catch
        {
            // 매니페스트를 읽지 못했다. 빈 목록이 곧 "확인 못 함"이다.
        }
        finally { Marshal.FreeHGlobal(buffer); }

        return names;
    }
}
