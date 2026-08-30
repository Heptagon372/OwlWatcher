using System.Runtime.InteropServices;

namespace OwlWatch.Collectors.Etw;

/// <summary>
/// ETW 실시간 세션과 TDH 파싱용 P/Invoke.
///
/// NuGet 의 TraceEvent 패키지를 쓰지 않는다 — 저장소 전체가 의존성 0 이고,
/// 시험장 PC 에 오프라인으로 배포해야 하며, "무엇을 안 하는지"를 코드로 증명해야 하기 때문이다.
/// 대신 여기 있는 것이 커널에 묻는 것의 전부다.
///
/// 구독 범위는 Microsoft-Windows-Kernel-Process 의 Process·Image 키워드뿐이다.
/// 파일 내용·레지스트리·네트워크 페이로드 계열 커널 프로바이더는 구독하지 않는다
/// (설계서 10장: 구독 목록 자체가 감사 대상).
/// </summary>
internal static class NativeEtw
{
    // ── 프로바이더

    /// <summary>Microsoft-Windows-Kernel-Process</summary>
    public static readonly Guid KernelProcessProvider = new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

    /// <summary>WINEVENT_KEYWORD_PROCESS. 프로세스 시작·종료.</summary>
    public const ulong KeywordProcess = 0x0000000000000010;

    /// <summary>WINEVENT_KEYWORD_IMAGE. 이미지 로드 — S11 캡처 스택 탐지의 입력.</summary>
    public const ulong KeywordImage = 0x0000000000000040;

    /// <summary>Kernel-Process 이벤트 ID. 매니페스트 기준.</summary>
    public const int EventProcessStart = 1;
    public const int EventProcessStop = 2;
    public const int EventImageLoad = 5;

    // ── 세션 제어 (advapi32)

    public const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
    public const uint WNODE_FLAG_TRACED_GUID = 0x00020000;

    public const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
    public const uint EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0;

    public const uint EVENT_TRACE_CONTROL_STOP = 1;
    public const uint EVENT_TRACE_CONTROL_QUERY = 0;

    public const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
    public const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;

    public const ulong INVALID_PROCESSTRACE_HANDLE = unchecked(0xFFFFFFFFFFFFFFFF);

    public const int ERROR_SUCCESS = 0;
    public const int ERROR_ACCESS_DENIED = 5;
    public const int ERROR_ALREADY_EXISTS = 183;
    public const int ERROR_INSUFFICIENT_BUFFER = 122;
    public const int ERROR_NOT_FOUND = 1168;
    public const int ERROR_WMI_INSTANCE_NOT_FOUND = 4201;
    public const int ERROR_CANCELLED = 1223;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "StartTraceW")]
    public static extern int StartTrace(out ulong sessionHandle, string sessionName, IntPtr properties);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "ControlTraceW")]
    public static extern int ControlTrace(ulong sessionHandle, string? sessionName, IntPtr properties, uint controlCode);

    [DllImport("advapi32.dll")]
    public static extern int EnableTraceEx2(ulong sessionHandle, ref Guid providerId, uint controlCode,
        byte level, ulong matchAnyKeyword, ulong matchAllKeyword, uint timeout, IntPtr enableParameters);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "OpenTraceW")]
    public static extern ulong OpenTrace(ref EVENT_TRACE_LOGFILE logfile);

    [DllImport("advapi32.dll")]
    public static extern int ProcessTrace(ulong[] handleArray, uint handleCount, IntPtr startTime, IntPtr endTime);

    [DllImport("advapi32.dll")]
    public static extern int CloseTrace(ulong traceHandle);

    // ── 구조체
    //
    // 레이아웃을 하나라도 틀리면 OpenTrace 가 조용히 이상하게 동작한다.
    // 그래서 EtwSelfTest 가 Marshal.SizeOf 를 알려진 값과 대조한다.

    [StructLayout(LayoutKind.Sequential)]
    public struct WNODE_HEADER
    {
        public uint BufferSize;
        public uint ProviderId;
        public ulong HistoricalContext;
        public long TimeStamp;
        public Guid Guid;
        public uint ClientContext;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EVENT_TRACE_PROPERTIES
    {
        public WNODE_HEADER Wnode;
        public uint BufferSize;
        public uint MinimumBuffers;
        public uint MaximumBuffers;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint FlushTimer;
        public uint EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers;
        public uint FreeBuffers;
        public uint EventsLost;
        public uint BuffersWritten;
        public uint LogBuffersLost;
        public uint RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset;
        public uint LoggerNameOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EVENT_DESCRIPTOR
    {
        public ushort Id;
        public byte Version;
        public byte Channel;
        public byte Level;
        public byte Opcode;
        public ushort Task;
        public ulong Keyword;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EVENT_HEADER
    {
        public ushort Size;
        public ushort HeaderType;
        public ushort Flags;
        public ushort EventProperty;
        public uint ThreadId;
        public uint ProcessId;
        public long TimeStamp;
        public Guid ProviderId;
        public EVENT_DESCRIPTOR EventDescriptor;
        public ulong ProcessorTime;
        public Guid ActivityId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ETW_BUFFER_CONTEXT
    {
        public byte ProcessorNumber;
        public byte Alignment;
        public ushort LoggerId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EVENT_RECORD
    {
        public EVENT_HEADER EventHeader;
        public ETW_BUFFER_CONTEXT BufferContext;
        public ushort ExtendedDataCount;
        public ushort UserDataLength;
        public IntPtr ExtendedData;
        public IntPtr UserData;
        public IntPtr UserContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EVENT_TRACE_HEADER
    {
        public ushort Size;
        public ushort FieldTypeFlags;
        public uint Version;
        public uint ThreadId;
        public uint ProcessId;
        public long TimeStamp;
        public Guid Guid;
        public uint ClientContext;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EVENT_TRACE
    {
        public EVENT_TRACE_HEADER Header;
        public uint InstanceId;
        public uint ParentInstanceId;
        public Guid ParentGuid;
        public IntPtr MofData;
        public uint MofLength;
        public ETW_BUFFER_CONTEXT BufferContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEMTIME
    {
        public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct TIME_ZONE_INFORMATION
    {
        public int Bias;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string StandardName;
        public SYSTEMTIME StandardDate;
        public int StandardBias;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DaylightName;
        public SYSTEMTIME DaylightDate;
        public int DaylightBias;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct TRACE_LOGFILE_HEADER
    {
        public uint BufferSize;
        public uint Version;
        public uint ProviderVersion;
        public uint NumberOfProcessors;
        public long EndTime;
        public uint TimerResolution;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint BuffersWritten;
        public Guid LogInstanceGuid;
        public IntPtr LoggerName;
        public IntPtr LogFileName;
        public TIME_ZONE_INFORMATION TimeZone;
        public long BootTime;
        public long PerfFreq;
        public long StartTime;
        public uint ReservedFlags;
        public uint BuffersLost;
    }

    public delegate void EventRecordCallback(ref EVENT_RECORD eventRecord);
    public delegate uint BufferCallback(IntPtr logfile);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct EVENT_TRACE_LOGFILE
    {
        public IntPtr LogFileName;
        public IntPtr LoggerName;
        public long CurrentTime;
        public uint BuffersRead;
        public uint ProcessTraceMode;
        public EVENT_TRACE CurrentEvent;
        public TRACE_LOGFILE_HEADER LogfileHeader;
        public IntPtr BufferCallback;
        public uint BufferSize;
        public uint Filled;
        public uint EventsLost;
        public IntPtr EventRecordCallback;
        public uint IsKernelTrace;
        public IntPtr Context;
    }

    // ── TDH · 이벤트 속성 추출
    //
    // 매니페스트 레이아웃을 손으로 파싱하지 않는다. Windows 빌드마다 필드가 추가되고,
    // 손으로 파싱하면 조용히 틀린 pid 를 만들어 낸다 — P0 근거를 다루는 코드에서 그건 최악이다.

    [DllImport("tdh.dll", CharSet = CharSet.Unicode)]
    public static extern int TdhGetEventInformation(ref EVENT_RECORD evt, uint tdhContextCount,
        IntPtr tdhContext, IntPtr buffer, ref uint bufferSize);

    [DllImport("tdh.dll", CharSet = CharSet.Unicode)]
    public static extern int TdhGetProperty(ref EVENT_RECORD evt, uint tdhContextCount, IntPtr tdhContext,
        uint propertyDataCount, ref PROPERTY_DATA_DESCRIPTOR propertyData, uint bufferSize, byte[] buffer);

    [DllImport("tdh.dll", CharSet = CharSet.Unicode)]
    public static extern int TdhGetPropertySize(ref EVENT_RECORD evt, uint tdhContextCount, IntPtr tdhContext,
        uint propertyDataCount, ref PROPERTY_DATA_DESCRIPTOR propertyData, out uint propertySize);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROPERTY_DATA_DESCRIPTOR
    {
        public ulong PropertyName;  // wide string 포인터
        public uint ArrayIndex;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TRACE_EVENT_INFO
    {
        public Guid ProviderGuid;
        public Guid EventGuid;
        public EVENT_DESCRIPTOR EventDescriptor;
        public uint DecodingSource;
        public uint ProviderNameOffset;
        public uint LevelNameOffset;
        public uint ChannelNameOffset;
        public uint KeywordsNameOffset;
        public uint TaskNameOffset;
        public uint OpcodeNameOffset;
        public uint EventMessageOffset;
        public uint ProviderMessageOffset;
        public uint BinaryXMLOffset;
        public uint BinaryXMLSize;
        public uint EventNameOffset;      // union: ActivityIDNameOffset
        public uint EventAttributesOffset; // union: RelatedActivityIDNameOffset
        public uint PropertyCount;
        public uint TopLevelPropertyCount;
        public uint Flags;
        // 뒤에 EVENT_PROPERTY_INFO 배열이 이어진다.
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EVENT_PROPERTY_INFO
    {
        public uint Flags;
        public uint NameOffset;
        public ushort InTypeOrStructStartIndex;
        public ushort OutTypeOrNumOfStructMembers;
        public uint MapNameOffsetOrPadding;
        public ushort CountOrCountPropertyIndex;
        public ushort LengthOrLengthPropertyIndex;
        public uint ReservedTags;
    }
}
