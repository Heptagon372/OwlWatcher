using System.Runtime.InteropServices;

namespace OwlWatch.Collectors.Etw;

/// <summary>
/// ETW 실시간 세션 하나. 열고 → 프로바이더를 켜고 → 백그라운드에서 소비한다.
///
/// 실시간 세션은 관리자 또는 Performance Log Users 권한이 필요하다. 그래서 설계서는
/// 이걸 서비스로 돌리라고 하고(M3), 권한이 없으면 여기서 정확한 이유를 남기고 실패한다.
/// **실패를 감추지 않는 것이 중요하다** — 원장이 안 도는데 도는 척하면 등급 모델이 무너진다.
/// </summary>
internal sealed class EtwSession : IDisposable
{
    private readonly string _sessionName;
    private ulong _sessionHandle;
    private ulong _traceHandle = NativeEtw.INVALID_PROCESSTRACE_HANDLE;
    private IntPtr _properties = IntPtr.Zero;
    private Thread? _consumer;
    private NativeEtw.EventRecordCallback? _callback;   // GC 로부터 보호
    private NativeEtw.BufferCallback? _bufferCallback;
    private volatile bool _stopping;

    public bool Running { get; private set; }
    public string? FailureReason { get; private set; }
    public int LastError { get; private set; }

    public EtwSession(string sessionName) => _sessionName = sessionName;

    /// <summary>
    /// 세션을 열고 프로바이더를 켠다. 실패하면 false 와 함께 FailureReason 이 채워진다.
    /// </summary>
    public bool Start(Guid provider, ulong keywords, byte level = 4 /* Informational */)
    {
        // EVENT_TRACE_PROPERTIES 뒤에 세션 이름이 이어지는 단일 버퍼.
        var propsSize = Marshal.SizeOf<NativeEtw.EVENT_TRACE_PROPERTIES>();
        var nameBytes = (_sessionName.Length + 1) * 2;
        var total = propsSize + nameBytes;

        _properties = Marshal.AllocHGlobal(total);
        for (var i = 0; i < total; i++) Marshal.WriteByte(_properties, i, 0);

        var props = new NativeEtw.EVENT_TRACE_PROPERTIES
        {
            Wnode = new NativeEtw.WNODE_HEADER
            {
                BufferSize = (uint)total,
                Flags = NativeEtw.WNODE_FLAG_TRACED_GUID,
                ClientContext = 1, // QPC
            },
            BufferSize = 64,
            MinimumBuffers = 4,
            MaximumBuffers = 64,
            LogFileMode = NativeEtw.EVENT_TRACE_REAL_TIME_MODE,
            FlushTimer = 1,
            LoggerNameOffset = (uint)propsSize,
        };
        Marshal.StructureToPtr(props, _properties, false);

        var rc = NativeEtw.StartTrace(out _sessionHandle, _sessionName, _properties);

        if (rc == NativeEtw.ERROR_ALREADY_EXISTS)
        {
            // 이전 실행이 남긴 세션. 정리하고 한 번 더.
            NativeEtw.ControlTrace(0, _sessionName, _properties, NativeEtw.EVENT_TRACE_CONTROL_STOP);
            Marshal.StructureToPtr(props, _properties, false);
            rc = NativeEtw.StartTrace(out _sessionHandle, _sessionName, _properties);
        }

        if (rc != NativeEtw.ERROR_SUCCESS)
        {
            LastError = rc;
            FailureReason = Explain(rc);
            Cleanup();
            return false;
        }

        rc = NativeEtw.EnableTraceEx2(_sessionHandle, ref provider,
            NativeEtw.EVENT_CONTROL_CODE_ENABLE_PROVIDER, level, keywords, 0, 0, IntPtr.Zero);
        if (rc != NativeEtw.ERROR_SUCCESS)
        {
            LastError = rc;
            FailureReason = $"프로바이더를 켜지 못했다 (EnableTraceEx2 = {rc})";
            Stop();
            return false;
        }

        Running = true;
        return true;
    }

    /// <summary>
    /// 이벤트 하나를 다루는 핸들러. ref 로 받는 이유가 있다 — EVENT_RECORD 의 UserData 포인터는
    /// 콜백이 반환하는 순간 무효가 되므로, 속성 추출은 반드시 콜백 안에서 끝나야 한다.
    /// 해시·서명 같은 비싼 작업은 나중으로 미룬다.
    /// </summary>
    internal delegate void RecordHandler(ref NativeEtw.EVENT_RECORD record);

    /// <summary>백그라운드에서 이벤트를 소비한다. ProcessTrace 는 세션이 멈출 때까지 블록한다.</summary>
    public void Consume(RecordHandler onEvent)
    {
        if (!Running) throw new InvalidOperationException("세션이 열려 있지 않다");

        _callback = (ref NativeEtw.EVENT_RECORD record) =>
        {
            if (_stopping) return;
            try { onEvent(ref record); }
            catch { /* 한 이벤트가 실패해도 원장은 계속 돈다 */ }
        };
        _bufferCallback = _ => _stopping ? 0u : 1u;

        var logfile = new NativeEtw.EVENT_TRACE_LOGFILE
        {
            LoggerName = Marshal.StringToHGlobalUni(_sessionName),
            ProcessTraceMode = NativeEtw.PROCESS_TRACE_MODE_REAL_TIME | NativeEtw.PROCESS_TRACE_MODE_EVENT_RECORD,
            EventRecordCallback = Marshal.GetFunctionPointerForDelegate(_callback),
            BufferCallback = Marshal.GetFunctionPointerForDelegate(_bufferCallback),
        };

        _traceHandle = NativeEtw.OpenTrace(ref logfile);
        if (_traceHandle == NativeEtw.INVALID_PROCESSTRACE_HANDLE)
        {
            LastError = Marshal.GetLastWin32Error();
            FailureReason = $"OpenTrace 실패 ({LastError})";
            Running = false;
            return;
        }

        _consumer = new Thread(() =>
        {
            var handles = new[] { _traceHandle };
            var rc = NativeEtw.ProcessTrace(handles, 1, IntPtr.Zero, IntPtr.Zero);
            if (rc != NativeEtw.ERROR_SUCCESS && rc != NativeEtw.ERROR_CANCELLED && !_stopping)
            {
                LastError = rc;
                FailureReason = $"ProcessTrace 종료 ({rc})";
            }
            Running = false;
        })
        {
            IsBackground = true,
            Name = "owlwatch-etw",
        };
        _consumer.Start();
    }

    public void Stop()
    {
        _stopping = true;

        if (_sessionHandle != 0 && _properties != IntPtr.Zero)
            NativeEtw.ControlTrace(_sessionHandle, null, _properties, NativeEtw.EVENT_TRACE_CONTROL_STOP);

        if (_traceHandle != NativeEtw.INVALID_PROCESSTRACE_HANDLE)
        {
            NativeEtw.CloseTrace(_traceHandle);
            _traceHandle = NativeEtw.INVALID_PROCESSTRACE_HANDLE;
        }

        try { _consumer?.Join(TimeSpan.FromSeconds(3)); } catch { /* 종료 중 */ }
        Running = false;
        Cleanup();
    }

    private void Cleanup()
    {
        if (_properties != IntPtr.Zero) { Marshal.FreeHGlobal(_properties); _properties = IntPtr.Zero; }
        _sessionHandle = 0;
    }

    public void Dispose() => Stop();

    /// <summary>
    /// 실패 이유를 감독관·운영자가 조치할 수 있는 말로 바꾼다.
    /// 설계서 14장 미결 2번(Performance Log Users 로 충분한가)이 여기 걸려 있다.
    /// </summary>
    public static string Explain(int rc) => rc switch
    {
        NativeEtw.ERROR_ACCESS_DENIED =>
            "ETW 실시간 세션을 열 권한이 없다 (ERROR_ACCESS_DENIED). " +
            "관리자로 실행하거나 계정을 Performance Log Users 그룹에 넣어야 한다. " +
            "설계서는 이 때문에 원장을 서비스로 돌리라고 한다(M3).",
        NativeEtw.ERROR_ALREADY_EXISTS =>
            "같은 이름의 세션이 이미 있다. 이전 실행이 남긴 것이면 logman stop 으로 지운다.",
        _ => $"세션을 열지 못했다 (Win32 {rc})",
    };
}
