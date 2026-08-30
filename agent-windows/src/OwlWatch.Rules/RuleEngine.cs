using System.Globalization;
using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Rules;

/// <summary>
/// 탐지 규칙 · 등급 판정. core-rules/src/engine.js 의 포트.
///
/// 순수 함수다 — 시계도, 파일도, 네트워크도 만지지 않는다. 모든 시각은 관측에서 온다.
/// 그래야 spec/fixtures 로 재현되고 레퍼런스 구현과 체인 해시가 맞는다(설계서 G3 · 12장).
/// </summary>
public static class RuleEngine
{
    /// <summary>관측 출처가 등급의 상한을 정한다. 설계서 02장 "P0에는 휴리스틱을 넣지 않는다".</summary>
    public static string SourceGrade(string? source) => source switch
    {
        "kernel" or "server" or "selfverify" => "P0",
        _ => "P1",
    };

    private static readonly string[] HidClasses =
        { "IOHIDLibUserClient", "IOHIDDeviceUserClient", "AppleHIDKeyboardEventDriver" };

    public sealed class Result
    {
        public List<JsonObject> Events = new();
        public JsonObject HeartbeatSummary = new();
    }

    private sealed class Draft
    {
        public string Rule = "";
        public string Grade = "";
        public string Severity = "";
        public List<string> Signals = new();
        public JsonObject Subject = new();
        public JsonObject? Obs;
        public string Detail = "";
        public string Ts = "";
        public List<string> Contexts = new();
        public JsonArray EvidenceObs = new();
        public List<string> Notes = new();
        public List<string>? EscalatedFrom;
    }

    private sealed class Ctx
    {
        public Policy Policy = null!;
        public SessionInfo Session = null!;
        public EngineState State = null!;
        public List<Draft> Drafts = new();
        public Dictionary<string, List<string>> Seen = new(StringComparer.Ordinal);

        public long Th(string k, long d) => Policy.Th(k, d);
        public void See(string kind, string key)
        {
            if (!Seen.TryGetValue(kind, out var l)) { l = new List<string>(); Seen[kind] = l; }
            l.Add(key);
        }
    }

    private static long Ms(string ts) =>
        DateTimeOffset.Parse(ts, CultureInfo.InvariantCulture).ToUnixTimeMilliseconds();

    /// <summary>engine.js procKey(). 이름이 아니라 해시가 대상의 키다.</summary>
    public static string ProcKey(JsonObject o)
    {
        var sha = o.Str("sha256");
        if (!string.IsNullOrEmpty(sha)) return $"proc:sha256:{sha}";
        var cd = o.Str("cdhash");
        if (!string.IsNullOrEmpty(cd)) return $"proc:cdhash:{cd}";
        var p = (o.Str("path") ?? o.Str("ownerPath") ?? "unknown").Replace('\\', '/').ToLowerInvariant();
        return $"proc:path:{p}";
    }

    private static string ProcKey(LedgerRec r)
    {
        if (!string.IsNullOrEmpty(r.Sha256)) return $"proc:sha256:{r.Sha256}";
        var p = (r.Path ?? "unknown").Replace('\\', '/').ToLowerInvariant();
        return $"proc:path:{p}";
    }

    public static Result Evaluate(
        IReadOnlyList<JsonObject> observations,
        IReadOnlyList<string> scanned,
        Policy policy,
        SessionInfo session,
        EngineState state)
    {
        var ctx = new Ctx { Policy = policy, Session = session, State = state };

        // ── 0단계 · 원장 색인
        foreach (var o in observations)
        {
            var kind = o.Str("kind");
            var source = o.Str("source");
            if (kind == "exec" && source == "kernel")
            {
                var pid = o.Int("pid") ?? -1;
                state.LedgerPids[pid] = new LedgerRec { Src = o };
                state.LedgerExited.Remove(pid);
                state.Counters.LedgerExecs++;
            }
            else if (kind == "exec")
            {
                state.Counters.LedgerExecs++;
            }
            if (kind == "process" && o.Str("note") == "exit")
                state.LedgerExited.Add(o.Int("pid") ?? -1);
        }

        // PRECHECK 의 첫 완전열거가 기준선. 이전부터 돌던 프로세스를 "원장에 없다"는 이유로
        // 잡으면 좌석마다 오탐이 쏟아진다.
        if (!state.BaselineCaptured && scanned.Contains("process"))
        {
            foreach (var o in observations)
                if (o.Str("kind") == "process") state.BaselinePids.Add(o.Int("pid") ?? -1);
            state.BaselineCaptured = true;
        }

        // ── 1단계 · 관측별 규칙
        foreach (var o in observations)
        {
            switch (o.Str("kind"))
            {
                case "exec": RuleExec(ctx, o); break;
                case "process": RuleProcess(ctx, o); break;
                case "statusItem": RuleStatusItem(ctx, o); break;
                case "captureExcludedWindow": RuleExcludedWindow(ctx, o); break;
                case "capsTransition": state.CapsBuffer.Add(new CapsSample { TsMs = Ms(o.Str("ts")!), Obs = o }); break;
                case "imageLoad": RuleImageLoad(ctx, o); break;
                case "iokitOpen": RuleIokitOpen(ctx, o); break;
                case "tccGrant": RuleTccGrant(ctx, o); break;
                case "netPosture": RuleNetPosture(ctx, o); break;
                case "procConnection": break; // 증거로만 보관
                case "vmIndicator": RuleVm(ctx, o); break;
                case "remoteControlProcess": RuleRemote(ctx, o); break;
                case "lockdownState": RuleLockdown(ctx, o); break;
                case "captureGuard": RuleCaptureGuard(ctx, o); break;
                case "agentIntegrity": RuleIntegrity(ctx, o); break;
                case "attestation": RuleAttestation(ctx, o); break;
            }
        }

        // ── 2단계 · Caps Lock 주기
        RuleCapsPattern(ctx);

        // ── 3단계 · 원장 상관
        RuleLedgerCorrelation(ctx, observations, scanned);

        // ── 4단계 · 완전열거 대상의 소멸
        var lastTs = observations.Count > 0 ? observations[^1].Str("ts") : null;
        foreach (var kind in scanned)
        {
            var now = ctx.Seen.TryGetValue(kind, out var n) ? n : new List<string>();
            var before = state.Presence.TryGetValue(kind, out var b) ? b : new List<string>();
            foreach (var key in before)
            {
                if (now.Contains(key)) continue;
                Push(ctx, new Draft
                {
                    Rule = "R-SUBJECT-CLEARED",
                    Grade = "P2",
                    Severity = "info",
                    Signals = { "S1" },
                    Subject = new JsonObject
                    {
                        ["kind"] = kind == "statusItem" ? "process" : "window",
                        ["key"] = key,
                        ["label"] = key,
                    },
                    Obs = new JsonObject { ["ts"] = lastTs ?? session.ExamStartsAt },
                    Detail = Summaries.Cleared(key),
                }, bypassDebounce: true);

                // 재등장 시 즉시 알리기 위해 디바운스를 푼다.
                foreach (var dk in state.Debounce.Keys.Where(k => k.EndsWith("|" + key, StringComparison.Ordinal)).ToList())
                    state.Debounce.Remove(dk);
            }
            state.Presence[kind] = now;
        }

        // ── 5단계 · P1 에스컬레이션
        ApplyEscalation(ctx);

        // ── 6단계 · 확정
        var result = new Result();
        foreach (var d in ctx.Drafts)
        {
            state.Seq += 1;

            var evidence = new JsonObject { ["observations"] = d.EvidenceObs };
            if (d.Notes.Count > 0) evidence["notes"] = J.Arr(d.Notes);
            if (d.EscalatedFrom is not null) evidence["escalatedFrom"] = J.Arr(d.EscalatedFrom);

            var evt = new JsonObject
            {
                ["sessionId"] = session.SessionId,
                ["seq"] = state.Seq,
                ["ts"] = d.Ts,
                ["grade"] = d.Grade,
                ["severity"] = d.Severity,
                ["rule"] = d.Rule,
                ["signals"] = J.Arr(d.Signals),
                ["summary"] = Summaries.Build(d.Rule, session, d.Grade, d.Obs, d.Detail),
                ["subject"] = d.Subject,
                ["evidence"] = evidence,
                ["contexts"] = J.Arr(d.Contexts),
                ["prevHash"] = state.PrevHash,
            };
            evt["hash"] = Canonical.HashEvent(evt);
            evt["sig"] = null; // 에이전트가 하드웨어 키로 채운다 (S14)
            state.PrevHash = evt["hash"]!.GetValue<string>();
            result.Events.Add(evt);
        }

        result.HeartbeatSummary = state.Counters.ToJson();
        return result;
    }

    // ── 초안 등록 ────────────────────────────────────────────────

    private static Draft? Push(Ctx ctx, Draft spec, bool bypassDebounce = false, string? severityOverride = null)
    {
        var state = ctx.State;
        var obs = spec.Obs ?? new JsonObject();

        var grade = spec.Grade;
        if (grade == "P0")
        {
            var cap = SourceGrade(obs.Str("source"));
            var degraded = obs.Bool("degraded") == true;
            if (cap != "P0" || degraded)
            {
                grade = "P1";
                var src = obs.Str("source") ?? "불명";
                var tail = degraded ? "(부분 실패)" : "";
                spec.Notes.Add(
                    $"출처가 {src}{tail} 이므로 등급을 P0에서 P1로 낮춤. " +
                    "커널·서버·자가검증이 아닌 근거는 결정적이지 않다.");
            }
        }

        var severity = severityOverride ?? (grade == "P0" ? "crit" : grade == "P1" ? "warn" : "info");
        if (grade == "P2" && severityOverride is null) severity = "info";

        var subjectKey = spec.Subject.Str("key") ?? "";
        var tsText = !string.IsNullOrEmpty(spec.Ts) ? spec.Ts : (obs.Str("ts") ?? ctx.Session.ExamStartsAt);
        var tsMs = Ms(tsText);

        if (!bypassDebounce)
        {
            var dk = $"{spec.Rule}|{subjectKey}";
            if (state.Debounce.TryGetValue(dk, out var last) && tsMs - last < ctx.Th("debounceMs", 300000))
                return null;
            state.Debounce[dk] = tsMs;
        }

        if (grade == "P1") state.NoteP1(subjectKey, spec.Rule);

        spec.Grade = grade;
        spec.Severity = severity;
        spec.Ts = tsText;
        spec.Obs = obs;
        if (spec.EvidenceObs.Count == 0 && obs.ContainsKey("kind"))
            spec.EvidenceObs.Add(obs.DeepClone());

        ctx.Drafts.Add(spec);
        return spec;
    }

    private static void ApplyEscalation(Ctx ctx)
    {
        var state = ctx.State;
        var threshold = ctx.Th("p1EscalationCount", 2);
        var crossed = new List<(string Key, List<string> Rules)>();

        foreach (var key in state.SubjectOrder)
        {
            var rules = state.SubjectP1Rules[key];
            if (rules.Count >= threshold && !state.Escalated.Contains(key))
            {
                state.Escalated.Add(key);
                crossed.Add((key, rules));
            }
        }

        foreach (var d in ctx.Drafts)
            if (d.Grade == "P1" && state.Escalated.Contains(d.Subject.Str("key") ?? "") && d.Severity == "warn")
                d.Severity = "crit";

        foreach (var (key, rules) in crossed)
        {
            var anchor = ctx.Drafts.FirstOrDefault(d => (d.Subject.Str("key") ?? "") == key);
            var label = anchor?.Subject.Str("label") ?? key;
            ctx.Drafts.Add(new Draft
            {
                Rule = "R-P1-ESCALATION",
                Grade = "P1",
                Severity = "crit",
                Signals = { "S1" },
                Subject = new JsonObject { ["kind"] = "process", ["key"] = key, ["label"] = label },
                Detail = Summaries.Escalation(label, rules),
                Obs = anchor?.Obs ?? new JsonObject(),
                Ts = anchor?.Ts ?? ctx.Session.ExamStartsAt,
                EscalatedFrom = new List<string>(rules),
            });
        }
    }

    private static JsonObject Subj(string kind, string key, string? label, int? pid, bool withPid)
    {
        var o = new JsonObject { ["kind"] = kind, ["key"] = key };
        if (label is not null) o["label"] = label;
        if (withPid) { if (pid.HasValue) o["pid"] = pid.Value; else o["pid"] = null; }
        return o;
    }

    // ── P0 규칙 ─────────────────────────────────────────────────

    private static void RuleExec(Ctx ctx, JsonObject o)
    {
        var s = Subject.From(o);
        var v = ctx.Policy.Classify(s, ctx.Session.Platform, o.Str("ts"));
        if (v.Denied is not null)
        {
            Push(ctx, new Draft
            {
                Rule = "R-DENY-PROCESS", Grade = "P0",
                Signals = { v.Denied.Signal },
                Obs = o,
                Subject = Subj("process", ProcKey(o), o.Str("path"), o.Int("pid"), true),
                Detail = Summaries.Remote(o, v.Denied.Id),
                Contexts = ctx.Policy.P2Contexts(s, ctx.Session),
            }, severityOverride: "crit");
            return;
        }
        if (v.Allowed) return;

        Push(ctx, new Draft
        {
            Rule = "R-S9-UNKNOWN-EXEC", Grade = "P0",
            Signals = { "S9" },
            Obs = o,
            Subject = Subj("process", ProcKey(o), o.Str("path"), o.Int("pid"), true),
            Detail = Summaries.Exec(o, Summaries.Qual(o)),
            Contexts = ctx.Policy.P2Contexts(s, ctx.Session),
        });
    }

    private static void RuleTccGrant(Ctx ctx, JsonObject o)
    {
        if (o.Str("service") != "ScreenCapture" || o.Str("right") != "allowed") return;
        var identity = o.Str("identity");
        var v = ctx.Policy.Classify(new Subject { Path = identity, Signer = identity }, ctx.Session.Platform, o.Str("ts"));
        if (v.Allowed) return;

        Push(ctx, new Draft
        {
            Rule = "R-S10-SCREENCAPTURE-GRANT", Grade = "P0",
            Signals = { "S10" }, Obs = o,
            Subject = Subj("process", $"proc:path:{(identity ?? "").ToLowerInvariant()}", identity, null, false),
            Detail = Summaries.Tcc(o),
        });
    }

    private static void RuleIokitOpen(Ctx ctx, JsonObject o)
    {
        var cls = o.Str("userClientClass") ?? "";
        if (!HidClasses.Any(c => cls.Contains(c, StringComparison.Ordinal))) return;
        var v = ctx.Policy.Classify(Subject.From(o), ctx.Session.Platform, o.Str("ts"));
        if (v.Allowed) return;

        Push(ctx, new Draft
        {
            Rule = "R-S12-HID-OPEN", Grade = "P0",
            Signals = { "S12" }, Obs = o,
            Subject = Subj("device", ProcKey(o), o.Str("path") ?? $"pid {o.Int("pid")}", o.Int("pid"), true),
            Detail = Summaries.Hid(o),
        });
    }

    private static void RuleCaptureGuard(Ctx ctx, JsonObject o)
    {
        if (o.Bool("ok") != false) return;
        Push(ctx, new Draft
        {
            Rule = "R-S13-CAPTURE-GUARD-FAIL", Grade = "P0",
            Signals = { "S13" }, Obs = o,
            Subject = Subj("guard", "guard:capture", "시험 창 캡처 보호", null, false),
            Detail = Summaries.GuardFail(o),
        });
    }

    private static void RuleLockdown(Ctx ctx, JsonObject o)
    {
        if (o.Str("mode") == "none" || o.Bool("active") != false) return;
        Push(ctx, new Draft
        {
            Rule = "R-S7-LOCKDOWN-EXIT", Grade = "P0",
            Signals = { "S7" }, Obs = o,
            Subject = Subj("session", $"session:{ctx.Session.SessionId}", "평가 모드", null, false),
            Detail = Summaries.LockdownExit(o),
        });
    }

    private static void RuleAttestation(Ctx ctx, JsonObject o)
    {
        // 소프트웨어 키 폴백은 알림이 아니라 표기다. 설계서 S14: "속이지 않는다".
        if (o.Bool("verified") != false) return;
        Push(ctx, new Draft
        {
            Rule = "R-S14-ATTESTATION-FAIL", Grade = "P0",
            Signals = { "S14" }, Obs = o,
            Subject = Subj("session", $"session:{ctx.Session.SessionId}", "기기 키", null, false),
            Detail = Summaries.AttestFail(),
        });
    }

    // ── P1 규칙 ─────────────────────────────────────────────────

    private static void RuleProcess(Ctx ctx, JsonObject o)
    {
        var key = ProcKey(o);
        ctx.See("process", key);
        // "에이전트형"의 정의는 플랫폼마다 다르므로 수집기가 답한다(agentLike).
        // 알려주지 않으면 창 가시성으로 폴백한다 — 픽스처가 이 경로를 쓴다.
        var agentLike = o.Bool("agentLike") ?? (o.Bool("hasVisibleWindow") == false);
        if (!agentLike) return;

        var s = Subject.From(o);
        var v = ctx.Policy.Classify(s, ctx.Session.Platform, o.Str("ts"));
        if (v.Denied is not null)
        {
            Push(ctx, new Draft
            {
                Rule = "R-DENY-PROCESS", Grade = "P0",
                Signals = { v.Denied.Signal }, Obs = o,
                Subject = Subj("process", key, o.Str("path"), o.Int("pid"), true),
                Detail = Summaries.Remote(o, v.Denied.Id),
            }, severityOverride: "crit");
            return;
        }
        if (v.Allowed) return;

        ctx.State.Counters.UnknownProcs++;
        Push(ctx, new Draft
        {
            Rule = "R-S1-UNKNOWN-AGENT-PROC", Grade = "P1",
            Signals = { "S1" }, Obs = o,
            Subject = Subj("process", key, o.Str("path"), o.Int("pid"), true),
            Detail = Summaries.AgentProc(o, Summaries.Qual(o)),
            Contexts = ctx.Policy.P2Contexts(s, ctx.Session),
        });
    }

    private static void RuleStatusItem(Ctx ctx, JsonObject o)
    {
        var key = ProcKey(o);
        ctx.See("statusItem", key);
        ctx.State.Counters.StatusItems++;

        var s = Subject.From(o);
        var v = ctx.Policy.Classify(s, ctx.Session.Platform, o.Str("ts"));
        if (v.Allowed || v.Denied is not null) return;

        Push(ctx, new Draft
        {
            Rule = "R-S2-UNKNOWN-STATUS-ITEM", Grade = "P1",
            Signals = { "S2" }, Obs = o,
            Subject = Subj("process", key, o.Str("ownerPath"), o.Int("ownerPid"), true),
            Detail = Summaries.StatusItem(o, Summaries.Qual(o)),
            Contexts = ctx.Policy.P2Contexts(s, ctx.Session),
        });
    }

    private static void RuleExcludedWindow(Ctx ctx, JsonObject o)
    {
        if (o.Str("affinity") == "none") return;
        var ownerPid = o.Int("ownerPid");
        if (ownerPid.HasValue && ownerPid == ctx.Session.AgentPid) return; // 우리 시험 창

        var key = ProcKey(o);
        ctx.See("captureExcludedWindow", key);

        var v = ctx.Policy.Classify(Subject.From(o), ctx.Session.Platform, o.Str("ts"));
        if (v.Allowed) return;

        Push(ctx, new Draft
        {
            Rule = "R-S3-CAPTURE-EXCLUDED-WINDOW", Grade = "P1",
            Signals = { "S3" }, Obs = o,
            Subject = Subj("process", key, o.Str("ownerPath"), ownerPid, true),
            Detail = Summaries.ExcludedWindow(o, Summaries.Qual(o)),
        });
    }

    private static void RuleCapsPattern(Ctx ctx)
    {
        var state = ctx.State;
        var maxInterval = ctx.Th("capsMaxIntervalMs", 300);
        var minToggles = ctx.Th("capsMinTogglesInWindow", 2);
        var window = ctx.Th("capsWindowMs", 1500);

        // OrderBy 는 안정 정렬 — List.Sort 는 불안정해서 같은 시각 표본의 순서가 갈릴 수 있다.
        var buf = state.CapsBuffer.OrderBy(x => x.TsMs).ToList();
        var consumed = new HashSet<CapsSample>();

        var i = 0;
        while (i < buf.Count)
        {
            var j = i;
            while (j + 1 < buf.Count && buf[j + 1].TsMs - buf[j].TsMs <= maxInterval) j++;
            var run = buf.GetRange(i, j - i + 1);
            var span = run[^1].TsMs - run[0].TsMs;

            if (run.Count >= minToggles && span <= window)
            {
                state.Counters.CapsPatterns++;
                long total = 0;
                for (var k = 1; k < run.Count; k++) total += run[k].TsMs - run[k - 1].TsMs;
                var avg = (long)Math.Round((double)total / (run.Count - 1), MidpointRounding.AwayFromZero);

                var ev = new JsonArray();
                foreach (var r in run) ev.Add(r.Obs.DeepClone());

                Push(ctx, new Draft
                {
                    Rule = "R-S4-CAPS-PATTERN", Grade = "P1",
                    Signals = { "S4" }, Obs = run[0].Obs,
                    Subject = Subj("device", "device:capslock", "Caps Lock", null, false),
                    Detail = Summaries.Caps(run.Count, avg),
                    EvidenceObs = ev,
                });
                foreach (var r in run) consumed.Add(r);
            }
            i = j + 1;
        }

        var cutoff = buf.Count > 0 ? buf[^1].TsMs - window * 4 : 0;
        state.CapsBuffer = buf.Where(b => !consumed.Contains(b) && b.TsMs >= cutoff).ToList();
    }

    private static void RuleImageLoad(Ctx ctx, JsonObject o)
    {
        var mods = ctx.Policy.CaptureStackModules.Select(m => m.ToLowerInvariant()).ToList();
        var modulePath = o.Str("modulePath") ?? "";
        var mod = modulePath.Split('\\', '/')[^1].ToLowerInvariant();
        if (!mods.Contains(mod)) return;

        var key = ProcKey(o);
        if (!ctx.State.Mods.TryGetValue(key, out var set)) { set = new List<string>(); ctx.State.Mods[key] = set; }
        if (!set.Contains(mod)) set.Add(mod);
        if (set.Count < 2) return; // 단일 모듈은 신호가 아니다. 조합만 본다.

        var v = ctx.Policy.Classify(Subject.From(o), ctx.Session.Platform, o.Str("ts"));
        if (v.Allowed) return;

        Push(ctx, new Draft
        {
            Rule = "R-S11-CAPTURE-STACK", Grade = "P1",
            Signals = { "S11" }, Obs = o,
            Subject = Subj("process", key, o.Str("path"), o.Int("pid"), true),
            Detail = Summaries.CaptureStack(o, set),
        });
    }

    private static void RuleNetPosture(Ctx ctx, JsonObject o)
    {
        if (o.Bool("canary") == true)
        {
            var contexts = new List<string>();
            if ((o.Int("ifaceCount") ?? 1) > 1) contexts.Add("multipleInterfaces");
            Push(ctx, new Draft
            {
                Rule = "R-S5-CANARY-REACHED", Grade = "P1",
                Signals = { "S5" }, Obs = o,
                Subject = Subj("network", "net:canary", "시험망 이탈", null, false),
                Detail = Summaries.Canary(),
                Contexts = contexts,
            }, severityOverride: "crit");
        }

        if (o.Bool("beacon") == false)
        {
            // 설계서 07장 실패 모드: 학교망 장애로 40명이 동시에 빨간불이 되면 감독관이 시스템을 끈다.
            Push(ctx, new Draft
            {
                Rule = "R-S5-BEACON-MISS", Grade = "P2",
                Signals = { "S5" }, Obs = o,
                Subject = Subj("network", "net:beacon", "시험망 비콘", null, false),
                Detail = Summaries.BeaconMiss(),
            }, severityOverride: "info");
        }
    }

    private static void RuleVm(Ctx ctx, JsonObject o)
    {
        // 하이퍼바이저 비트는 호스트의 VBS 에서도 켜진다. 게스트 판정은 수집기의 몫이다.
        var guest = o.Bool("vmGuestLikely") ?? o.Bool("hypervisorPresent");
        if (guest != true) return;
        if (ctx.Policy.VmAllowed) return;
        Push(ctx, new Draft
        {
            Rule = "R-S6-VM", Grade = "P1",
            Signals = { "S6" }, Obs = o,
            Subject = Subj("session", $"session:{ctx.Session.SessionId}:vm", "가상머신", null, false),
            Detail = Summaries.Vm(o),
        });
    }

    private static void RuleRemote(Ctx ctx, JsonObject o)
    {
        var v = ctx.Policy.Classify(Subject.From(o), ctx.Session.Platform, o.Str("ts"));
        var id = v.Denied?.Id ?? o.Str("matched") ?? "remote-unknown";
        Push(ctx, new Draft
        {
            Rule = "R-DENY-PROCESS", Grade = "P0",
            Signals = { "S6" }, Obs = o,
            Subject = Subj("process", ProcKey(o), o.Str("path"), o.Int("pid"), true),
            Detail = Summaries.Remote(o, id),
        }, severityOverride: "crit");
    }

    private static void RuleIntegrity(Ctx ctx, JsonObject o)
    {
        var skew = Math.Abs(o.Int("clockSkewMs") ?? 0);
        var bad = o.Bool("selfSignatureValid") == false
                  || o.Bool("debuggerPresent") == true
                  || skew > ctx.Th("clockSkewToleranceMs", 30000);
        if (!bad) return;

        // 설계서 05장 카탈로그는 S8을 P1로 둔다. 자가검증이라 형식상 P0 요건을 만족하지만,
        // 서명된 바이너리를 패치하면 무결성 검사도 함께 패치되므로 결정적이라고 말할 수 없다.
        Push(ctx, new Draft
        {
            Rule = "R-S8-INTEGRITY", Grade = "P1",
            Signals = { "S8" }, Obs = o,
            Subject = Subj("session", $"session:{ctx.Session.SessionId}:agent", "에이전트 무결성", null, false),
            Detail = Summaries.Integrity(o),
        }, severityOverride: o.Bool("debuggerPresent") == true ? "crit" : "warn");
    }

    // ── 상관 규칙 ────────────────────────────────────────────────

    private static void RuleLedgerCorrelation(Ctx ctx, IReadOnlyList<JsonObject> observations, IReadOnlyList<string> scanned)
    {
        var state = ctx.State;
        if (ctx.Session.Ledger != "kernel") return; // 원장이 커널이 아니면 상관이 성립하지 않는다

        // (1) 원장 우회: 화면에는 있는데 커널 실행 기록에 없다.
        foreach (var o in observations)
        {
            var kind = o.Str("kind");
            if (kind != "statusItem" && kind != "process") continue;
            if (o.Str("source") != "userspace") continue;

            var pid = o.Int("ownerPid") ?? o.Int("pid");
            if (!pid.HasValue) continue;
            if (state.BaselinePids.Contains(pid.Value) || state.LedgerPids.ContainsKey(pid.Value)) continue;

            var v = ctx.Policy.Classify(Subject.From(o), ctx.Session.Platform, o.Str("ts"));
            if (v.Allowed) continue;

            Push(ctx, new Draft
            {
                Rule = "R-CORR-LEDGER-BYPASS", Grade = "P1",
                Signals = { "S9", "S1" }, Obs = o,
                Subject = Subj("process", ProcKey(o), o.Str("ownerPath") ?? o.Str("path"), pid, true),
                Detail = Summaries.LedgerBypass(o),
            }, severityOverride: "crit");
        }

        // (2) 스캔 회피: 커널 기록에는 살아 있는데 사용자 공간 목록에 없다.
        if (!scanned.Contains("process")) return;
        var alive = new HashSet<string>(ctx.Seen.TryGetValue("process", out var s) ? s : new List<string>(), StringComparer.Ordinal);
        var lastTs = observations.Count > 0 ? observations[^1].Str("ts") : null;

        // pid 오름차순 — 레퍼런스 구현과 이벤트 순서를 맞춘다.
        foreach (var pid in state.LedgerPids.Keys.OrderBy(x => x).ToList())
        {
            if (state.LedgerExited.Contains(pid)) continue;
            var rec = state.LedgerPids[pid];
            var key = ProcKey(rec);
            if (alive.Contains(key)) continue;

            var v = ctx.Policy.Classify(new Subject { Path = rec.Path, Sha256 = rec.Sha256, Signer = rec.Signer },
                ctx.Session.Platform, ctx.Session.ExamStartsAt);
            if (v.Allowed) continue;

            var synthetic = rec.ToSynthetic(lastTs ?? ctx.Session.ExamStartsAt);

            Push(ctx, new Draft
            {
                Rule = "R-CORR-SCAN-EVASION", Grade = "P1",
                Signals = { "S9", "S1" }, Obs = synthetic,
                Subject = Subj("process", key, rec.Path, pid, true),
                Detail = Summaries.ScanEvasion(rec.Path),
            }, severityOverride: "crit");
        }
    }
}
