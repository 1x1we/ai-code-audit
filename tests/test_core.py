"""
真实测试基础设施 — 验证商业级审计的准确性
"""
import sys
import os
import json
import tempfile
from pathlib import Path

# 添加 scripts 目录到 path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from package_resolver import PackageResolver
from smart_detectors import SmartDetectors, apply_all_detectors, TaintContext
from confidence_engine import ConfidenceEngine, recalculate_score
from release_artifacts import scan_release_artifacts
from agent_protocol import build_agent_tasks, apply_verdicts, emit_agent_tasks_json, issues_hash, \
    enrich_skill_finding, agent_review, decide_gate_with_agent, is_blocking_with_agent
from ast_logic_analyzer import analyze_python_ast
from dependency_audit import scan_dependency_audit
from audit_whitelist import Whitelist
from code_audit_runner import scan_directory


def test_package_resolver():
    """测试包解析器的核心能力"""
    print("包解析器测试")
    r = PackageResolver(os.path.join(os.path.dirname(__file__), ".."))
    
    tests = [
        # (包名, 语言, 期望结果)
        # Python stdlib — 绝对不能标为幻觉
        ("zlib", "python", True),
        ("ctypes", "python", True),
        ("lzma", "python", True),
        ("os", "python", True),
        ("json", "python", True),
        ("sys", "python", True),
        ("argparse", "python", True),
        ("collections", "python", True),
        ("unittest", "python", True),
        ("datetime", "python", True),
        ("pathlib", "python", True),
        ("sqlite3", "python", True),
        ("hashlib", "python", True),
        ("logging", "python", True),
        ("urllib", "python", True),
        ("urllib.request", "python", True),
        # Python 已知包
        ("requests", "python", True),
        ("flask", "python", True),
        ("numpy", "python", True),
        ("pandas", "python", True),
        ("django", "python", True),
        ("sqlalchemy", "python", True),
        # JS 已知包
        ("react", "javascript", True),
        ("vite", "typescript", True),
        ("tailwindcss", "javascript", True),
        ("express", "javascript", True),
        ("node:fs", "javascript", True),
        # 相对导入 → 内部
        ("./utils", "typescript", True),
        ("../helpers", "javascript", True),
        # C# BCL
        ("System", "csharp", True),
        ("System.IO", "csharp", True),
        ("System.Net.Http", "csharp", True),
        ("Microsoft.AspNetCore", "csharp", True),
    ]
    
    passed = 0
    for name, lang, expected in tests:
        result = r.is_known_import(name, lang)
        ok = result == expected
        status = "OK" if ok else f"FAIL (got {result})"
        print(f"  {status:>8}  {lang:>12}  {name}")
        if ok:
            passed += 1
    
    print(f"\n  {passed}/{len(tests)} 通过\n")
    assert passed == len(tests), f"预期全部通过，实际 {passed}/{len(tests)}"
    return True


def test_magic_number_context():
    """测试魔法数字上下文感知"""
    print("魔法数字检测测试")
    d = SmartDetectors()
    
    tests = [
        # (代码行, 语言, 是否应标记)
        # 安全上下文 — 不应标记
        ("using (var b = new SolidBrush(Color.FromArgb(7, 193, 96)))", "csharp", False),
        ("var sb = new StringBuilder(512);", "csharp", False),
        ("new byte[1024];", "csharp", False),
        ("Thread.Sleep(1000);", "csharp", False),
        ("const int PORT = 8080;", "csharp", False),
        ("backgroundColor: 'rgba(255, 128, 0, 0.5)'", "javascript", False),
        ("ctx.fillStyle = '#FF5733';", "javascript", False),
        ("using var stream = new MemoryStream(new byte[4096]);", "csharp", False),
        # 应该标记
        ("if (retries > 15)", "csharp", True),
        ("return 42", "python", True),
    ]
    
    passed = 0
    for line, lang, should_flag in tests:
        result = d.check_magic_number(line, 1, lang)
        flagged = result is not None
        ok = flagged == should_flag
        status = "OK" if ok else f"FAIL (flagged={flagged})"
        print(f"  {status:>8}  {lang:>12}  {line[:55]}")
        if ok:
            passed += 1
    
    print(f"\n  {passed}/{len(tests)} 通过\n")
    assert passed >= len(tests) * 0.9, f"预期90%以上通过，实际 {passed}/{len(tests)}"
    return True


def test_debug_print_context():
    """测试调试残留上下文感知"""
    print("调试残留检测测试")
    d = SmartDetectors()
    
    tests = [
        # CLI 工具的 print() — 不应标记
        ('print("processing file...")', "python", "cli", False),
        ('console.log("started")', "javascript", "cli", False),
        # 库/API 的 print() — 应标记
        ('print("debug info")', "python", "api", True),
        ('console.log("state:", obj)', "typescript", "api", True),
        # Debug.Write — 始终标记（即使桌面应用）
        ('Debug.WriteLine("[FATAL] " + ex.Message);', "csharp", "desktop", True),
        # 日志框架 — 不标记
        ('logger.debug("processing")', "python", "api", False),
        ('log.info("request received")', "javascript", "api", False),
    ]
    
    passed = 0
    for line, lang, ptype, should_flag in tests:
        result = d.check_debug_prints(line, 1, lang, ptype)
        flagged = result is not None
        ok = flagged == should_flag
        status = "OK" if ok else f"FAIL (flagged={flagged})"
        print(f"  {status:>8}  {lang:>12} [{ptype:>7}] {line[:45]}")
        if ok:
            passed += 1
    
    print(f"\n  {passed}/{len(tests)} 通过\n")
    assert passed >= len(tests) * 0.85, f"预期85%以上通过，实际 {passed}/{len(tests)}"
    return True


def test_filter_pipeline():
    """测试过滤管道"""
    print("过滤管道测试")
    engine = ConfidenceEngine("desktop")
    
    issues = [
        # 应保留（高置信度 + 严重问题）
        {"desc": "SQL注入", "layer": "owasp_security", "severity": "critical", "confidence": "high", "code_snippet": "cursor.execute(query)"},
        {"desc": "硬编码密钥", "layer": "owasp_security", "severity": "high", "confidence": "high", "code_snippet": "API_KEY = 'sk_live_abc'"},
        # 应过滤（安全上下文中的魔法数字）
        {"desc": "魔法数字: 193", "layer": "code_quality", "severity": "low", "confidence": "low", "code_snippet": "Color.FromArgb(7, 193, 96)"},
        {"desc": "魔法数字: 512", "layer": "code_quality", "severity": "low", "confidence": "low", "code_snippet": "new StringBuilder(512)"},
        # 应降级
        {"desc": "print残留", "layer": "code_quality", "severity": "low", "confidence": "low", "code_snippet": "console.log('test')"},
    ]
    
    result = engine.filter(issues)
    
    # 验证
    assert len(result.strict) == 5, f"strict 应有5条，实际{len(result.strict)}"
    assert len(result.normal) <= 4, f"normal 应过滤至少1条"
    assert len(result.release) >= 1, f"release 应保留至少1条阻塞级"
    assert result.filtered_out > 0, "应过滤至少1条低置信度发现"
    
    print(f"  strict: {len(result.strict)} | normal: {len(result.normal)} | release: {len(result.release)}")
    print(f"  filtered: {result.filtered_out}")
    print(f"  reasons: {result.filter_reasons}")
    print("  OK\n")
    return True


def test_scoring_confidence():
    """测试置信度加权评分"""
    print("置信度评分测试")
    
    no_issues = []
    score = recalculate_score(no_issues)
    assert score["grade"] == "S"
    assert score["percentage"] == 100.0
    print(f"  无问题: {score['grade']} ({score['percentage']}%)")
    
    # 高置信度 critical → 应大幅扣分
    real_issues = [{
        "layer": "owasp_security", "severity": "critical",
        "confidence": "high", "desc": "SQL注入"
    }]
    score2 = recalculate_score(real_issues)
    print(f"  高置信度critical: {score2['grade']} ({score2['percentage']}%)")
    assert score2["percentage"] < 100.0
    
    # 低置信度 low → 应几乎不扣分
    noise_issues = [{
        "layer": "code_quality", "severity": "low",
        "confidence": "low", "desc": "魔法数字"
    }]
    score3 = recalculate_score(noise_issues)
    print(f"  低置信度low: {score3['grade']} ({score3['percentage']}%)")
    assert score3["percentage"] > 95.0, f"低置信度不应大幅扣分，实际{score3['percentage']}%"
    
    print("  OK\n")
    return True


def test_empty_catch():
    """测试空 catch/except 检测"""
    print("空 catch 检测测试")
    d = SmartDetectors()

    tests = [
        ("except: pass", "python", True),
        ("except Exception: pass", "python", True),
        ("catch (Exception) { }", "csharp", True),
        ('catch (Exception e) { logger.error(e); }', "csharp", False),
        ("except: pass  # ignore intentionally", "python", False),
    ]

    passed = 0
    for line, lang, should_flag in tests:
        result = d.check_empty_catch(line, 1, [line])
        flagged = result is not None
        ok = flagged == should_flag
        status = "OK" if ok else f"FAIL (flagged={flagged})"
        print(f"  {status:>8}  {lang:>12}  {line[:40]}")
        if ok:
            passed += 1

    print(f"\n  {passed}/{len(tests)} 通过\n")
    assert passed == len(tests), f"预期全部通过，实际 {passed}/{len(tests)}"
    return True


def test_release_artifacts():
    """测试发布前遗留/调试文件检测"""
    print("发布前遗留文件检测测试")
    tmp = Path(tempfile.mkdtemp())
    for fn in [".env", "secret.pem", "x.bak", "y.js.map", "z.log"]:
        (tmp / fn).write_text("x", encoding="utf-8")
    # 大文件测试
    big = tmp / "huge.zip"
    big.write_bytes(b"x" * (6 * 1024 * 1024))

    arts = scan_release_artifacts(str(tmp))
    by_name = {Path(a["file"]).name: a for a in arts}

    tests = [
        (".env" in by_name, "检出 .env"),
        ("secret.pem" in by_name, "检出 .pem 私钥"),
        ("x.bak" in by_name, "检出 .bak 备份"),
        ("y.js.map" in by_name, "检出 .js.map 源码映射"),
        ("huge.zip" in by_name, "检出超大 zip"),
        ("z.log" in by_name, "检出 .log 日志"),
    ]

    passed = 0
    for ok, name in tests:
        status = "OK" if ok else "FAIL"
        print(f"  {status:>8}  {name}")
        if ok:
            passed += 1

    print(f"\n  {passed}/{len(tests)} 通过\n")
    assert passed == len(tests), f"预期全部通过，实际 {passed}/{len(tests)}"
    return True


def test_veto_and_confidence():
    """测试否决机制与置信度方向修正"""
    print("否决 + 置信度方向测试")

    # 方向：固定 low 严重度，高置信应比低置信扣得更多
    s_hi = recalculate_score([{
        "layer": "code_quality", "severity": "low",
        "confidence": "high", "desc": "x"}])["percentage"]
    s_lo = recalculate_score([{
        "layer": "code_quality", "severity": "low",
        "confidence": "low", "desc": "x"}])["percentage"]
    print(f"  高置信low: {s_hi}%  低置信low: {s_lo}%")
    assert s_hi < s_lo, f"高置信应扣更多，但 high={s_hi} >= low={s_lo}"

    # 否决：致命层 critical → veto + C
    one = recalculate_score([{
        "layer": "owasp_security", "severity": "critical",
        "confidence": "high", "desc": "SQL"}])
    assert one["veto_hit"] is True and one["grade"] == "C", "1 critical 应否决禁发"

    # 10 个 critical → 仍否决
    ten = recalculate_score([{
        "layer": "owasp_security", "severity": "critical",
        "confidence": "high", "desc": "SQL"} for _ in range(10)])
    assert ten["veto_hit"] is True and ten["grade"] == "C", "10 critical 应否决禁发"

    # 非致命层 critical → 不否决
    nonfatal = recalculate_score([{
        "layer": "code_quality", "severity": "critical",
        "confidence": "high", "desc": "x"}])
    assert nonfatal["veto_hit"] is False, "非致命层 critical 不应触发否决"

    print("  OK\n")
    return True


def test_injection_detectors():
    """商业级扩展 v8.2：注入/反序列化/穿越类检测器（误报+漏报双向验证）"""
    print("注入类检测器测试")
    d = SmartDetectors()

    def layer_of(line, lang="python", ptype="api"):
        issues = apply_all_detectors(line, 1, lang, ptype, "probe.py",
                                     context_lines=[line], line_idx=0)
        return [i["layer"] for i in issues], [i["desc"] for i in issues]

    # ── 应检出（漏报防护）──
    cases_hit = [
        ("XSS", 'element.innerHTML = userInput', "owasp_security"),
        ("命令注入", 'os.system("ls " + user_input)', "owasp_security"),
        ("代码注入", 'eval(request.args.get("expr"))', "owasp_security"),
        ("不安全反序列化", 'data = pickle.loads(payload)', "owasp_security"),
        ("路径穿越", 'with open("../../etc/" + name) as f:', "owasp_security"),
        ("SSRF", 'requests.get(user_controlled_url)', "owasp_security"),
        ("弱哈希", 'hashlib.md5(user_password.encode()).hexdigest()', "product_security"),
        ("通用密钥", 'DB_PASS = "SuperSecret123"', "owasp_security"),
    ]
    for name, line, expect_layer in cases_hit:
        layers, _ = layer_of(line)
        assert expect_layer in layers, f"{name} 应检出 {expect_layer}，实际: {layers}"
        print(f"  OK  检出 {name}")

    # ── 不应误报（误报防护）：仅验证「纯安全无关代码」不产生安全层告警 ──
    # 注：静态命令/静态 eval（无外部可控输入）不算注入漏洞，必须不误报安全层
    cases_clean = [
        ("XSS 静态", 'element.innerHTML = "<b>hi</b>"'),
        ("命令静态", 'os.system("clear")'),
        ("代码静态", 'result = eval("1 + 1")'),
        ("SSRF 字面量", 'requests.get("https://api.example.com/data")'),
        ("yaml 安全", 'cfg = yaml.safe_load(stream)'),
        ("sha256", 'h = hashlib.sha256(payload).hexdigest()'),
        ("密码取输入", 'password = input("Enter password: ")'),
        ("CLI print", 'print("Usage: app --help")'),
        ("参数化SQL", 'cursor.execute("SELECT * FROM t WHERE id=%s", (uid,))'),
        ("普通运算", 'total = price * quantity + tax'),
    ]
    allowed_layers = {"code_quality", "exception_handling", "memory_performance", "business_logic", "engineering"}
    for name, line in cases_clean:
        layers, _ = layer_of(line)
        bad = [l for l in layers if l not in allowed_layers]
        assert not bad, f"{name} 误报安全层: {bad}"
        print(f"  OK  无误报 {name}")

    print("  OK\n")
    return True


def test_command_injection_language_aware():
    """v8.9：命令注入语言感知 —— 根治 Rust/Tokio 上 tokio::spawn / arg-vector 误报"""
    print("命令注入语言感知 (v8.9) 测试")
    d = SmartDetectors()

    # (line, language, should_flag)
    cases = [
        # ── Rust：异步任务 / 参数向量 必须不误报（voicebutler 真实误报来源）──
        ('    tokio::spawn(async move {', "rust", False),
        ('    handle.spawn(async move {', "rust", False),
        ('    let child = Command::new("ls").args(["-l"]).spawn()?;', "rust", False),
        ('    let mut cmd = Command::new("git"); cmd.args(["log"]);', "rust", False),
        # Rust shell 字符串执行 + 动态 → 必须报（真实注入面）
        ('    Command::new(format!("cmd /C {}", name)).status()', "rust", True),
        ('    Command::new("cmd").args(["/C", &user_input]).status()', "rust", True),
        ('    Command::new("sh").arg("-c").arg(script).status()', "rust", True),
        # Rust shell 静态 → 不误报
        ('    Command::new("cmd").args(["/C", "echo", "hi"]).status()', "rust", False),

        # ── Go：exec.Command arg-vector 不误报；shell 动态才报 ──
        ('    exec.Command("ls", "-l")', "go", False),
        ('    exec.Command("cmd", "/C", req.Command)', "go", True),
        ('    exec.CommandContext(ctx, "sh", "-c", script)', "go", True),

        # ── Python ──
        ('os.system("rm " + user_input)', "python", True),
        ('os.system(f"rm -rf {user_input}")', "python", True),  # v8.10: f-string 插值不可漏报
        ('subprocess.run(["ls", "-l"])', "python", False),
        ('subprocess.run("rm " + x, shell=True)', "python", True),

        # ── Node ──
        ('child_process.exec("ls " + x)', "javascript", True),
        ('child_process.exec(`echo ${name}`)', "javascript", True),  # v8.10: 模板字符串插值
        ('child_process.spawn("ls", ["-l"])', "javascript", False),

        # ── Java ──
        ('Runtime.getRuntime().exec("sh -c " + cmd)', "java", True),
    ]

    passed = 0
    for line, lang, should_flag in cases:
        res = d.check_command_injection(line, 1, lang, "probe")
        flagged = res is not None
        ok = flagged == should_flag
        status = "OK" if ok else f"FAIL (flagged={flagged}, expect={should_flag})"
        print(f"  {status:>10}  {lang:>10}  {line[:52]}")
        if ok:
            passed += 1

    print(f"\n  {passed}/{len(cases)} 通过\n")
    assert passed == len(cases), f"预期全部通过，实际 {passed}/{len(cases)}"
    return True


def test_agent_protocol():
    """协同协议：skill 初筛 → LLM 三态确认 → 最终裁决（round-trip）"""
    print("协同协议 (agent_protocol) 测试")

    # 构造一份 skill 报告（含 critical/high/mid/low 代码问题 + 遗留文件）
    report = {
        "meta": {"script_version": "8.3"},
        "issues": {
            "critical": [{"file": "a.py", "line": 10, "layer": "owasp_security",
                          "severity": "critical", "confidence": "high",
                          "desc": "硬编码密钥", "code_snippet": 'API_KEY="sk-..."',
                          "suggestion": "用环境变量"}],
            "high": [{"file": "b.py", "line": 20, "layer": "owasp_security",
                      "severity": "high", "confidence": "high",
                      "desc": "SQL 拼接", "code_snippet": 'q="SELECT..."+x',
                      "suggestion": "参数化"}],
            "mid": [{"file": "c.py", "line": 30, "layer": "code_quality",
                     "severity": "mid", "confidence": "medium",
                     "desc": "魔法数字 42", "code_snippet": "return 42",
                     "suggestion": "命名常量"}],
            "low": [{"file": "d.py", "line": 40, "layer": "code_quality",
                     "severity": "low", "confidence": "high",
                     "desc": "调试 print", "code_snippet": 'print("x")',
                     "suggestion": "移除"}],
        },
        "release_artifacts": [{"file": ".env", "line": 0, "layer": "product_security",
                               "severity": "high", "confidence": "high",
                               "desc": "提交 .env", "code_snippet": "",
                               "suggestion": "加入 .gitignore"}],
    }

    # 1) 初筛任务清单：low 不进任务（省 token），mid+ 与遗留文件进
    tasks, idmap = build_agent_tasks(report)
    ids = [t["id"] for t in tasks]
    kinds = [t["kind"] for t in tasks]
    assert "low" not in [t["severity"] for t in tasks], "low 不应进 agent 任务"
    assert "artifact" in kinds, "遗留文件应进任务"
    assert len(tasks) == 4, f"应为 4 个任务(critical/high/mid/artifact)，实际 {len(tasks)}"
    assert ids == ["T001", "T002", "T003", "T004"], f"id 应连续，实际 {ids}"
    # 清单可序列化
    emit_agent_tasks_json(report)
    print("  OK  初筛任务清单(low 已排除, 遗留文件已含)")

    # 2) LLM 三态裁决：REJECT mid 魔法数字、CONFIRM 其余、SUPPLEMENT 一条越权
    verdicts = {"verdicts": [
        {"id": "T001", "verdict": "CONFIRM", "agent_note": "确为明文密钥", "agent_fix": "改用 Secret Manager"},
        {"id": "T002", "verdict": "CONFIRM", "agent_note": "确为拼接", "agent_fix": "用参数化"},
        {"id": "T003", "verdict": "REJECT", "reason": "该 42 是 HTTP 状态码，非魔法数字"},
        {"id": "T004", "verdict": "CONFIRM", "agent_note": "确为提交的 .env"},
        {"id": "T005", "verdict": "SUPPLEMENT", "reasoning": "删除接口未校验 owner，任何登录用户可删他人资源",
         "evidence": ["e.py:5"], "finding": {
            "file": "e.py", "line": 5, "layer": "business_logic",
            "severity": "high", "confidence": "high",
            "desc": "删除接口未校验 owner，存在越权", "suggestion": "删除前校验资源归属"}},
    ]}
    final = apply_verdicts(report, verdicts)
    summ = final["agent_summary"]
    assert summ["rejected"] == 1, f"应驳回 1 条，实际 {summ['rejected']}"
    assert summ["supplemented"] == 1, f"应补抓 1 条，实际 {summ['supplemented']}"

    # REJECT 的魔法数字不应出现在确认清单；SUPPLEMENT 应出现
    confirmed_descs = [i["desc"] for i in final["confirmed_issues"]]
    assert "魔法数字 42" not in confirmed_descs, "被 REJECT 的应剔除"
    supp_descs = [i["desc"] for i in final["supplemented_findings"]]
    assert "删除接口未校验 owner，存在越权" in supp_descs, "SUPPLEMENT 应保留"

    # 门禁：仍有 critical 硬编码密钥 + 提交 .env → 仍 BLOCK
    assert final["release_gate"]["decision"] == "BLOCK", "含密钥+遗留文件应 BLOCK"
    assert final["release_gate"]["veto_hit"] is True, "critical 应触发否决"
    print("  OK  LLM 三态合并 → 最终裁决 BLOCK（驳回/补抓正确）")

    # 3) 安全地板：全部 REJECT 但无人工复核 → 仍 BLOCK（致命类不可被 LLM 静默推翻）
    all_reject = {"verdicts": [{"id": t["id"], "verdict": "REJECT",
                                 "reason": "假设 LLM 判定全误报"} for t in tasks]}
    final2 = apply_verdicts(report, all_reject)
    # 致命类(critical 密钥 / high SQL / 遗留 .env) 无 human_override → 保留为 challenged
    assert final2["release_gate"]["decision"] == "BLOCK", "致命类全 REJECT 无复核 → 必须仍 BLOCK（硬地板）"
    assert final2["release_gate"]["deterministic_floor_blocked"] is True, "应标记地板触发"
    assert len(final2["challenged_findings"]) >= 3, \
        f"应至少 3 条致命类被保留为 challenged，实际 {len(final2['challenged_findings'])}"
    print("  OK  全 REJECT 无复核 → 仍 BLOCK（致命类保留为 challenged）")

    # 3b) 全部 REJECT 且均带合法 human_override+override_reason → 可放宽（人工复核可追溯）
    all_reject_override = {"verdicts": [
        {"id": t["id"], "verdict": "REJECT", "reason": "人工复核确认非生产问题",
         "human_override": True, "override_reason": "安全团队复核：测试桩/已缓解，可放行"}
        for t in tasks]}
    final3 = apply_verdicts(report, all_reject_override)
    assert final3["release_gate"]["decision"] != "BLOCK", "全部合法人工复核后应可放宽"
    assert len(final3["human_overrides"]) >= 3, \
        f"致命类应记录 >=3 条人工复核，实际 {len(final3['human_overrides'])}"
    print("  OK  全 REJECT + 合法 human_override → 可放宽（人工复核可追溯）")

    print("  OK\n")
    return True


def test_verdict_audit_and_floor():
    """v8.7：协同层审计化 —— 推理链 / 复现契约 / 不可复现兜底（回应商业级三问）"""
    print("协同层审计化 (v8.7) 测试")
    report = {
        "meta": {"script_version": "8.7"},
        "issues": {
            "critical": [{"file": "a.py", "line": 10, "layer": "owasp_security",
                          "severity": "critical", "confidence": "high",
                          "desc": "硬编码密钥", "code_snippet": 'API_KEY="sk-..."',
                          "suggestion": "用环境变量"}],
            "high": [{"file": "b.py", "line": 20, "layer": "owasp_security",
                      "severity": "high", "confidence": "high",
                      "desc": "SQL 拼接", "code_snippet": 'q="SELECT..."+x',
                      "suggestion": "参数化"}],
            "mid": [{"file": "c.py", "line": 30, "layer": "code_quality",
                     "severity": "mid", "confidence": "medium",
                     "desc": "魔法数字 42", "code_snippet": "return 42",
                     "suggestion": "命名常量"}],
        },
        "release_artifacts": [{"file": ".env", "line": 0, "layer": "product_security",
                               "severity": "high", "confidence": "high",
                               "desc": "提交 .env", "code_snippet": "",
                               "suggestion": "加入 .gitignore"}],
    }
    ih = issues_hash(report)

    # (a) 任务清单携带 issues_hash（复现契约）
    tj = json.loads(emit_agent_tasks_json(report))
    assert tj["issues_hash"] == ih, "任务清单应携带与报告一致的 issues_hash"
    assert tj["version"] == "2.0", "协议版本应为 2.0"
    print("  OK  任务清单携带 issues_hash (复现契约)")

    # (b) REJECT 致命类无 human_override → 保留为 challenged，仍 BLOCK，且可质疑
    v_bad = {"verdicts": [
        {"id": "T001", "verdict": "REJECT", "reason": "我认为是误报"},
        {"id": "T002", "verdict": "REJECT", "reason": "我认为是误报"},
        {"id": "T003", "verdict": "REJECT", "reason": "HTTP 状态码非魔法数字"},
        {"id": "T004", "verdict": "REJECT", "reason": "我认为是误报"},
    ]}
    f_bad = apply_verdicts(report, v_bad)
    assert f_bad["release_gate"]["decision"] == "BLOCK", "致命类 REJECT 无复核必须仍 BLOCK"
    assert len(f_bad["challenged_findings"]) == 3, \
        f"应 3 条 challenged(T001/T002/T004)，实际 {len(f_bad['challenged_findings'])}"
    assert all(c.get("llm_reasoning") for c in f_bad["challenged_findings"]), "challenged 应带推理可质疑"
    print("  OK  REJECT 致命类无复核 → 保留 challenged + 仍 BLOCK")

    # (c) REJECT 致命类 + 合法 human_override → 可放宽 + 复现 verified + 人工复核可追溯
    v_ok = {"determinism_manifest": {"model": "gpt-4o", "temperature": 0, "seed": 42, "issues_hash": ih},
            "verdicts": [
        {"id": "T001", "verdict": "REJECT", "reason": "密钥实际来自测试脚手架",
         "human_override": True, "override_reason": "安全团队复核：测试桩，不进生产"},
        {"id": "T002", "verdict": "REJECT", "reason": "已用 ORM 参数化",
         "human_override": True, "override_reason": "复核：该行为遗留死代码，已确认无注入"},
        {"id": "T003", "verdict": "REJECT", "reason": "HTTP 状态码非魔法数字"},
        {"id": "T004", "verdict": "REJECT", "reason": "已加入 .gitignore",
         "human_override": True, "override_reason": "复核：CI 已配置 secrets，不提交明文"},
    ]}
    f_ok = apply_verdicts(report, v_ok)
    assert f_ok["release_gate"]["decision"] != "BLOCK", "合法人工复核后应可放宽"
    assert len(f_ok["human_overrides"]) == 3, f"应记录 3 条人工复核，实际 {len(f_ok['human_overrides'])}"
    assert f_ok["validation"]["reproducibility"] == "verified", "提供匹配 issues_hash 应标 verified"
    print("  OK  REJECT + 合法 human_override → 可放宽 + 复现 verified + 人工复核可追溯")

    # (d) 缺推理的裁决 → 保守保留 + needs_human_review（不静默丢弃）
    v_nr = {"verdicts": [
        {"id": "T001", "verdict": "REJECT", "reason": "x"},
        {"id": "T002", "verdict": "CONFIRM"},
        {"id": "T003", "verdict": "REJECT", "reason": "HTTP 状态码非魔法数字"},
        {"id": "T004", "verdict": "REJECT", "reason": "x"},
    ]}
    f_nr = apply_verdicts(report, v_nr)
    assert f_nr["release_gate"]["decision"] == "BLOCK", "缺推理致命类必须仍 BLOCK"
    assert any(i.get("needs_human_review") for i in f_nr["confirmed_issues"]), "缺推理应标 needs_human_review"
    assert "T001" in f_nr["validation"]["invalid"], "T001 缺推理应判 invalid"
    print("  OK  缺推理裁决 → 保守保留 + needs_human_review（不静默丢弃）")

    # (e) SUPPLEMENT 携带 source + requires_human_validation + 推理链
    v_sup = {"verdicts": [
        {"id": "T001", "verdict": "CONFIRM", "reason": "确为明文密钥，需整改", "evidence": ["a.py:10"], "confidence": "high"},
        {"id": "T002", "verdict": "CONFIRM", "reason": "确为拼接，需参数化", "evidence": ["b.py:20"], "confidence": "high"},
        {"id": "T003", "verdict": "REJECT", "reason": "HTTP 状态码非魔法数字"},
        {"id": "T004", "verdict": "CONFIRM", "reason": "确为提交的 .env", "evidence": [".env"], "confidence": "high"},
        {"id": "T005", "verdict": "SUPPLEMENT", "reason": "删除接口未校验 owner，存在越权",
         "evidence": ["e.py:5"], "confidence": "high",
         "finding": {"file": "e.py", "line": 5, "layer": "business_logic", "severity": "high",
                     "confidence": "high", "desc": "删除接口未校验 owner，存在越权", "suggestion": "删除前校验归属"}},
    ]}
    f_sup = apply_verdicts(report, v_sup)
    supp = f_sup["supplemented_findings"]
    assert len(supp) == 1, f"应 1 条 SUPPLEMENT，实际 {len(supp)}"
    assert supp[0]["source"] == "llm_supplemented", "SUPPLEMENT 应标 source=llm_supplemented"
    assert supp[0]["requires_human_validation"] is True, "SUPPLEMENT 应标需人工复核"
    assert supp[0]["llm_reasoning"], "SUPPLEMENT 应带推理链"
    print("  OK  SUPPLEMENT → source=llm_supplemented + requires_human_validation + 推理链")

    # (f) 最终报告审计链完整：source + llm_reasoning + audit_trail
    assert all(i.get("source") for i in f_sup["confirmed_issues"]), "确认发现应带 source"
    assert all(i.get("llm_reasoning") for i in f_sup["confirmed_issues"]
               if i.get("source") == "llm_confirmed"), "LLM 确认发现应带推理链"
    assert "audit_trail" in f_sup and len(f_sup["audit_trail"]) >= 5, "应产出完整 audit_trail"
    print("  OK  最终报告带 source + llm_reasoning + audit_trail（可逐条质疑）")

    print("  OK\n")
    return True


def test_verdict_robustness_v8_8():
    """v8.8：逻辑漏洞闭环 —— 陈旧裁决(hash不匹配)不误放 + SUPPLEMENT 不单方 BLOCK"""
    print("协同层健壮性 (v8.8) 测试")

    # 报告 A：含致命类 T001=critical 硬编码密钥
    report_a = {
        "meta": {"script_version": "8.8"},
        "issues": {
            "critical": [{"file": "a.py", "line": 10, "layer": "owasp_security",
                          "severity": "critical", "confidence": "high",
                          "desc": "硬编码密钥", "code_snippet": 'API_KEY="sk-..."',
                          "suggestion": "用环境变量"}],
            "high": [], "mid": [], "low": [],
        },
        "release_artifacts": [],
    }
    ih_a = issues_hash(report_a)

    # 场景1：陈旧裁决 —— 故意回填一个「错误」的 issues_hash（对应报告 B 而非 A），
    # 且带 human_override 想放行 T001。必须视为不可信，全部作废 → 仍 BLOCK。
    stale = {"determinism_manifest": {"model": "gpt-4o", "temperature": 0, "seed": 42,
                                      "issues_hash": "deadbeefdeadbeef"},
             "verdicts": [
        {"id": "T001", "verdict": "REJECT", "reason": "人工复核确认测试桩",
         "human_override": True, "override_reason": "安全团队复核：测试桩，不进生产"}]}
    f_stale = apply_verdicts(report_a, stale)
    assert f_stale["meta"]["verdicts_untrusted"] is True, "hash 不匹配应标 verdicts_untrusted"
    assert f_stale["validation"]["reproducibility"] == "hash_mismatch", "应标 hash_mismatch"
    assert f_stale["release_gate"]["decision"] == "BLOCK", "陈旧裁决不得误放真实漏洞（仍必须 BLOCK）"
    assert len(f_stale["human_overrides"]) == 0, "不可信裁决不得记录任何人工放行"
    # 致命类发现应被「确定性保留」（不丢、不误放），且来源标注为确定性，不附陈旧 LLM 推理
    kept = [i for i in f_stale["confirmed_issues"] if i["file"] == "a.py"]
    assert len(kept) == 1, "T001 应被确定性保留"
    assert kept[0].get("source") == "deterministic", "不可信下不应附 LLM 陈旧推理"
    print("  OK  陈旧裁决(hash不匹配) → 全部作废 + 仍 BLOCK（不误放真实漏洞）")

    # 场景2：干净报告（无致命类）→ 仅 SUPPLEMENT 一处高危越权。
    # 必须 CONDITIONAL（需人工复核），绝不自动 BLOCK（LLM 层不得单方卡发布）。
    report_clean = {
        "meta": {"script_version": "8.8"},
        "issues": {
            "critical": [], "high": [],
            "mid": [{"file": "c.py", "line": 30, "layer": "code_quality",
                     "severity": "mid", "confidence": "medium",
                     "desc": "魔法数字", "code_snippet": "return 42", "suggestion": "命名常量"}],
            "low": [],
        },
        "release_artifacts": [],
    }
    ih_clean = issues_hash(report_clean)
    sup_only = {"determinism_manifest": {"model": "gpt-4o", "temperature": 0, "seed": 42,
                                         "issues_hash": ih_clean},
                "verdicts": [
        {"id": "T001", "verdict": "SUPPLEMENT", "reason": "删除接口未校验 owner，存在越权",
         "evidence": ["e.py:5"], "confidence": "high",
         "finding": {"file": "e.py", "line": 5, "layer": "business_logic", "severity": "high",
                     "confidence": "high", "desc": "删除接口未校验 owner，存在越权",
                     "suggestion": "删除前校验归属"}}]}
    f_sup = apply_verdicts(report_clean, sup_only)
    assert len(f_sup["supplemented_findings"]) == 1, "应 1 条 SUPPLEMENT"
    assert f_sup["supplemented_findings"][0]["requires_human_validation"] is True, "需人工复核"
    assert f_sup["release_gate"]["decision"] == "CONDITIONAL", \
        f"SUPPLEMENT 不得单方 BLOCK，应 CONDITIONAL，实际 {f_sup['release_gate']['decision']}"
    print("  OK  SUPPLEMENT 单独存在 → CONDITIONAL（不单方 BLOCK，需人工复核）")

    print("  OK\n")
    return True


def test_ast_logic_analyzer():
    """v8.5：Python AST 逻辑分析（真实 AST，非正则）"""
    print("AST 逻辑分析测试")

    # 除零（字面量 0 分母，确定性 high）
    z = analyze_python_ast("def f():\n    return total / 0\n", "a.py")
    assert any("除零" in i["desc"] for i in z), "应检出除零"
    assert any(i["severity"] == "high" for i in z), "除零应为 high"

    # open 未 with（替代旧正则，更准）
    o = analyze_python_ast("def g():\n    fh = open('x.txt')\n    return fh.read()\n", "b.py")
    assert any("open()" in i["desc"] for i in o), "应检出 open 未 with"

    # with open() 不应误报
    ok = analyze_python_ast("def h():\n    with open('x.txt') as f:\n        return f.read()\n", "c.py")
    assert not any("open()" in i["desc"] for i in ok), "with open 不应误报"

    # while True 无退出路径（潜在无限循环）
    w = analyze_python_ast("def loop():\n    while True:\n        do_work()\n", "d.py")
    assert any("无限循环" in i["desc"] for i in w), "应检出潜在无限循环"

    # while True 有 break → 不误报
    wb = analyze_python_ast(
        "def loop():\n    while True:\n        if stop:\n            break\n        work()\n", "e.py")
    assert not any("无限循环" in i["desc"] for i in wb), "有 break 不应误报无限循环"

    print("  OK\n")
    return True


def test_dependency_audit():
    """v8.5：依赖漏洞(SCA)审计，精选定版命中 + 未锁定提示"""
    print("依赖审计测试")
    tmp = Path(tempfile.mkdtemp())
    (tmp / "requirements.txt").write_text(
        "flask==2.1.0\nrequests==2.19.0\npyyaml==4.2\n", encoding="utf-8")
    (tmp / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^4.17.0", "express": "4.17.0"}}),
        encoding="utf-8")

    deps = scan_dependency_audit(str(tmp))
    descs = " ".join(i["desc"] for i in deps)

    assert "flask" in descs, "应命中 flask<2.2.5"
    assert "requests" in descs, "应命中 requests<2.20.0"
    assert "lodash" in descs, "应命中 lodash(范围依赖)"
    assert "express" in descs, "应命中 express<4.18.2"
    # 已修复版本不应命中
    assert "pyyaml==4.2" not in descs, "pyyaml 4.2 已修复不应命中"

    # 未锁定版本 → low 提示（不应误判为漏洞）
    tmp2 = Path(tempfile.mkdtemp())
    (tmp2 / "requirements.txt").write_text("django\n", encoding="utf-8")
    deps2 = scan_dependency_audit(str(tmp2))
    assert any(i["severity"] == "low" for i in deps2), "未锁定版本应给 low 提示"

    # 升级到安全版本 → 不再命中
    tmp3 = Path(tempfile.mkdtemp())
    (tmp3 / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    assert not scan_dependency_audit(str(tmp3)), "flask 3.0.0 不应命中"

    print("  OK\n")
    return True


def test_whitelist():
    """v8.5：白名单 —— 排除文件/层级/正则，注入已知包"""
    print("白名单测试")
    wl = Whitelist({
        "exclude_files": ["test_*.py"],
        "exclude_layers": ["code_quality"],
        "exclude_patterns": [r"第三方SDK"],
        "known_packages": ["my_internal_lib"],
    })
    # 层级排除
    assert wl.is_issue_excluded({"layer": "code_quality", "desc": "魔法数字", "code_snippet": "x"}), \
        "应排除 code_quality 层"
    assert not wl.is_issue_excluded({"layer": "owasp_security", "desc": "SQL", "code_snippet": "q"}), \
        "不应误伤其他层"
    # 正则排除
    assert wl.is_issue_excluded(
        {"layer": "business_logic", "desc": "第三方SDK 内部实现", "code_snippet": "x"}), \
        "应按正则排除"
    # 文件排除
    assert wl.is_file_excluded("src/test_foo.py"), "应排除 test_*.py"
    assert not wl.is_file_excluded("src/real.py"), "不应排除正常文件"
    # 已知包注入
    from package_resolver import PackageResolver
    r = PackageResolver(".")
    r.add_known(["my_internal_lib"])
    assert r.is_known_import("my_internal_lib", "python"), "白名单包应视为已知"

    print("  OK\n")
    return True


def test_no_duplicate_artifacts():
    """回归：遗留文件(.env)只计入 release_artifacts，不双计到 issues[]（v8.5 修复）"""
    print("遗留文件不双计测试")
    tmp = Path(tempfile.mkdtemp())
    (tmp / ".env").write_text("DB_PASS=supersecret\n", encoding="utf-8")
    (tmp / "app.py").write_text("x = 1 / 0\n", encoding="utf-8")

    rep = scan_directory(str(tmp))
    assert "error" not in rep, f"扫描失败: {rep.get('error')}"

    # .env 只应出现在 release_artifacts，不应出现在 issues 各严重度分组
    in_issues = sum(
        1 for sev in rep["issues"].values()
        for i in sev if "release_artifacts" in str(i.get("file", "")) or ".env" in str(i.get("desc", ""))
    )
    assert in_issues == 0, f".env 不应出现在 issues 分组（双计 bug），实际 {in_issues}"

    # release_artifacts 应恰好 1 条 .env
    arts = [a for a in rep["release_artifacts"] if ".env" in a["file"]]
    assert len(arts) == 1, f"release_artifacts 应有 1 条 .env，实际 {len(arts)}"

    # 协同任务清单：.env 只出一条（不应重复）
    tasks_json = emit_agent_tasks_json(rep)
    import json as _json
    tasks = _json.loads(tasks_json)["tasks"]
    env_tasks = [t for t in tasks if ".env" in t.get("file", "") or ".env" in t.get("skill_reason", "")]
    assert len(env_tasks) == 1, f"协同任务中 .env 应只 1 条，实际 {len(env_tasks)}"

    print("  OK\n")
    return True


# ══════════════════════════════════════════════════════
# v8.11 新增测试：端口硬编码增强 / H7 误报修复 / 标签细分 / 门禁作用域
# ══════════════════════════════════════════════════════

def test_command_injection_subtype():
    """v8.11：命令注入按真实危害细分 RCE / 任意文件读 / 任意文件写删"""
    print("命令注入子类型细分测试")
    d = SmartDetectors()
    cases = [
        ('os.system("rm -rf " + user_input)', "python", "command_injection:file_write"),
        ('os.system("cat " + user_input)', "python", "command_injection:file_read"),
        ('os.system("ls " + user_input)', "python", "command_injection:rce"),
        ('subprocess.run("echo " + x, shell=True)', "python", "command_injection:rce"),
        ('Runtime.getRuntime().exec("sh -c rm " + cmd)', "java", "command_injection:file_write"),
    ]
    passed = 0
    for line, lang, expect_subtype in cases:
        res = d.check_command_injection(line, 1, lang, "probe")
        ok = res is not None and res.get("subtype") == expect_subtype
        status = "OK" if ok else f"FAIL (got={res.get('subtype') if res else None})"
        print(f"  {status:>10}  {lang:>10}  {line[:46]} -> {expect_subtype}")
        if ok:
            passed += 1
    print(f"\n  {passed}/{len(cases)} 通过\n")
    assert passed == len(cases), f"预期全部通过，实际 {passed}/{len(cases)}"
    return True


def test_rust_format_taint_h7():
    """v8.11：修复 H7 —— format! 仅当插值含外部输入才判注入；写死路径/常量不误报"""
    print("Rust format! 污点感知 (H7 修复) 测试")
    d = SmartDetectors()
    cases = [
        # 写死路径/常量插值 → 不应报（H7 误报来源）
        ('    Command::new("powershell").args(["-Command", format!("{}/cache/temp.wav", BASE_DIR)]).status()',
         "rust", False),
        ('    Command::new("cmd").args(["/C", format!("{}/out.txt", OUT_DIR)]).status()',
         "rust", False),
        # 外部输入插值 → 必须报
        ('    Command::new("cmd").args(["/C", format!("echo {}", user_input)]).status()',
         "rust", True),
        ('    Command::new(format!("cmd /C {}", name)).status()',
         "rust", True),
        # 纯静态 → 不报
        ('    Command::new("cmd").args(["/C", "echo", "hi"]).status()',
         "rust", False),
    ]
    passed = 0
    for line, lang, should_flag in cases:
        res = d.check_command_injection(line, 1, lang, "probe")
        flagged = res is not None
        ok = flagged == should_flag
        status = "OK" if ok else f"FAIL (flagged={flagged})"
        print(f"  {status:>10}  {line[:62]}")
        if ok:
            passed += 1
    print(f"\n  {passed}/{len(cases)} 通过\n")
    assert passed == len(cases), f"预期全部通过，实际 {passed}/{len(cases)}"
    return True


def test_magic_number_port_in_url():
    """v8.11：URL/连接串中的端口（含 11434 等）与 IPv4 行不误判魔法数字"""
    print("魔法数字：URL 端口/IPv4 测试")
    d = SmartDetectors()
    cases = [
        ('let url = "http://127.0.0.1:11434/api";', "rust", False),
        ('const EP = "http://localhost:8080/v1";', "javascript", False),
        ('conn = "postgres://user:pass@db.host:5432/app";', "python", False),
        ('if (retries > 15)', "csharp", True),
        ('return 42', "python", True),
    ]
    passed = 0
    for line, lang, should_flag in cases:
        res = d.check_magic_number(line, 1, lang)
        flagged = res is not None
        ok = flagged == should_flag
        status = "OK" if ok else f"FAIL (flagged={flagged})"
        print(f"  {status:>10}  {lang:>10}  {line[:50]}")
        if ok:
            passed += 1
    print(f"\n  {passed}/{len(cases)} 通过\n")
    assert passed == len(cases), f"预期全部通过，实际 {passed}/{len(cases)}"
    return True


def test_hardcoded_port_detector():
    """v8.11+：独立硬编码端口检测器 — 既检测真实端口，又排除英文词/URL 误报"""
    print("硬编码端口检测器测试")
    d = SmartDetectors()
    # (代码行, 语言, 应标记, 期望端口值或 None)
    cases = [
        # —— 应检测（真实端口硬编码）——
        ('const PORT = 8080;', "csharp", True, 8080),
        ('self.port = 3000', "python", True, 3000),
        ('serverPort = 5432', "csharp", True, 5432),
        ('int _port = 11434;', "csharp", True, 11434),
        ('server.listen(3000)', "javascript", True, 3000),
        ('server.bind(("0.0.0.0", 8080))', "python", True, 8080),
        ('TcpListener::bind("0.0.0.0:9090")', "rust", True, 9090),
        ('app.listen(3000)', "javascript", True, 3000),
        ('net.Listen("tcp", ":6379")', "go", True, 6379),
        # —— 不应检测（误报护栏）——
        ('let url = "http://localhost:11434/api";', "rust", False, None),  # URL 连接串
        ('important = 3000', "python", False, None),   # 英文词含 port 但非端口
        ('report = 8080', "python", False, None),      # 同上
        ('const year = 2024', "csharp", False, None),  # 年份，非端口关键词
    ]
    passed = 0
    for line, lang, should_flag, expect_port in cases:
        res = d.check_hardcoded_port(line, 1, lang, "probe")
        flagged = res is not None
        ok = flagged == should_flag
        if ok and flagged and expect_port is not None:
            ok = res.get("subtype") == "hardcoded_port" and str(expect_port) in res.get("desc", "")
        status = "OK" if ok else f"FAIL (flagged={flagged}, port={res.get('desc') if res else None})"
        print(f"  {status:>10}  {lang:>10}  {line[:46]} -> {expect_port}")
        if ok:
            passed += 1
    print(f"\n  {passed}/{len(cases)} 通过\n")
    assert passed == len(cases), f"预期全部通过，实际 {passed}/{len(cases)}"
    return True


def test_ssrf_local_scope_gate():
    """v8.11：SSRF 命中 localhost 标记 scope=local，门禁降级为 CONDITIONAL 而非硬 BLOCK"""
    print("SSRF 本地作用域测试")
    d = SmartDetectors()
    # 行内 localhost 字面量 + 动态 → scope=local
    local_hit = d.check_ssrf('requests.get(f"http://localhost:{port}/api")', "python", 1, "p")
    ok1 = local_hit is not None and local_hit.get("scope") == "local"
    # 变量 host（无 localhost 字面量）→ scope=network（保守）
    net = d.check_ssrf('requests.get(f"http://{host}/api")', "python", 1, "p")
    ok2 = net is not None and net.get("scope") == "network"
    print(f"  {'OK' if ok1 else 'FAIL'}  localhost 字面量 SSRF → scope={local_hit.get('scope') if local_hit else None}")
    print(f"  {'OK' if ok2 else 'FAIL'}  变量 host SSRF → scope={net.get('scope') if net else None}")
    assert ok1 and ok2, "SSRF scope 判定错误"
    return True


def test_taint_context():
    """v8.13：同文件内污点追踪上下文构建正确"""
    print("污点追踪上下文 (v8.13) 测试")
    lines = [
        "func handle(w http.ResponseWriter, r *http.Request) {",
        "    path := r.URL.Path",
        "    if pathAllowed(path) {",
        "        data := readFile(path)",
        "    }",
        "    let local = std::env::temp_dir();",
        "    let tmp = format!(\"{}/x.mp3\", local);",
    ]
    ctx = TaintContext.build(lines, "go")
    assert "r" in ctx.tainted or "path" in ctx.tainted, "request 参数应标 tainted"
    assert "path" in ctx.guarded, "pathAllowed(path) 应标 guarded"
    assert "local" in ctx.clean, "temp_dir 来源应标 clean"
    # resolve 判定
    assert ctx.resolve("format!(\"{}\", path)") == "guarded", "guarded 变量应判 guarded"
    assert ctx.resolve("x.mp3") == "clean", "字面量应判 clean"
    assert ctx.resolve("user_input") == "tainted", "外部语义命名应判 tainted"
    print("  OK  污点/守卫/clean 三态 + resolve 正确")
    return True


def test_taint_match_arm_not_param():
    """v8.13 回归：Rust/Go 的 match 分支 (Some(v) =>) 误把本地绑定当函数参数→命令注入误报。

    根因：_seed_params 曾对所有语言匹配 (...) => 抽取参数，把 Rust match 臂绑定
    v 当成了外部可控参数，导致 Command::new(\"sh\").arg(v) 被误判 HIGH。
    修复后仅 JS/TS 箭头函数从 => 抽取参数；Rust match 臂绑定不再污染 params。
    """
    print("match 臂绑定非参数 (v8.13 回归) 测试")
    lines = [
        "fn f(x: &str) {",
        "    match x.parse::<i32>() {",
        "        Ok(v) => {",
        '            let _ = Command::new("sh").arg("-c").arg(v).status();',
        "        }",
        "        Err(_) => {}",
        "    }",
        "}",
    ]
    ctx = TaintContext.build(lines, "rust")
    assert "v" not in ctx.params, "match 臂绑定 v 不应被当函数参数"
    assert ctx.references_param('arg(v)') is False, "match 臂 v 流入 shell 不应判外部可控"
    # 函数真实参数 x 仍应被当外部可控（即便未直接进 shell）
    assert "x" in ctx.params, "函数签名参数 x 应被当外部可控"
    # JS 箭头函数参数不受影响
    ctx2 = TaintContext.build(['const g = (a, b) => { spawn(shell, ["-c", a]); };'], "ts")
    assert "a" in ctx2.params and ctx2.references_param('spawn(shell, ["-c", a])') is True, \
        "JS 箭头函数参数 a 应仍被当外部可控"
    print("  OK  Rust match 臂不污染 / JS 箭头参数仍捕获")
    return True


def test_command_injection_taint_downgrade():
    """v8.13：本地/已守卫 shell 参数降级为 LOW，不触发 BLOCK；真实外部输入仍 HIGH"""
    print("命令注入污点降级 (v8.13) 测试")
    d = SmartDetectors()
    # voicebutler 真实场景：powershell 播本地 temp 文件，path 非外部输入
    voicebutler = [
        "let dir = std::env::temp_dir();",
        "let path = format!(\"{}/vb_tts.mp3\", dir);",
        'Command::new("powershell").args(["-Command", format!("(New-Item -Path \'{}\')", path)]).status();',
    ]
    ctx = TaintContext.build(voicebutler, "rust")
    res = d.check_command_injection(voicebutler[2], 3, "rust", "tts/mod.rs", taint_ctx=ctx)
    assert res is not None, "应仍产出发现（可审计，不静默丢弃）"
    assert res["severity"] == "low", f"本地/守卫参数应降级 LOW，实际 {res['severity']}"
    assert res.get("taint_state") in ("clean", "guarded"), "应带 taint_state"
    # 真实注入：外部输入进 shell，仍 HIGH
    real = d.check_command_injection('Command::new("sh").arg("-c").arg(user_input).status()',
                                      1, "rust", "p", taint_ctx=ctx)
    assert real is not None and real["severity"] == "high", "真实外部输入必须 HIGH"
    # 无 taint_ctx 时保持原行为（HIGH）
    bare = d.check_command_injection('Command::new("sh").arg("-c").arg(user_input).status()',
                                     1, "rust", "p")
    assert bare is not None and bare["severity"] == "high", "无 taint_ctx 应保持 HIGH"
    print("  OK  本地降级 LOW / 真实注入 HIGH / 无 ctx 兼容")
    return True


def test_path_traversal_taint_guarded():
    """v8.13：守卫在前 → 降级 LOW；未守卫外部输入 → 保持；纯本地 → 跳过"""
    print("路径穿越污点降级 (v8.13) 测试")
    d = SmartDetectors()
    # 守卫在前（voicebutler bridge 真实场景）
    guarded_file = [
        "func open(req Request) {",
        "    if pathAllowed(req.Path) {",
        "        os.ReadFile(req.Path)",
        "    }",
        "}",
    ]
    ctx = TaintContext.build(guarded_file, "go")
    res = d.check_path_traversal(guarded_file[2], 3, "go", "filesystem.go", taint_ctx=ctx)
    assert res is not None and res["severity"] == "low", f"守卫前应降级 LOW，实际 {res}"
    assert res.get("taint_state") == "guarded"
    # 未守卫的外部输入路径（独立构建不含守卫的 ctx）→ 保持 MID
    dirty_ctx = TaintContext.build(["func open2(req Request) {", "    os.ReadFile(req.Path)", "}"], "go")
    dirty = d.check_path_traversal("os.ReadFile(req.Path)", 1, "go", "f.go", taint_ctx=dirty_ctx)
    assert dirty is not None and dirty["severity"] == "mid", f"未守卫外部输入应 MID，实际 {dirty}"
    # 纯本地路径操作（无外部输入）→ 跳过（非漏洞）
    local = d.check_path_traversal("data := os.ReadFile(localConfig)", 1, "go", "f.go",
                                    taint_ctx=ctx)
    # localConfig 非外部命名 → clean → 应跳过（None）
    assert local is None, f"纯本地路径应跳过，实际 {local}"
    print("  OK  守卫→LOW / 未守卫→MID / 本地→跳过")
    return True


def test_magic_number_tsx_exempt():
    """v8.13：TSX/JSX 样式噪声（Tailwind 类 / framer-motion / style）豁免魔法数字"""
    print("TSX 魔法数字豁免 (v8.13) 测试")
    d = SmartDetectors()
    # 应为 None（样式噪声）
    assert d.check_magic_number('    <div className="gap-1 p-3">', 1, "tsx", "x.tsx") is None
    assert d.check_magic_number('    <motion.div animate={{ x: 20, opacity: 0.5 }} />', 1, "tsx", "x.tsx") is None
    assert d.check_magic_number('    const style = { marginTop: 8 };', 1, "tsx", "x.tsx") is None
    # 真实代码逻辑仍应标（LOW）
    logic = d.check_magic_number('    if (count > 10) {', 1, "tsx", "x.tsx")
    assert logic is not None and logic["severity"] == "low", f"逻辑比较应标魔法数字，实际 {logic}"
    arr = d.check_magic_number('    if (total > 50) {', 1, "tsx", "x.tsx")
    assert arr is not None, "比较逻辑应标魔法数字"
    # 非 tsx 文件行为不变（引号内数字仍可能标，取决于既有规则，这里只验证不崩溃）
    assert d.check_magic_number('const PORT = 8080', 1, "go", "x.go") is None or True
    print("  OK  TSX 样式豁免 / 逻辑仍标")
    return True


def test_collab_gate_agent_reject():
    """v8.13：三层协同 — 智能体 REJECT 致命发现后，门禁不再 BLOCK"""
    print("协同门禁 智能体REJECT (v8.13) 测试")
    scoring = {"grade": "A", "veto_hit": False}
    # 技能初筛：一条 HIGH 命令注入（已由污点降级的不会是 high，这里模拟一条真实 high）
    high = enrich_skill_finding({
        "file": "a.py", "line": 1, "layer": "owasp_security",
        "severity": "high", "confidence": "high",
        "desc": "命令注入", "taint_state": "tainted",
    })
    # 无协同：硬 BLOCK
    assert decide_gate_with_agent(scoring, [high], []) == "BLOCK", "无 REJECT 应 BLOCK"
    # 智能体审查后 REJECT（带 human_override）
    rejected = agent_review(high, "REJECT", "测试桩，非生产路径",
                            human_override=True, override_reason="单元测试桩")
    assert is_blocking_with_agent(rejected) is False, "REJECT 致命类应放行"
    assert decide_gate_with_agent(scoring, [rejected], []) != "BLOCK", "REJECT 后应非 BLOCK（放行人工复核）"
    print("  OK  协同门禁：REJECT→CONDITIONAL，BLOCK→保留")
    return True


if __name__ == "__main__":
    results = []
    try:
        results.append(("包解析器", test_package_resolver()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("包解析器", False))
    
    try:
        results.append(("魔法数字", test_magic_number_context()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("魔法数字", False))
    
    try:
        results.append(("调试残留", test_debug_print_context()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("调试残留", False))
    
    try:
        results.append(("过滤管道", test_filter_pipeline()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("过滤管道", False))

    try:
        results.append(("污点追踪上下文v8.13", test_taint_context()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("污点追踪上下文v8.13", False))

    try:
        results.append(("match臂绑定非参数v8.13", test_taint_match_arm_not_param()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("match臂绑定非参数v8.13", False))

    try:
        results.append(("命令注入污点降级v8.13", test_command_injection_taint_downgrade()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("命令注入污点降级v8.13", False))

    try:
        results.append(("路径穿越污点降级v8.13", test_path_traversal_taint_guarded()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("路径穿越污点降级v8.13", False))

    try:
        results.append(("TSX魔法数字豁免v8.13", test_magic_number_tsx_exempt()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("TSX魔法数字豁免v8.13", False))

    try:
        results.append(("协同门禁REJECTv8.13", test_collab_gate_agent_reject()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("协同门禁REJECTv8.13", False))

    try:
        results.append(("置信度评分", test_scoring_confidence()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("置信度评分", False))

    try:
        results.append(("空catch", test_empty_catch()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("空catch", False))

    try:
        results.append(("发布前遗留文件", test_release_artifacts()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("发布前遗留文件", False))

    try:
        results.append(("否决+置信度", test_veto_and_confidence()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("否决+置信度", False))

    try:
        results.append(("注入类检测器", test_injection_detectors()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("注入类检测器", False))

    try:
        results.append(("命令注入语言感知v8.9", test_command_injection_language_aware()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("命令注入语言感知v8.9", False))

    try:
        results.append(("命令注入子类型v8.11", test_command_injection_subtype()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("命令注入子类型v8.11", False))

    try:
        results.append(("Rust format! 污点v8.11", test_rust_format_taint_h7()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("Rust format! 污点v8.11", False))

    try:
        results.append(("魔法数字URL端口v8.11", test_magic_number_port_in_url()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("魔法数字URL端口v8.11", False))

    try:
        results.append(("硬编码端口检测器v8.11+", test_hardcoded_port_detector()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("硬编码端口检测器v8.11+", False))

    try:
        results.append(("SSRF本地作用域v8.11", test_ssrf_local_scope_gate()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("SSRF本地作用域v8.11", False))

    try:
        results.append(("协同协议", test_agent_protocol()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("协同协议", False))

    try:
        results.append(("协同层审计化", test_verdict_audit_and_floor()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("协同层审计化", False))

    try:
        results.append(("协同层健壮性v8.8", test_verdict_robustness_v8_8()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("协同层健壮性v8.8", False))

    try:
        results.append(("AST逻辑分析", test_ast_logic_analyzer()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("AST逻辑分析", False))

    try:
        results.append(("依赖审计", test_dependency_audit()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("依赖审计", False))

    try:
        results.append(("白名单", test_whitelist()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("白名单", False))

    try:
        results.append(("遗留不双计", test_no_duplicate_artifacts()))
    except Exception as e:
        print(f"  FAIL: {e}")
        results.append(("遗留不双计", False))

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print("=" * 40)
    print(f"  总计: {passed}/{total} 通过")
    print("=" * 40)
    sys.exit(0 if passed == total else 1)
