#!/usr/bin/env python3
"""
商业级代码审计门禁 v8.0 — 多语言AST · 生态感知 · 置信度评分 · 零误报
基于 v7.2 重写：集成 PackageResolver + SmartDetectors + ConfidenceEngine
"""

import os
import re
import ast
import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Set
from collections import defaultdict

# 导入新模块
try:
    from package_resolver import PackageResolver
    from smart_detectors import SmartDetectors, apply_all_detectors, TaintContext
    from confidence_engine import ConfidenceEngine, recalculate_score
    from release_artifacts import scan_release_artifacts
    from agent_protocol import build_agent_tasks, apply_verdicts, emit_agent_tasks_json
    from ast_logic_analyzer import analyze_python_ast
    from dependency_audit import scan_dependency_audit
    from audit_whitelist import Whitelist, load_whitelist
    _NEW_MODULES = True
except ImportError:
    _NEW_MODULES = False

SCRIPT_VERSION = "8.13"

# ── 配置 ──

LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "vue": {".vue"},
    "csharp": {".cs"},
    "cpp": {".cpp", ".h", ".hpp", ".c", ".cc", ".cxx"},
    "go": {".go"},
    "rust": {".rs"},
    "java": {".java"},
    "kotlin": {".kt", ".kts"},
}

EXCLUDED_DIRS = {
    "node_modules", "__pycache__", "venv", ".venv", "env", ".env",
    "dist", "build", ".git", "coverage", ".next", ".nuxt",
    "bin", "obj", "packages", ".vs", "Debug", "Release",
    "target", "vendor", "Pods", ".gradle", ".idea",
    ".svn", ".hg", ".audit_cache",
}

AUTO_GENERATED_PATTERNS = [
    r"^\s*//.*auto.generated",
    r"^\s*//.*DO NOT EDIT",
    r"^\s*#.*auto.generated",
    r"^\s*#.*DO NOT EDIT",
]

BUILD_SYSTEM_FILES = {
    ".csproj": "MSBuild", ".sln": "MSBuild",
    "package.json": "npm", "Cargo.toml": "Cargo",
    "go.mod": "Go", "pom.xml": "Maven",
    "build.gradle": "Gradle", "build.gradle.kts": "Gradle",
    "pyproject.toml": "Python", "setup.py": "Python",
}

# ── 辅助函数 ──

def detect_language(file_path: str) -> Optional[str]:
    ext = Path(file_path).suffix.lower()
    for lang, exts in LANGUAGE_EXTENSIONS.items():
        if ext in exts:
            return lang
    return None

def is_excluded(path: str) -> bool:
    parts = set(Path(path).parts)
    return bool(parts & EXCLUDED_DIRS)

def is_auto_generated(content: str, file_path: str) -> bool:
    first_lines = "\n".join(content.split("\n")[:5])
    for pat in AUTO_GENERATED_PATTERNS:
        if re.search(pat, first_lines, re.IGNORECASE):
            return True
    
    fname = Path(file_path).name
    if re.search(r'(\.pb2\.py|\.pb\.go|\.g\.dart|_pb2\.py|\.generated\.)', fname):
        return True
    
    return False


def check_code_quality_legacy(content: str, file_path: str, language: str) -> List[Dict]:
    """保留原始代码质量检测（作为兜底）"""
    issues = []
    lines = content.split("\n")
    
    for i, line in enumerate(lines, 1):
        # 空函数
        if re.search(r'(async\s+)?\w+\s+\w+\s*\([^)]*\)\s*\{\s*\}', line):
            if not line.strip().startswith("//"):
                issues.append({
                    "file": file_path, "line": i,
                    "desc": "空函数体", "layer": "code_quality",
                    "severity": "low", "confidence": "high",
                })
    
    return issues


# ── 核心扫描引擎 ──

def scan_file(file_path: str, root_path: str, resolver: Optional[PackageResolver],
              detector: SmartDetectors, project_type: str) -> List[Dict]:
    """扫描单个文件，返回 issue 列表"""
    issues = []
    
    try:
        content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return issues
    
    language = detect_language(file_path)
    if not language:
        return issues
    
    is_auto = is_auto_generated(content, file_path)
    
    # ── 1. AI 幻觉检测（使用 PackageResolver）──
    if resolver and language in ("python", "javascript", "typescript", "csharp"):
        _check_imports(content, file_path, language, resolver, issues)
    
    # ── 2. 智能逐行检测（SQL/密钥/SSRF/XSS 等全部由 smart_detectors 覆盖）──
    if not is_auto:
        lines = content.split("\n")
        # v8.13：同文件内污点追踪上下文（命令注入/路径穿越 sink 降级用）
        # 注意：TaintContext 为模块级类，需用模块名/直接导入访问，
        # 不可误写为 SmartDetectors.TaintContext（类属性不存在 → 静默失效）。
        try:
            taint_ctx = TaintContext.build(lines, language)
        except Exception:
            taint_ctx = None
        for i, line in enumerate(lines, 1):
            if is_auto:
                break
            smart_issues = apply_all_detectors(
                line, i, language, project_type, file_path,
                context_lines=lines, line_idx=i - 1,
                taint_ctx=taint_ctx,
            )
            issues.extend(smart_issues)

    # ── 4. 旧版代码质量兜底 ──
    if not is_auto:
        issues.extend(check_code_quality_legacy(content, file_path, language))

    # ── 5. Python AST 逻辑分析（v8.5 新增：除零/无限循环/None 解引用/open 未 with）──
    if not is_auto and language == "python":
        try:
            issues.extend(analyze_python_ast(content, file_path))
        except Exception:
            pass

    return issues


def _check_imports(content: str, file_path: str, language: str,
                   resolver: PackageResolver, issues: List[Dict]):
    """检查 import/using 语句是否为已知包"""
    lines = content.split("\n")
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        
        package_name = None
        
        if language == "python":
            m = re.search(r'(?:from|import)\s+([\w.]+)', line)
            if m:
                package_name = m.group(1).split(".")[0]
        elif language in ("javascript", "typescript"):
            m = re.search(r'(?:from|require)\s*\(?\s*["\']([^"\']+)["\']', line)
            if m:
                raw = m.group(1)
                if raw.startswith("./") or raw.startswith("../"):
                    continue  # 相对导入
                package_name = raw.split("/")[0] if "/" in raw else raw
                if package_name.startswith("@"):
                    parts = raw.split("/", 2)
                    package_name = "/".join(parts[:2]) if len(parts) >= 2 else raw
        elif language == "csharp":
            m = re.search(r'using\s+([\w.]+)\s*;', line)
            if m:
                package_name = m.group(1).split(".")[0]
        
        if package_name:
            is_known, category, reason = resolver.resolve(package_name, language)
            if not is_known:
                # 低置信度未知包 → 降级为 low severity
                issues.append({
                    "file": file_path,
                    "line": i,
                    "desc": f"未知导入: '{package_name}' — 不在已知包数据库/项目依赖中，请手动确认",
                    "layer": "ai_hallucination",
                    "severity": "low",       # v8.0: 低置信度降级为 low
                    "confidence": "low",
                    "veto": False,
                    "code_snippet": line.strip()[:120],
                    "suggestion": f"验证 {package_name} 是否为有效的外部依赖或项目内部模块。如确认可用，可添加到白名单。",
                })


def scan_directory(root_path: str, project_type: str = None,
                  whitelist: Optional[Whitelist] = None) -> Dict:
    """扫描整个目录"""
    root = Path(root_path).resolve()
    if not root.exists():
        return {"error": f"路径不存在: {root_path}"}
    
    # 初始化新模块
    resolver = None
    if _NEW_MODULES:
        resolver = PackageResolver(str(root))
        project_type = project_type or resolver._project_type
        # 白名单注入已知包（避免 AI 幻觉层误报内部库）
        if whitelist and whitelist.known_packages:
            resolver.add_known(whitelist.known_packages)
    
    project_type = project_type or "unknown"
    detector = SmartDetectors()
    engine = ConfidenceEngine(project_type)
    
    # 收集文件
    all_files = []
    for f in root.rglob("*"):
        if f.is_file() and not is_excluded(str(f)):
            if whitelist and whitelist.is_file_excluded(str(f)):
                continue
            lang = detect_language(str(f))
            if lang:
                all_files.append(str(f))
    
    # 限制大型项目扫描范围
    if len(all_files) > 200:
        # 优先源码目录
        src_dirs = {"src", "lib", "app", "api", "core", "server", "client", "main"}
        src_files = [f for f in all_files if any(d in Path(f).parts for d in src_dirs)]
        other_files = [f for f in all_files if f not in src_files]
        all_files = src_files[:150] + other_files[:50]
    
    # 扫描
    all_issues = []
    total_lines = 0

    for fpath in all_files:
        try:
            line_count = len(Path(fpath).read_text(encoding="utf-8", errors="ignore").split("\n"))
            total_lines += line_count

            issues = scan_file(fpath, str(root), resolver, detector, project_type)
            all_issues.extend(issues)
        except Exception:
            continue

    # ── 发布前遗留/调试文件检测（门禁新增维度）──
    # 注意：遗留文件仅计入 release_artifacts + 门禁裁决，不并入 all_issues，
    # 避免与 issues[] 重复（修复 v8.5 前 .env 被双计、协同任务重复出两条的 bug）。
    artifact_issues = []
    if _NEW_MODULES:
        try:
            artifact_issues = scan_release_artifacts(
                str(root), size_threshold_mb=5.0, whitelist=whitelist)
        except Exception:
            artifact_issues = []

    # ── 依赖漏洞(SCA)审计（v8.5 新增）──
    dep_issues = []
    if _NEW_MODULES:
        try:
            dep_issues = scan_dependency_audit(str(root))
        except Exception:
            dep_issues = []
    all_issues.extend(dep_issues)

    # ── 白名单过滤（v8.5）：按层级/正则排除，避免对测试/生成代码误判 ──
    if whitelist:
        all_issues = [i for i in all_issues if not whitelist.is_issue_excluded(i)]
        artifact_issues = [a for a in artifact_issues if not whitelist.is_issue_excluded(a)]

    # ── 过滤管道 ──
    filtered = engine.filter(all_issues, mode="normal")
    
    # ── 评分（置信度加权）──
    if _NEW_MODULES:
        scoring = recalculate_score(filtered.normal, max_score=80)
    else:
        scoring = _legacy_score(filtered.normal)
    
    # ── 按严重度分组 ──
    by_severity = {"critical": [], "high": [], "mid": [], "low": []}
    by_layer = defaultdict(list)
    for issue in filtered.normal:
        sev = issue.get("severity", "low")
        by_severity.setdefault(sev, []).append(issue)
        layer = issue.get("layer", "code_quality")
        by_layer[layer].append(issue)
    
    # ── 模块分布 ──
    modules = defaultdict(int)
    for fpath in all_files:
        rel = Path(fpath).relative_to(root)
        parts = rel.parts
        mod = parts[0] if len(parts) > 1 else Path(fpath).stem
        if mod == str(root.name):
            mod = "root"
        modules[mod] += 1
    
    # ── 构建报告 ──
    context_summary = resolver.get_context_summary() if resolver else {}
    
    # ── 发布门禁决策 ──
    grade = scoring.get("grade", "C")
    veto_hit = scoring.get("veto_hit", False)

    # 安全/致命层中出现高/严重问题 → 直接否决（门禁核心约束）
    BLOCKING_LAYERS = {
        "owasp_security", "product_security", "business_logic",
        "memory_performance", "ai_hallucination",
    }
    security_issues = [i for i in filtered.normal
                       if i.get("severity") in ("critical", "high") and i.get("layer") in BLOCKING_LAYERS]
    # v8.11：scope=local 的安全问题（规则4：localhost 不构成网络漏洞）不触发硬 BLOCK，
    # 仅降级为需人工复核（CONDITIONAL）；其余安全高危仍硬 BLOCK。
    # v8.13：污点分析已判为 clean/guarded（本地/已守卫，非外部输入）的发现，
    # 以及智能体已 REJECT 的发现，不再计入硬 BLOCK（交由人工 CONDITIONAL 复核）。
    has_security_high = any(
        i.get("scope") != "local"
        and i.get("taint_state") not in ("clean", "guarded")
        and i.get("agent_decision") != "reject"
        for i in security_issues)
    has_local_only_security = any(i.get("scope") == "local" for i in security_issues)
    has_artifact_block = any(
        a.get("severity") in ("critical", "high") for a in artifact_issues
    )

    if veto_hit or grade == "C" or has_security_high or has_artifact_block:
        gate_decision = "BLOCK"          # 禁止发布
    elif grade == "B" or artifact_issues or has_local_only_security or any(
            i.get("severity") == "mid" for i in filtered.normal):
        gate_decision = "CONDITIONAL"    # 有条件发布（需修复中高危/遗留）
    else:
        gate_decision = "PASS"           # 可发布

    gate_reasons = []
    if veto_hit:
        gate_reasons.append(
            "致命层存在 critical 级问题（" + ", ".join(scoring.get("veto_layers", [])) + "）→ 否决禁发"
        )
    if has_security_high:
        sec = [i for i in security_issues if i.get("scope") != "local"]
        gate_reasons.append(
            f"安全/致命层存在 {len(sec)} 个高/严重问题（如 SQL 注入、硬编码密钥、RCE）→ 禁止发布"
        )
    if has_local_only_security:
        gate_reasons.append(
            f"存在 {sum(1 for i in security_issues if i.get('scope') == 'local')} 个 localhost/本地服务暴露类安全问题"
            "（规则4：不构成网络漏洞）→ 降级为需人工复核，放行前需确认本地服务确有防护"
        )
    artifact_by_sev = {}
    for a in artifact_issues:
        artifact_by_sev[a["severity"]] = artifact_by_sev.get(a["severity"], 0) + 1
    if artifact_by_sev:
        gate_reasons.append(
            "发布前遗留/调试文件: " + ", ".join(f"{k}×{v}" for k, v in artifact_by_sev.items())
        )
    if not gate_reasons and gate_decision == "PASS":
        gate_reasons.append("未发现致命否决项与遗留文件，达到发布门禁")

    return {
        "meta": {
            "script_version": SCRIPT_VERSION,
            "audit_type": "full",
            "new_engine": _NEW_MODULES,
        },
        "summary": {
            "files_scanned": len(all_files),
            "total_lines": total_lines,
            "auto_generated_files": 0,
            "project_type": project_type,
            "project_context": context_summary,
            "build_systems": _detect_build_system(root),
            "languages": list(set(detect_language(f) for f in all_files if detect_language(f))),
            "modules": dict(sorted(modules.items(), key=lambda x: -x[1])[:15]),
            "issues_by_severity": {k: len(v) for k, v in by_severity.items()},
            "issues_by_layer": {k: len(v) for k, v in by_layer.items()},
            "total_issues": len(filtered.normal),
            "filtered_issues": filtered.filtered_out,
            "filter_reasons": filtered.filter_reasons,
            "total_raw_issues": len(all_issues),
            "release_artifacts_count": len(artifact_issues),
            "dependency_issues": len(dep_issues),
        },
        "scoring": scoring,
        "release_gate": {
            "decision": gate_decision,
            "grade": grade,
            "veto_hit": veto_hit,
            "veto_layers": scoring.get("veto_layers", []),
            "reasons": gate_reasons,
            "artifact_summary": artifact_by_sev,
        },
        "release_artifacts": artifact_issues,
        "top5_critical": by_severity.get("critical", [])[:5],
        "issues": by_severity,
        "filtered_out_count": filtered.filtered_out,
    }


def _detect_build_system(root: Path) -> List[str]:
    systems = []
    for fname, label in BUILD_SYSTEM_FILES.items():
        if (root / fname).exists():
            systems.append(label)
    return systems or ["未识别"]


def _legacy_score(issues: List[Dict]) -> Dict:
    """旧版评分（兼容模式）"""
    layer_max = {
        "ai_hallucination": 15, "code_quality": 8, "business_logic": 15,
        "owasp_security": 15, "memory_performance": 8, "exception_handling": 6,
        "engineering": 5, "product_security": 8,
    }
    deductions = {k: 0.0 for k in layer_max}
    counts = {k: {"critical": 0, "high": 0, "mid": 0, "low": 0} for k in layer_max}
    
    for issue in issues:
        layer = issue.get("layer", "code_quality")
        sev = issue.get("severity", "low")
        if layer in counts:
            counts[layer][sev] = counts[layer].get(sev, 0) + 1
        w = {"critical": 3.0, "high": 2.0, "mid": 1.0, "low": 0.5}.get(sev, 0.5)
        if layer in deductions:
            deductions[layer] += w
    
    scores = {}
    total = 0
    for layer, mx in layer_max.items():
        s = max(0, mx - deductions[layer])
        scores[layer] = {"score": round(s, 1), "max": mx, "deduction": round(deductions[layer], 1), "counts": counts[layer]}
        total += s
    
    pct = round(total / 80 * 100, 1)
    grade = "S" if pct >= 87.7 else "A" if pct >= 74.6 else "B" if pct >= 57 else "C"
    return {"total_score": round(total, 1), "total_max": 80, "percentage": pct, "grade": grade, "layers": scores}


def generate_markdown_report(report: Dict) -> str:
    """生成人类可读的 Markdown 报告"""
    s = report["summary"]
    sc = report["scoring"]
    
    md = f"""# 代码审计门禁报告 v{SCRIPT_VERSION}

## 基本信息
| 项 | 值 |
|----|-----|
| 审计模式 | full |
| 项目类型 | {s['project_type']} |
| 构建系统 | {', '.join(s['build_systems'])} |
| 代码语言 | {', '.join(s['languages'])} |
| 源码文件 | {s['files_scanned']} 个 |
| 总代码行 | {s['total_lines']} 行 |
| 原始发现 | {s['total_raw_issues']} 个 |
| 去噪后 | {s['total_issues']} 个 |
| 自动过滤 | {s['filtered_issues']} 个 |

## 评分卡
| 层级 | 得分/满分 | 扣分 | 状态 |
|------|:---:|------|:---:|
"""
    for layer, data in sc.get("layers", {}).items():
        md += f"| {layer} | {data['score']}/{data['max']} | -{data['deduction']} | {data['counts']} |\n"
    
    md += f"\n**总分: {sc['total_score']}/{sc['total_max']} ({sc['percentage']}%) — {sc['grade']}级**\n"

    # 发布门禁结论
    gate = report.get("release_gate", {})
    if gate:
        decision = gate.get("decision", "PASS")
        emoji = {"PASS": "✅", "CONDITIONAL": "⚠️", "BLOCK": "🚫"}.get(decision, "✅")
        md += f"\n## 发布门禁结论\n\n{emoji} **{decision}**"
        if gate.get("veto_hit"):
            md += "（致命层否决）"
        md += "\n\n"
        for reason in gate.get("reasons", []):
            md += f"- {reason}\n"

    # 发布前遗留/调试文件
    arts = report.get("release_artifacts", [])
    if arts:
        md += f"\n## 发布前遗留/调试文件（{len(arts)} 项）\n\n"
        md += "| 文件 | 层级 | 严重度 | 置信度 | 说明 |\n"
        md += "|------|------|:---:|:---:|------|\n"
        for a in arts[:50]:
            md += f"| {a.get('file','')} | {a.get('layer','')} | {a.get('severity','')} | {a.get('confidence','')} | {a.get('desc','')} |\n"
        md += "\n"

    if s.get("filtered_issues", 0) > 0:
        md += f"\n> 自动过滤了 {s['filtered_issues']} 个低置信度/安全上下文中的发现。\n"
        if s.get("filter_reasons"):
            md += f"> 过滤原因: {s['filter_reasons']}\n"

    return md


# ── 自测试 ──

def run_self_test() -> bool:
    """运行内置自测试（44 项，覆盖全引擎）"""
    print("=" * 60)
    print(f"  代码审计门禁 v{SCRIPT_VERSION} 自测试")
    print("=" * 60)

    tests = []

    # ── 1. 包解析器（12 项）──
    print("\n1. 包解析器 (PackageResolver)")
    if _NEW_MODULES:
        r = PackageResolver(".")
        checks = [
            ("zlib", "python", True), ("ctypes", "python", True),
            ("lzma", "python", True), ("os", "python", True),
            ("json", "python", True), ("requests", "python", True),
            ("flask", "python", True), ("react", "javascript", True),
            ("vite", "typescript", True), ("System", "csharp", True),
            ("System.IO", "csharp", True), ("__unknown_pkg_xyz__", "python", False),
        ]
        for name, lang, exp in checks:
            tests.append((f"包解析 {name}/{lang}", r.is_known_import(name, lang) == exp))

    # ── 2. 魔法数字（6 项）──
    print("\n2. 魔法数字 (SmartDetectors)")
    d = SmartDetectors()
    mn_checks = [
        ("using (var b = new SolidBrush(Color.FromArgb(7, 193, 96)))", "csharp", False),
        ("var sb = new StringBuilder(512);", "csharp", False),
        ("new byte[1024];", "csharp", False),
        ("if (retries > 15)", "csharp", True),
        ("return 42", "python", True),
        ('if status == 404', "csharp", True),
    ]
    for line, lang, flag in mn_checks:
        res = d.check_magic_number(line, 1, lang) is not None
        tests.append((f"魔法数字 {line[:30]}", res == flag))

    # ── 3. 调试残留（6 项）──
    print("\n3. 调试残留 (SmartDetectors)")
    dp_checks = [
        ('print("hello")', "python", "cli", False),
        ('print("debug")', "python", "api", True),
        ('console.log("x")', "javascript", "cli", False),
        ('console.log("x")', "typescript", "api", True),
        ('Debug.WriteLine("[FATAL]")', "csharp", "desktop", True),
        ('logger.debug("x")', "python", "api", False),
    ]
    for line, lang, ptype, flag in dp_checks:
        res = d.check_debug_prints(line, 1, lang, ptype) is not None
        tests.append((f"调试残留 {line[:25]}", res == flag))

    # ── 4. 空 catch（4 项）──
    print("\n4. 空 catch (SmartDetectors)")
    ec_checks = [
        ("except: pass", "python", True),
        ("catch (Exception) { }", "csharp", True),
        ('catch (Exception e) { logger.error(e); }', "csharp", False),
        ("except: pass  # ignore", "python", False),
    ]
    for line, lang, flag in ec_checks:
        ctx = [line]
        res = d.check_empty_catch(line, 1, ctx) is not None
        tests.append((f"空catch {line[:28]}", res == flag))

    # ── 5. SQL 注入（4 项）──
    print("\n5. SQL 注入 (SmartDetectors)")
    sql_checks = [
        ('query = "SELECT * FROM u WHERE n = \'" + name + "\'"', True),
        ('cursor.execute("SELECT * FROM u WHERE id = %s" % uid)', True),
        ('cursor.execute("SELECT * FROM u WHERE id = ?", (uid,))', False),
        ('q = "SELECT * FROM u"', False),
    ]
    for line, flag in sql_checks:
        res = d.check_sql_injection(line, 1, "python") is not None
        tests.append((f"SQL {line[:30]}", res == flag))

    # ── 6. 发布前遗留文件（4 项）──
    print("\n6. 发布前遗留文件 (release_artifacts)")
    import tempfile
    tmp = Path(tempfile.mkdtemp())
    for fn in [".env", "key.pem", "app.bak", "app.js.map"]:
        (tmp / fn).write_text("x", encoding="utf-8")
    arts = scan_release_artifacts(str(tmp))
    found = {a["desc"].split(":")[0] for a in arts}
    tests.append(("检出 .env", any(".env" in a["desc"] for a in arts)))
    tests.append(("检出私钥 .pem", any("key.pem" in a["file"] for a in arts)))
    tests.append(("检出备份 .bak", any("app.bak" in a["file"] for a in arts)))
    tests.append(("检出源码映射 .js.map", any("app.js.map" in a["file"] for a in arts)))

    # ── 7. 置信度方向 + 否决（8 项）──
    print("\n7. 置信度评分 + 否决 (ConfidenceEngine)")
    no_issues = recalculate_score([])
    tests.append(("无问题 → S/100%", no_issues["grade"] == "S" and no_issues["percentage"] == 100.0))

    hi_crit = recalculate_score([{"layer": "owasp_security", "severity": "critical",
                                  "confidence": "high", "desc": "SQL"}])
    tests.append(("1 critical(high) → 扣分", hi_crit["percentage"] < 100.0))

    lo_low = recalculate_score([{"layer": "code_quality", "severity": "low",
                                 "confidence": "low", "desc": "magic"}])
    tests.append(("1 low(low) → 几乎不扣", lo_low["percentage"] > 95.0))

    # 方向：固定 low 严重度，高置信应比低置信扣得更多
    s_hi = recalculate_score([{"layer": "code_quality", "severity": "low",
                               "confidence": "high", "desc": "x"}])["percentage"]
    s_lo = recalculate_score([{"layer": "code_quality", "severity": "low",
                               "confidence": "low", "desc": "x"}])["percentage"]
    tests.append(("高置信扣分 > 低置信", s_hi < s_lo))

    # 否决：致命层 critical → veto_hit + C
    one_crit = recalculate_score([{"layer": "owasp_security", "severity": "critical",
                                   "confidence": "high", "desc": "SQL"}])
    tests.append(("1 critical → veto_hit", one_crit["veto_hit"] is True))
    tests.append(("1 critical → 判级 C", one_crit["grade"] == "C"))

    ten_crit = recalculate_score([{"layer": "owasp_security", "severity": "critical",
                                   "confidence": "high", "desc": "SQL"} for _ in range(10)])
    tests.append(("10 critical → veto_hit", ten_crit["veto_hit"] is True))
    tests.append(("10 critical → 判级 C(禁发)", ten_crit["grade"] == "C"))

    # ── 8. AST 逻辑分析 + 依赖审计 + 白名单（v8.5 新增）──
    print("\n8. AST逻辑/依赖审计/白名单 (v8.5)")
    ast_zero = analyze_python_ast("def f():\n    return 1 / 0\n", "probe.py")
    tests.append(("AST 检出除零", any("除零" in i["desc"] for i in ast_zero)))
    ast_open = analyze_python_ast(
        "def g():\n    f = open('a.txt')\n    return f.read()\n", "probe.py")
    tests.append(("AST 检出 open 未 with", any("open()" in i["desc"] for i in ast_open)))
    tmpd = Path(tempfile.mkdtemp())
    (tmpd / "requirements.txt").write_text(
        "flask==2.1.0\nrequests==2.19.0\n", encoding="utf-8")
    dep = scan_dependency_audit(str(tmpd))
    tests.append(("依赖审计命中 flask CVE", any("flask" in i["desc"] for i in dep)))
    tests.append(("依赖审计命中 requests CVE", any("requests" in i["desc"] for i in dep)))
    wl = Whitelist({"exclude_layers": ["code_quality"]})
    tests.append(("白名单排除层级", wl.is_issue_excluded(
        {"layer": "code_quality", "desc": "魔法数字 42", "code_snippet": "return 42"})))
    tests.append(("白名单不误伤其他层", not wl.is_issue_excluded(
        {"layer": "owasp_security", "desc": "SQL拼接", "code_snippet": "execute(q)"})))

    # ── 结果 ──
    print("\n" + "=" * 60)
    passed = sum(1 for _, ok in tests if ok)
    total = len(tests)
    for name, ok in tests:
        print(f"  {'OK' if ok else 'FAIL':>4}  {name}")
    print(f"\n  结果: {passed}/{total} 通过, {total - passed} 失败")
    print("=" * 60)
    return passed == total


# ── 入口 ──

def main():
    parser = argparse.ArgumentParser(description=f"代码审计门禁 v{SCRIPT_VERSION}")
    parser.add_argument("path", nargs="?", default="./src")
    parser.add_argument("--output", "-o", default=None)
    parser.add_argument("--output-md", default=None)
    parser.add_argument("--project-type", default=None)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--strict", action="store_true", help="不过滤，输出全部发现")
    parser.add_argument("--agent-mode", action="store_true",
                        help="仅输出疑似任务清单(agent_tasks)，供 LLM 智能体三态确认，省 token")
    parser.add_argument("--agent-tasks-out", default=None,
                        help="--agent-mode 的清单输出路径（默认打印到 stdout）")
    parser.add_argument("--apply-verdicts", default=None,
                        help="传入 LLM 智能体三态裁决 JSON，合并产出最终发布裁决")
    parser.add_argument("--whitelist", default=None,
                        help="白名单 JSON 路径：排除文件/目录/层级/规则，注入已知包（见 SKILL.md）")
    args = parser.parse_args()
    
    if args.self_test:
        ok = run_self_test()
        sys.exit(0 if ok else 1)
    
    result = scan_directory(args.path, args.project_type,
                            whitelist=load_whitelist(args.whitelist))
    
    if "error" in result:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(1)
    
    # ── 协同模式 1：skill 初筛 → 输出疑似任务清单 ──
    if args.agent_mode:
        tasks_json = emit_agent_tasks_json(result, indent=2)
        if args.agent_tasks_out:
            Path(args.agent_tasks_out).write_text(tasks_json, encoding="utf-8")
            print(f"OK agent_tasks: {args.agent_tasks_out}", file=sys.stderr)
        else:
            print(tasks_json)
        sys.exit(0)
    
    # ── 协同模式 2：合并 LLM 三态裁决 → 最终发布裁决 ──
    if args.apply_verdicts:
        with open(args.apply_verdicts, encoding="utf-8") as fh:
            verdicts = json.load(fh)
        final = apply_verdicts(result, verdicts)
        final_json = json.dumps(final, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(final_json, encoding="utf-8")
            print(f"OK final: {args.output}", file=sys.stderr)
        else:
            print(final_json)
        sys.exit(0)
    
    # JSON 输出
    output = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"OK JSON: {args.output}", file=sys.stderr)
    else:
        print(output)
    
    # Markdown 输出
    if args.output_md:
        md = generate_markdown_report(result)
        Path(args.output_md).write_text(md, encoding="utf-8")
        print(f"OK Markdown: {args.output_md}", file=sys.stderr)


if __name__ == "__main__":
    main()
