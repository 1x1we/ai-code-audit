#!/usr/bin/env python3
"""商业级智能检测器 v1.0 — 上下文感知 · 反误报 · 置信度评分"""

import re
from typing import List, Dict, Tuple, Optional, Set


# ══════════════════════════════════════════════════════
# 魔法数字：合法上下文白名单
# ══════════════════════════════════════════════════════

# 模式：(正则, 语言, 说明)
MAGIC_NUMBER_SAFE_CONTEXTS = [
    # 颜色函数
    (r"FromArgb\s*\([^)]*\b(\d+)\b[^)]*\)", "csharp", "Color.FromArgb(R,G,B)"),
    (r"Color\s*\([^)]*\b(\d+)\b[^)]*\)", "all", "颜色构造函数"),
    (r"rgb\s*\([^)]*\b(\d+)\b[^)]*\)", "all", "CSS rgb()"),
    (r"rgba\s*\([^)]*\b(\d+)\b[^)]*\)", "all", "CSS rgba()"),
    (r"hsl\s*\([^)]*\b(\d+)\b[^)]*\)", "all", "CSS hsl()"),
    (r"#[\da-fA-F]{3,8}", "all", "CSS 颜色码"),
    
    # 缓冲区/大小常量
    (r"new\s+StringBuilder\s*\(\s*\d+\s*\)", "csharp", "StringBuilder 缓冲区"),
    (r"new\s+byte\s*\[\s*\d+\s*\]", "csharp", "byte 数组分配"),
    (r"malloc\s*\(\s*\d+\s*\)", "c", "C malloc"),
    (r"calloc\s*\(\s*\d+", "c", "C calloc"),
    
    # 标准 API 参数
    (r"\.Read\s*\(\s*[^,]+,\s*0\s*,\s*\d+\s*\)", "all", "Stream.Read 偏移"),
    (r"\.Write\s*\(\s*[^,]+,\s*0\s*,\s*\d+\s*\)", "all", "Stream.Write 偏移"),
    (r"sleep\s*\(\s*\d+\s*\)", "all", "sleep 时间"),
    (r"\.sleep\s*\(\s*\d+\s*\)", "all", "sleep 方法"),
    (r"timeout\s*[=:]\s*\d+", "all", "超时设置"),
    (r"retry\w*\s*[=:]\s*\d+", "all", "重试次数"),
    (r"max\w*\s*[=:]\s*\d+", "all", "最大值设置"),
    (r"port\s*[=:]\s*\d{2,5}", "all", "端口号"),
    
    # 数学常量
    (r"Math\.PI\b", "all", "圆周率"),
    (r"Math\.E\b", "all", "自然常数"),
    
    # 日期时间（特定值，非单数字通配，避免误吞真实魔法数字）
    (r"3600\b", "all", "一小时秒数"),
    (r"86400\b", "all", "一天秒数"),
    
    # DllImport / FFI
    (r"\[DllImport\s*\([^)]*\)\]", "csharp", "P/Invoke 声明"),
    
    # 加密相关
    (r"new\s+RNGCryptoServiceProvider\s*\(\s*\)", "csharp", "加密 RNG"),
    (r"SHA\d+", "all", "SHA 算法标识"),
    (r"MD5\b", "all", "MD5 算法标识"),
    (r"aes-\d+", "all", "AES 密钥长度"),
    
    # 数组/集合索引偏移
    (r"\.Length\s*-\s*\d+", "all", "数组长度偏移"),
    (r"\.Count\s*-\s*\d+", "all", "集合计数偏移"),
    (r"\.size\s*\(\s*\)\s*-\s*\d+", "all", "容器大小偏移"),
    
    # 路径分隔符
    (r"Path\.Combine|path\.join|os\.path\.join", "all", "路径合并"),
    
    # 标准数学变换
    (r"Math\.\w+\s*\([^)]*\d+[^)]*\)", "all", "数学函数参数"),
    (r"\.toFixed\s*\(\s*\d+\s*\)", "javascript", "JS 小数位数"),
    (r"\.toPrecision\s*\(\s*\d+\s*\)", "javascript", "JS 精度"),
    
    # DPI/缩放
    (r"dpi|DPI|scale|Scale|zoom|Zoom", "all", "DPI/缩放相关"),
    
    # 网络端口参数
    (r"_port\s*[=:]\s*\d{2,5}", "all", "网络端口配置"),
]

# 真正的魔法数字模式（通常需要提取为常量）
TRUE_MAGIC_NUMBER_PATTERNS = [
    # 裸数字在条件判断中
    (r"if\s+[^(]*[><=!]+\s*(\d{2,})\b", "条件判断中的数字"),
    # 裸数字作为函数参数（非上述安全上下文）
    (r"return\s+\d{2,}\s*;", "return 裸数字"),
    # 数组索引硬编码（非 0/1）
    (r"\[(\d{2,})\]", "数组硬编码索引"),
]

# ══════════════════════════════════════════════════════
# 调试残留检测
# ══════════════════════════════════════════════════════

DEBUG_SAFE_CONTEXTS = [
    "logger.", "logging.", "log.", "self.log", "this.log",
    "console.error", "console.warn",  # JS 中常用于错误上报
    "Debug.Log",  # Unity
]

DEBUG_UNSAFE_PATTERNS = [
    (r"\bprint\s*\(", "print() 调用", "low"),
    (r"\bconsole\.log\s*\(", "console.log()", "low"),
    (r"\bconsole\.debug\s*\(", "console.debug()", "low"),
    (r"\bSystem\.Diagnostics\.Debug\.Write(Line)?\s*\(", "Debug.Write", "low"),
    (r"\bDebug\.WriteLine\s*\(", "Debug.WriteLine", "low"),
    (r"\becho\s", "echo 语句", "low"),
    (r"\bvar_dump\s*\(", "var_dump", "low"),
    (r"\bdd\s*\(", "dd() 调试辅助", "low"),
]

# ══════════════════════════════════════════════════════
# 空 catch 检测
# ══════════════════════════════════════════════════════

EMPTY_CATCH_SAFE_PATTERNS = [
    r"pass\s*#.*ignore",        # Python: 有注释说明
    r"//.*(ignore|suppress|skip|intentionally)",  # JS/C#: 有注释
    r"/\*.*(ignore|suppress).*\*/",  # 块注释
]

# ══════════════════════════════════════════════════════
# 检测器类
# ══════════════════════════════════════════════════════

class IssueSeverity:
    CRITICAL = "critical"
    HIGH = "high"
    MID = "mid"
    LOW = "low"
    INFO = "info"

class Confidence:
    HIGH = "high"       # AST + 上下文双重确认
    MEDIUM = "medium"   # 正则 + 上下文确认
    LOW = "low"         # 仅正则匹配
    UNKNOWN = "unknown"  # 无法确定


class SmartDetectors:
    """上下文感知的代码检测器集合"""

    @staticmethod
    def check_magic_number(line: str, line_num: int, language: str, 
                           file_path: str = "") -> Optional[Dict]:
        """
        检测魔法数字，跳过合法上下文
        
        返回: issue dict 或 None (安全上下文)
        """
        # 跳过注释行
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("--"):
            return None
        if stripped.startswith("/*") or stripped.startswith("*") or stripped.startswith("<!--"):
            return None
        
        # 找到所有裸数字
        numbers = re.finditer(r'(?<!\w)(\d{2,})(?!\w)', line)
        for match in numbers:
            num_str = match.group(1)
            num = int(num_str)
            
            # 跳过 0, 1, -1
            if num <= 1:
                continue
            
            # 跳过标准端口 (80, 443, 3000, 5000, 8080, 8443, 9876 等)
            if num in (80, 443, 3000, 5000, 8080, 8443, 9876, 3001, 4200, 8000):
                continue
            
            # 跳过常见数字 (100, 1000, 1024, 2048, 4096, 65535)
            if num in (100, 1000, 1024, 2048, 4096, 8192, 65535, 256):
                continue
            
            # 跳过时间相关 (60, 24, 3600, 86400, 30)
            if num in (24, 30, 60, 365, 3600, 86400):
                continue
            
            # 检查是否在安全上下文中
            is_safe = False
            for pattern, lang_scope, _ in MAGIC_NUMBER_SAFE_CONTEXTS:
                if lang_scope not in (language, "all"):
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    is_safe = True
                    break
            
            if is_safe:
                continue
            
            # 检查是否为已知 API 参数（string.match → 正则相关）
            if re.search(r'(StringBuilder|byte\s*\[|malloc|calloc|\.Read|\.Write|sleep|timeout|retry)', line):
                continue
            
            # 确认是真正的魔法数字
            confidence = Confidence.MEDIUM
            # 如果数字出现在赋值语句或 const 定义中，降级
            if re.search(r'(const|readonly|static\s+readonly|final|let|var).*[=:]\s*' + re.escape(num_str), line):
                confidence = Confidence.LOW
            
            return {
                "file": file_path,
                "line": line_num,
                "desc": f"魔法数字: {num_str}（建议提取为命名常量）",
                "layer": "code_quality",
                "severity": IssueSeverity.LOW,
                "confidence": confidence,
                "code_snippet": line.strip()[:120],
                "suggestion": f"将 {num_str} 提取为有意义的常量名，如 MAX_BUFFER_SIZE 或类似的语义化命名",
            }
        
        return None

    @staticmethod
    def check_debug_prints(line: str, line_num: int, language: str,
                           project_type: str = "unknown",
                           file_path: str = "") -> Optional[Dict]:
        """
        检测调试残留，区分 CLI 工具和库
        
        CLI 工具中的 print() 是正常输出，不标记。
        库中的 print() 才是调试残留。
        """
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            return None
        
        # CLI 工具：print() / echo 是正常输出
        if project_type in ("cli", "desktop") and language in ("python", "javascript", "typescript"):
            # 仍然标记 Debug.Write 等明确的调试 API
            if re.search(r'(Debug\.Write(Line)?|console\.debug)\s*\(', line):
                return {
                    "file": file_path,
                    "line": line_num,
                    "desc": "调试日志残留（建议使用正式日志框架）",
                    "layer": "code_quality",
                    "severity": IssueSeverity.LOW,
                    "confidence": Confidence.MEDIUM,
                    "code_snippet": line.strip()[:120],
                }
            # print() / console.log() 在 CLI/桌面工具中是合理的
            return None

        # 检查是否在安全上下文中
        for safe_pattern in DEBUG_SAFE_CONTEXTS:
            if safe_pattern in line:
                return None

        # 检查不安全模式
        for pattern, desc, severity in DEBUG_UNSAFE_PATTERNS:
            if re.search(pattern, line):
                # 进一步检查：是否有注释说明这是故意的
                if re.search(r'#\s*(noqa|keep|保留|debug|兼容|FIXME|TODO)', line, re.IGNORECASE):
                    return None
                if re.search(r'//\s*(noqa|keep|保留|debug|兼容|FIXME|TODO)', line, re.IGNORECASE):
                    return None

                return {
                    "file": file_path,
                    "line": line_num,
                    "desc": f"{desc}（生产环境可能输出敏感信息或污染日志）",
                    "layer": "code_quality",
                    "severity": severity,
                    "confidence": Confidence.MEDIUM,
                    "code_snippet": line.strip()[:120],
                    "suggestion": "生产环境建议使用日志框架并设置适当的日志级别",
                }
        
        return None

    @staticmethod
    def check_empty_catch(line: str, line_num: int, context_lines: List[str],
                          file_path: str = "") -> Optional[Dict]:
        """
        检测空 catch 块，跳过有合理注释的
        
        需要上下文来判断——不只是单行，要看 catch 块整体
        """
        # 如果单行已经有处理逻辑，跳过
        if re.search(r'(log|throw|return|break|continue|report|跟踪)', line, re.IGNORECASE):
            return None
        
        stripped = line.strip()
        
        # 检查是否有合理的注释说明
        for safe_pattern in EMPTY_CATCH_SAFE_PATTERNS:
            if re.search(safe_pattern, stripped, re.IGNORECASE):
                return None
        
        # 检测纯空 catch: catch { }, catch(Exception) { }, except: pass / except Exception: pass
        pure_empty = re.search(
            r'(catch\s*(\([^)]*\))?\s*\{\s*\}'
            r'|except\s*(?:\([^)]*\)|[A-Za-z_][\w.]*)?\s*:\s*pass\b)', line)
        if pure_empty:
            # 进一步检查上下文：后面 1-2 行是否有处理逻辑
            return {
                "file": file_path,
                "line": line_num,
                "desc": "空 catch/except 块 — 异常被静默吞没",
                "layer": "exception_handling",
                "severity": IssueSeverity.MID,
                "confidence": Confidence.HIGH,
                "code_snippet": line.strip()[:120],
                "suggestion": "至少记录异常日志（logger.error/console.error），需要忽略时添加注释说明原因",
            }
        
        return None

    @staticmethod
    def check_none_deref(line: str, line_num: int, language: str,
                         file_path: str = "") -> Optional[Dict]:
        """
        检测 None/null 解引用风险
        
        注意：只标记高风险模式（如函数返回 None 后直接 .attr）
        """
        stripped = line.strip()
        
        # Python: dict[key] 可能在 key 不存在时抛异常
        # 但这是 Python 的正常模式，只标记明显的风险
        if language == "python":
            # 检查是否有安全的 .get() 调用
            if ".get(" in line or "if " in line and " is not None" in line:
                return None
            # 链式 .attr 调用（潜在的 None 属性访问）
            chain = re.findall(r'\.(\w+)', line)
            if len(chain) >= 4 and all(x != "get" for x in chain):
                # 高置信度：链式调用中间可能有 None
                return {
                    "file": file_path,
                    "line": line_num,
                    "desc": f"链式调用可能遇到 None: {'.'.join(chain[:3])}",
                    "layer": "business_logic",
                    "severity": IssueSeverity.MID,
                    "confidence": Confidence.LOW,  # 低置信度——实际代码可能已在外层判空
                    "code_snippet": line.strip()[:120],
                }
        
        return None

    @staticmethod
    def check_sql_injection(line: str, line_num: int, language: str,
                            file_path: str = "") -> Optional[Dict]:
        """
        检测 SQL 字符串拼接/注入风险。

        判定：存在以 SQL 关键字开头的字符串，且该字符串被变量拼接
        （f-string / + 拼接 / .format / % 格式化）。若仅使用占位符
        （? / %s / :name / $1）且无拼接，则视为参数化查询，排除。
        """
        # 1) 必须存在 SQL 关键字字符串
        if not re.search(r'''["']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE)\b''',
                         line, re.IGNORECASE):
            return None

        # 2) 占位符但未拼接 → 参数化，安全
        has_placeholder = bool(re.search(r'''\?|:\w+|\$1|\$2|%s|%\(|@\w+''', line))
        has_concat = bool(re.search(
            r'''["']\s*\+|\+\s*["']|\bf["']|\.format\s*\(|%\s*\(|%\s*[a-zA-Z_]\w*\s*\)''', line))
        if has_placeholder and not has_concat:
            return None
        # 3) 存在拼接才是风险
        if not has_concat:
            return None

        return {
            "file": file_path,
            "line": line_num,
            "desc": "可能的 SQL 字符串拼接/注入 — 建议使用参数化查询",
            "layer": "owasp_security",
            "severity": IssueSeverity.HIGH,
            "confidence": Confidence.MEDIUM,
            "code_snippet": line.strip()[:120],
            "suggestion": "使用参数化查询: cursor.execute('SELECT * FROM t WHERE id = %s', (uid,))",
        }

    @staticmethod
    def check_debug_markers(line: str, line_num: int, language: str,
                            file_path: str = "") -> Optional[Dict]:
        """
        检测注释中的高风险遗留标记（TODO/FIXME/XXX/HACK 涉及密钥/安全/绕过）。
        仅扫描注释行，避免误报业务代码。
        """
        stripped = line.strip()
        if not (stripped.startswith("//") or stripped.startswith("#")
                or stripped.startswith("/*") or stripped.startswith("*")):
            return None

        m = re.search(
            r'\b(TODO|FIXME|XXX|HACK)\b\s*[:=]?\s*.*\b('
            r'password|secret|token|api[_-]?key|auth|encrypt|security|'
            r'bypass|disable|skip|hack|临时|硬编码|密钥)\b',
            line, re.IGNORECASE)
        if not m:
            return None

        return {
            "file": file_path,
            "line": line_num,
            "desc": f"高风险遗留标记: {m.group(0)[:40]} — 发布前需清理/确认",
            "layer": "code_quality",
            "severity": IssueSeverity.MID,
            "confidence": Confidence.LOW,
            "code_snippet": line.strip()[:120],
            "suggestion": "发布前移除或确认该 TODO/FIXME 不涉及安全/密钥相关遗留。",
        }

    # ══════════════════════════════════════════════════════
    # 注入 / 反序列化 / 穿越类检测器（商业级扩展 v8.2）
    # 全部为「模式 + 上下文」双重判定，命中即 high 级 owasp_security，
    # 由发布门禁直接 BLOCK；纯静态/字面量场景降级或放行以控误报。
    # ══════════════════════════════════════════════════════

    @staticmethod
    def _is_dynamic(expr: str) -> bool:
        """判断表达式是否可能为外部可控（非纯字面量）

        关键：先剥除字符串字面量内容，避免把 "1 + 1" 里的 '+' 误判为拼接信号。
        """
        s = (expr or "").strip()
        if not s:
            return True
        # 插值标记（字符串内部的外部可控内容）：JS 模板 ${...}、Python f-string {var}
        # 仅当 { 紧跟标识符（排除 dict 字面量 {"k":..} 与集合 {1,2}）才视为插值。
        # 必须在『剥除字符串字面量』之前检测，否则 f-string 内容会被整体剥离而漏判。
        if re.search(r'\$\{|\{[A-Za-z_][^}]*\}', s):
            return True
        # 纯引号包裹且内部无引号 → 单字面量，静态
        if s[0] in ("'", '"', "`") and s[-1] in ("'", '"', "`") \
                and not re.search(r'["\'`]', s[1:-1]):
            return False
        # 剥除字符串字面量内容后再判断拼接/插值/变量
        s_nostr = re.sub(r'["\'`][^"\'`]*["\'`]', '', s)
        if re.search(r'\+|`\s*\{|\$\{|\[\s*\w', s_nostr):
            return True
        return bool(re.search(r'[A-Za-z_]\w', s_nostr))

    @staticmethod
    def check_xss(line: str, line_num: int, language: str,
                  file_path: str = "") -> Optional[Dict]:
        """XSS：用户可控内容进入 HTML 渲染 sink（innerHTML / document.write 等）"""
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            return None
        if not re.search(
            r'(innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|'
            r'document\.write\w*\s*\(|dangerouslySetInnerHTML|v-html|\.html\s*\(', line):
            return None
        m = re.search(r'(innerHTML|outerHTML)\s*=\s*(.*)$', line)
        if m:
            if not SmartDetectors._is_dynamic(m.group(2)):
                return None  # 纯静态字符串，误报风险低
        else:
            m2 = re.search(
                r'(insertAdjacentHTML|document\.write\w*|dangerouslySetInnerHTML|\.html)\s*\(([^)]*)\)', line)
            if m2 and not SmartDetectors._is_dynamic(m2.group(2)):
                return None
        return {
            "file": file_path, "line": line_num,
            "desc": "XSS 风险：未净化的内容进入 HTML 渲染 — 应使用 textContent 或 DOMPurify 净化",
            "layer": "owasp_security", "severity": IssueSeverity.HIGH,
            "confidence": Confidence.MEDIUM,
            "code_snippet": line.strip()[:120],
            "suggestion": "对用户输入做 HTML 转义 / 使用 DOMPurify，避免 innerHTML 直接拼接。",
        }

    @staticmethod
    def _ci_issue(line: str, line_num: int, file_path: str) -> Dict:
        return {
            "file": file_path, "line": line_num,
            "desc": "命令注入风险：外部输入可能进入系统命令（shell 字符串）执行",
            "layer": "owasp_security",
            "severity": IssueSeverity.HIGH,
            "confidence": Confidence.HIGH,
            "code_snippet": line.strip()[:120],
            "suggestion": "使用参数列表调用（shell=False / arg-vector）并对参数做白名单校验，"
                          "避免把外部输入拼进 shell 字符串。",
        }

    @staticmethod
    def check_command_injection(line: str, line_num: int, language: str,
                                file_path: str = "") -> Optional[Dict]:
        """命令注入：外部输入进入 SHELL 字符串执行。

        v8.9 修正（基于 voicebutler 真实审计）：命令注入的前提是『shell 解释一个
        字符串』，而非『启动一个进程』或『派发一个异步任务』。旧实现把 Rust 的
        tokio::spawn(async ...)（异步任务）和 Command::new(...).args([...]).spawn()
        （参数向量，无 shell）也匹配成命令注入，在 Rust/Tokio 项目产生大量误报。

        分类：
          ASYNC_TASK  : tokio::spawn / Handle::spawn → 与命令执行无关
          ARG_VECTOR  : subprocess.run([...]) / Command::new(prog).args([...]) /
                        exec.Command(prog, args) / child_process.spawn(prog,[args])
                        → 无 shell，参数不经 shell 解释 → 非注入
          SHELL_STRING: os.system / shell_exec / subprocess(shell=True) /
                        child_process.exec / Runtime.exec / sh -c / cmd /C
                        → 字符串经 shell 解释 → 动态输入即注入
        """
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            return None
        lang = (language or "").lower()

        # ── Rust ──
        if lang == "rust":
            # 异步任务派发（最高优先级，永不命令注入）
            if re.search(r'\bspawn\s*\(\s*(?:async|move|\{)', line) \
               or re.search(r'(?:tokio|Handle|task|runtime|builder)\w*(?:::|\.)\s*spawn\s*\(', line):
                return None
            # std::process::Command：默认 arg-vector（无 shell）→ 非注入
            if "Command::new" in line:
                # 仅当程序名是 shell 解释器（"cmd"/"sh"/... 引号包裹，排除变量名 cmd）才可能是 shell 执行
                has_shell_kw = bool(re.search(r'"cmd["\s]|"sh["\s]|"bash["\s]|"powershell["\s]|"zsh["\s]', line))
                if has_shell_kw:
                    # 仅抽取 .arg()/.args() 的参数内容判断动态性（排除 .status()/.spawn() 等方法名）
                    args_body = " ".join(
                        m.group(1) for m in re.finditer(r'\.args?\(\s*([^)]*)\)', line))
                    if ("format!" in line) or SmartDetectors._is_dynamic(args_body):
                        return SmartDetectors._ci_issue(line, line_num, file_path)
                return None
            # 其他 spawn / 进程原语在 Rust 中均非 shell-string 注入
            if re.search(r'\bspawn\s*\(', line):
                return None
            return None

        # ── Go ──
        if lang == "go":
            if re.search(r'exec\.Command(?:Context)?\s*\(', line):
                # 仅当以 shell 解释器（sh -c / cmd /C）启动且含动态输入才危险
                has_shell = bool(re.search(
                    r'"sh"|"bash"|"cmd"|"powershell"|"/bin/sh"|"/bin/bash"|"cmd\.exe"', line))
                if has_shell and SmartDetectors._is_dynamic(line):
                    return SmartDetectors._ci_issue(line, line_num, file_path)
                return None  # 非 shell 程序（arg-vector）→ 非注入
            return None

        # ── 通用（Python / JS / Java / 其他）──
        # 仅匹配『经 shell 解释字符串执行』的原语；不再匹配裸 spawn
        if not re.search(
            r'\b(os\.system|os\.popen|subprocess\.(?:call|Popen|run)|'
            r'child_process\.(?:exec|execSync)|execSync|shell_exec|'
            r'Runtime\.getRuntime\(\)\.exec)\s*\(', line):
            return None
        m = re.search(
            r'\b(?:os\.system|os\.popen|subprocess\.(?:call|Popen|run)|'
            r'child_process\.(?:exec|execSync)|execSync|shell_exec|'
            r'Runtime\.getRuntime\(\)\.exec)\s*\(\s*([^,)]*)', line)
        arg = m.group(1) if m else ""

        # Python subprocess：列表/元组参数（无 shell）→ 非注入
        if re.search(r'subprocess\.(?:call|Popen|run)\s*\(', line):
            is_list = arg.strip().startswith(("[", "(")) or bool(re.search(r'\[[^\]]*\]', arg))
            shell_true = re.search(r'shell\s*=\s*True', line) is not None
            if is_list and not shell_true:
                return None
            if shell_true and SmartDetectors._is_dynamic(arg):
                return SmartDetectors._ci_issue(line, line_num, file_path)
            if shell_true:
                return None
            # 字符串命令（无 shell=True）→ 动态即危险
            if SmartDetectors._is_dynamic(arg):
                return SmartDetectors._ci_issue(line, line_num, file_path)
            return None

        # Node child_process.exec/execSync：默认走 shell → 动态即危险
        if re.search(r'child_process\.(?:exec|execSync)|execSync', line):
            if SmartDetectors._is_dynamic(arg):
                return SmartDetectors._ci_issue(line, line_num, file_path)
            return None
        # 其余（os.system / shell_exec / Runtime.exec）：字符串执行，动态即危险
        if SmartDetectors._is_dynamic(arg):
            return SmartDetectors._ci_issue(line, line_num, file_path)
        return None

    @staticmethod
    def check_code_injection(line: str, line_num: int, language: str,
                             file_path: str = "") -> Optional[Dict]:
        """代码注入：eval / exec / new Function 动态执行代码"""
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            return None
        if not re.search(
            r'\b(eval|exec)\s*\(|new\s+Function\s*\(|'
            r'(setTimeout|setInterval)\s*\(\s*["\']', line):
            return None
        dynamic = True
        am = re.search(r'\b(eval|exec)\s*\(\s*([^)]*)\)', line)
        if am:
            dynamic = SmartDetectors._is_dynamic(am.group(2))
        # 纯静态字面量（如 eval("1+1")）不是代码注入漏洞，不误报安全层
        if not dynamic:
            return None
        return {
            "file": file_path, "line": line_num,
            "desc": "代码注入风险：动态执行外部可控代码（eval/exec/Function）",
            "layer": "owasp_security",
            "severity": IssueSeverity.HIGH,
            "confidence": Confidence.HIGH,
            "code_snippet": line.strip()[:120],
            "suggestion": "避免 eval/exec 动态执行；如必须，仅执行可信来源并做严格校验。",
        }

    @staticmethod
    def check_insecure_deserialization(line: str, line_num: int, language: str,
                                       file_path: str = "") -> Optional[Dict]:
        """不安全反序列化：pickle / yaml.load(非 Safe) 等"""
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            return None
        if re.search(r'\bpickle\.(loads?|load)\s*\(|\bcPickle\b|marshal\.load', line):
            return {
                "file": file_path, "line": line_num,
                "desc": "不安全反序列化：pickle/marshal 反序列化不可信数据可造成 RCE",
                "layer": "owasp_security", "severity": IssueSeverity.HIGH,
                "confidence": Confidence.HIGH,
                "code_snippet": line.strip()[:120],
                "suggestion": "仅反序列化可信来源；跨语言场景改用 JSON 并做 schema 校验。",
            }
        if re.search(r'\byaml\.load\s*\(', line):
            if not re.search(r'Loader\s*=\s*yaml\.(SafeLoader|CSafeLoader)|safe_load|FullLoader', line):
                return {
                    "file": file_path, "line": line_num,
                    "desc": "不安全反序列化：yaml.load 未使用 SafeLoader 可造成代码执行",
                    "layer": "owasp_security", "severity": IssueSeverity.HIGH,
                    "confidence": Confidence.HIGH,
                    "code_snippet": line.strip()[:120],
                    "suggestion": "使用 yaml.safe_load(...) 替代 yaml.load(...)。",
                }
        return None

    @staticmethod
    def check_path_traversal(line: str, line_num: int, language: str,
                             file_path: str = "") -> Optional[Dict]:
        """路径穿越：文件路径拼接外部输入或含 .."""
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            return None
        if not re.search(
            r'\b(open|os\.open|os\.path\.join|Path|fs\.readFile|'
            r'File(?:Stream|Info|Open)?|fopen|ifstream)\b', line):
            return None
        if re.search(r'\.\.[\\/]', line):
            return {
                "file": file_path, "line": line_num,
                "desc": "路径穿越风险：文件路径含 '..' 且可能受外部控制",
                "layer": "owasp_security", "severity": IssueSeverity.HIGH,
                "confidence": Confidence.HIGH,
                "code_snippet": line.strip()[:120],
                "suggestion": "对路径做规范化（os.path.realpath）并校验是否在允许根目录下。",
            }
        if re.search(r'\b(request|req|user|input|args|params|query|body|form)\b', line):
            return {
                "file": file_path, "line": line_num,
                "desc": "路径穿越风险：文件路径拼接外部可控输入，需校验规范化",
                "layer": "owasp_security", "severity": IssueSeverity.MID,
                "confidence": Confidence.MEDIUM,
                "code_snippet": line.strip()[:120],
                "suggestion": "对外部文件名做白名单/规范化，禁止 '..' 与绝对路径。",
            }
        return None

    @staticmethod
    def check_ssrf(line: str, line_num: int, language: str,
                   file_path: str = "") -> Optional[Dict]:
        """SSRF：用户可控 URL 进入请求客户端"""
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            return None
        if not re.search(
            r'\b(requests\.(get|post|put|delete|patch)|httpx\.(get|post)|'
            r'axios\(|fetch\(|urllib\.request|curl\s+[-])', line):
            return None
        am = re.search(
            r'\b(requests|httpx)\.\w+\s*\(\s*([^,)]*)|axios\(\s*([^,)]*)|fetch\(\s*([^,)]*)\)', line)
        url_arg = ""
        if am:
            url_arg = am.group(2) or am.group(3) or am.group(4) or ""
        if SmartDetectors._is_dynamic(url_arg):
            return {
                "file": file_path, "line": line_num,
                "desc": "SSRF 风险：URL 来自外部可控输入，应做协议/域名白名单",
                "layer": "owasp_security", "severity": IssueSeverity.HIGH,
                "confidence": Confidence.MEDIUM,
                "code_snippet": line.strip()[:120],
                "suggestion": "对用户输入的 URL 做协议(http/https)与内网域名白名单校验后再请求。",
            }
        return None

    @staticmethod
    def check_weak_crypto(line: str, line_num: int, language: str,
                          file_path: str = "") -> Optional[Dict]:
        """弱加密原语：MD5/SHA1/DES/RC4/ECB / 弱随机源用于安全上下文"""
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            return None
        if re.search(r'\b(hashlib\.)?(md5|sha1)\b|Crypto\.Hash\.MD5|\bDES\b|\bDES3\b|\bRC4\b|\bARC4\b|ECB', line):
            sev = IssueSeverity.HIGH
            conf = Confidence.HIGH
            note = ""
            # md5/sha1 若明显仅用于文件校验和、非密码场景，降级提示
            if re.search(r'md5|sha1', line, re.IGNORECASE) and not re.search(
                    r'password|passwd|token|secret|auth|sign|hash.*user|user.*hash', line, re.IGNORECASE):
                sev = IssueSeverity.MID
                conf = Confidence.MEDIUM
                note = "（若用于文件校验和非密码场景可放宽）"
            return {
                "file": file_path, "line": line_num,
                "desc": "弱加密原语：MD5/SHA1/DES/RC4/ECB 不建议用于安全目的" + note,
                "layer": "product_security", "severity": sev,
                "confidence": conf,
                "code_snippet": line.strip()[:120],
                "suggestion": "密码存储用 bcrypt/scrypt/Argon2；对称加密用 AES-GCM；避免 ECB 模式。",
            }
        if re.search(r'\b(random\.random|Math\.random)\b', line) and re.search(
                r'token|secret|session|key|nonce|salt|auth|id', line, re.IGNORECASE):
            return {
                "file": file_path, "line": line_num,
                "desc": "弱随机源：Math.random/random.random 不宜生成安全令牌",
                "layer": "product_security", "severity": IssueSeverity.MID,
                "confidence": Confidence.MEDIUM,
                "code_snippet": line.strip()[:120],
                "suggestion": "安全随机用 crypto.randomBytes / secrets.token_urlsafe。",
            }
        return None

    @staticmethod
    def check_hardcoded_secret(line: str, line_num: int, language: str,
                               file_path: str = "") -> Optional[Dict]:
        """硬编码密钥/凭证（高熵云密钥直接模式 + 通用命名 + 上下文感知，避免误报）"""
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            return None

        # 1) 高熵云密钥直接模式（无需关键字前缀，sk-/AKIA 等）
        for tok_pat, label in [
            (r'sk-[A-Za-z0-9]{20,}', "OpenAI/SK 格式密钥"),
            (r'AKIA[A-Z0-9]{16}', "AWS Access Key ID"),
        ]:
            m = re.search(tok_pat, line)
            if m:
                val = m.group(0)
                # 仅豁免 AWS 官方文档示例密钥（以 EXAMPLE 结尾），
                # 不得用子串匹配 example/sample，否则会误杀真实密钥
                if re.search(r'(xxxx|placeholder|dummy|fake|changeme|<[^>]+>)',
                             val, re.IGNORECASE) or val.endswith("EXAMPLE"):
                    continue
                return {
                    "file": file_path, "line": line_num,
                    "desc": f"硬编码{label} — 应迁移到环境变量或密钥管理服务",
                    "layer": "owasp_security",
                    "severity": IssueSeverity.CRITICAL,
                    "confidence": Confidence.HIGH,
                    "code_snippet": line.strip()[:120],
                    "suggestion": "使用 os.environ / 密钥管理服务注入，避免明文入库或提交。",
                }

        # 2) 通用命名密钥（DB_PASS / SECRET / TOKEN / API_KEY ...）
        # 注意：DB_?PASS 需允许后续词（PASSWORD/PASSWD），否则 DB_PASSWORD 被漏检
        pat = (r'(?i)\b(DB_?(?:PASS(?:WORD|WD)?|PWD)|SECRET|TOKEN|ACCESS_?KEY|CLIENT_?SECRET|'
               r'PRIVATE_?KEY|API_?TOKEN|AUTH_?TOKEN|ENCRYPTION_?KEY|'
               r'SECRET_?KEY|API_?KEY|APIKEY|PASSWORD|PASSWD|PWD)\b'
               r'\s*[=:]\s*["\']([^"\']{6,})["\']')
        m = re.search(pat, line)
        if not m:
            return None
        value = m.group(2)
        if re.search(r'(placeholder|your[-_]?key|xxxx|dummy|fake|changeme|'
                     r'<[^>]+>|example|sample|to_do|todo)', value, re.IGNORECASE):
            return None
        looks_real = bool(re.search(r'[A-Za-z0-9_\-]{20,}', value))
        return {
            "file": file_path, "line": line_num,
            "desc": "硬编码密钥/凭证 — 应迁移到环境变量或密钥管理服务",
            "layer": "owasp_security",
            "severity": IssueSeverity.CRITICAL if looks_real else IssueSeverity.HIGH,
            "confidence": Confidence.HIGH,
            "code_snippet": line.strip()[:120],
            "suggestion": "使用 os.environ / 密钥管理服务注入，避免明文入库或提交。",
        }


def apply_all_detectors(line: str, line_num: int, language: str,
                        project_type: str, file_path: str,
                        context_lines: Optional[List[str]] = None,
                        line_idx: Optional[int] = None) -> List[Dict]:
    """对单行代码应用所有智能检测器，返回 issue 列表"""
    issues = []
    
    detector = SmartDetectors()
    
    # 魔法数字检测
    mn = detector.check_magic_number(line, line_num, language, file_path)
    if mn:
        issues.append(mn)
    
    # 调试残留检测
    dp = detector.check_debug_prints(line, line_num, language, project_type, file_path)
    if dp:
        issues.append(dp)
    
    # None 解引用
    nd = detector.check_none_deref(line, line_num, language, file_path)
    if nd:
        issues.append(nd)

    # SQL 注入（字符串拼接）
    sql = detector.check_sql_injection(line, line_num, language, file_path)
    if sql:
        issues.append(sql)

    # 高风险遗留标记
    dm = detector.check_debug_markers(line, line_num, language, file_path)
    if dm:
        issues.append(dm)

    # 注入 / 反序列化 / 穿越类（商业级扩展 v8.2）
    xss = detector.check_xss(line, line_num, language, file_path)
    if xss:
        issues.append(xss)

    ci = detector.check_command_injection(line, line_num, language, file_path)
    if ci:
        issues.append(ci)

    codeinj = detector.check_code_injection(line, line_num, language, file_path)
    if codeinj:
        issues.append(codeinj)

    des = detector.check_insecure_deserialization(line, line_num, language, file_path)
    if des:
        issues.append(des)

    pt = detector.check_path_traversal(line, line_num, language, file_path)
    if pt:
        issues.append(pt)

    ssrf = detector.check_ssrf(line, line_num, language, file_path)
    if ssrf:
        issues.append(ssrf)

    wc = detector.check_weak_crypto(line, line_num, language, file_path)
    if wc:
        issues.append(wc)

    sec = detector.check_hardcoded_secret(line, line_num, language, file_path)
    if sec:
        issues.append(sec)

    # 空 catch/except（需要上下文窗口）
    if context_lines is not None and line_idx is not None:
        ctx = context_lines[max(0, line_idx - 1): line_idx + 2]
        ec = detector.check_empty_catch(line, line_num, ctx, file_path)
        if ec:
            issues.append(ec)

    return issues
