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
# 命令注入子类型分类（v8.11：提升标签可操作性）
# 把笼统的「命令注入风险」细分为 RCE / 任意文件读 / 任意文件写删
# ══════════════════════════════════════════════════════

# 文件写 / 删 原语（外部输入进入这些命令 = 任意文件写删）
_FILE_WRITE_PAT = re.compile(
    r'(>>|>\s*\S|tee\s|rm\s|rmdir|del\s|Remove-Item|Move-Item|Set-Content|'
    r'Out-File|Write-File|Write-AllText|WriteAllText|copy\s|cp\s|mkfs|format\s)',
    re.IGNORECASE)

# 文件读 原语（外部输入进入这些命令 = 任意文件读）
_FILE_READ_PAT = re.compile(
    r'(\bcat\s|\btype\s|\bhead\s|\btail\s|\bmore\s|\bnl\s|Get-Content|'
    r'Read-File|ReadAllText|Get-ChildItem|dir\s)',
    re.IGNORECASE)

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

        # v8.13：TSX/JSX 样式噪声豁免。
        # Tailwind 类（gap-1）、framer-motion 偏移（x: 20）、style 对象数值（opacity: 0.5）、
        # className 字符串等不是代码逻辑意义上的魔法数字，过度标记会污染评分。
        # 仅保留显式代码逻辑（比较 / 数组索引 / 返回数值）中的魔法数字。
        if language in ("tsx", "jsx"):
            if re.search(r'</?[A-Za-z][\w.-]*(\s|>|/)|'
                         r'(className|class=|style|tw=|css=|sx=|:className)\b', stripped):
                return None
            if '"' in stripped or "'" in stripped or '`' in stripped:
                return None  # 引号内数字（Tailwind 类 / 模板字符串）一律跳过
            if not re.search(r'[=<>!]=\s*\d|[<>]\s*\d|\[\d+\]|return\s+\d|'
                             r'(?<![\w.])for\s*\([^)]*\d', stripped):
                return None

        # v8.11：含 IPv4 字面量的行（URL/地址/连接串）整体非魔法数字上下文
        if re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line):
            return None

        # v8.11：URL / 连接串中的 host:port 端口（localhost / 127.0.0.1 / 域名:端口）
        # 预提取端口集合，避免把 11434 / 5432 等服务端口误判为魔法数字
        url_ports = {
            int(m) for m in re.findall(
                r'(?:://[^:\s]+|localhost|127\.0\.0\.1|::1|[\w.-]+\.[A-Za-z]{2,})\s*:\s*(\d{2,5})', line)
        }

        # 找到所有裸数字
        numbers = re.finditer(r'(?<!\w)(\d{2,})(?!\w)', line)
        for match in numbers:
            num_str = match.group(1)
            num = int(num_str)

            # 跳过 0, 1, -1
            if num <= 1:
                continue

            # 跳过标准 / 常见服务端口（80, 443, 3000, 5000, 8080, 8443, 9876,
            # 3001, 4200, 8000, 以及 11434 Ollama, 5432 Postgres, 6379 Redis,
            # 3306 MySQL, 27017 Mongo, 1433 MSSQL, 11211 Memcached, 9200 ES,
            # 9042 Cassandra, 5984 CouchDB, 5672 RabbitMQ, 7000, 5601 Kibana,
            # 9090/9092 Prometheus, 8500 Consul …）
            if num in (80, 443, 3000, 5000, 8080, 8443, 9876, 3001, 4200, 8000,
                       11434, 5432, 6379, 3306, 27017, 1433, 11211, 9200, 9042,
                       5984, 5672, 7000, 5601, 9090, 9092, 8500):
                continue

            # 跳过 URL / 连接串中的端口（如 http://localhost:11434、postgres://db:5432）
            if num in url_ports:
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
    def check_hardcoded_port(line: str, line_num: int, language: str,
                             file_path: str = "") -> Optional[Dict]:
        """
        硬编码端口检测（v8.11+ 商业级增强）。

        背景：端口号原先被「魔法数字」检测器误标为噪音（待改进 #4），
        已在 check_magic_number 中豁免。但用户明确要求「增强端口硬编码问题的检测」，
        因此这里作为**独立、可审查**的发现项，把代码中写死的端口号报告为
        配置外部化建议（maintainability / config-hardening），不触发门禁。

        检测目标（高价值、低误报）：
          1) 端口变量赋值：self.port = 8080 / PORT = 3000 / serverPort = 5432
          2) 监听/绑定调用：.listen(3000) / server.bind(..., 8080) /
             TcpListener::bind("0.0.0.0:8080") / net.Listen("tcp", ":8080")
        跳过：
          - URL 连接串中的端口（http://localhost:11434 等，已由魔法数字豁免，避免重复+噪音）
          - 英文词误判（important/report/transport 含 "port" 但非端口语义 → 靠命名约束排除）
        """
        stripped = line.strip()
        # URL 连接串中的端口不在此报告（避免重复 + 噪音）
        if "://" in stripped:
            return None

        port_val = None
        kind = None

        # 1) 端口变量赋值（精确命名，避免 important/report 等英文词误判）
        #    - 精确 token：port / PORT
        #    - 点访问：self.port / config.port
        #    - 驼峰：serverPort / httpPort（要求大写 P，排除 important 等小写 p 英文词）
        m = re.search(
            r'(?:\b\w+\.)?(?:\b(?i:port)\b|(?i:_port)\b|[A-Za-z_]*Port)\s*[=:]\s*(\d{2,5})',
            stripped)
        if m:
            port_val = int(m.group(1))
            kind = "变量赋值"
        else:
            # 2) 监听/绑定调用中的端口参数（限定调用括号内，避免 run/Start 等泛化词误伤）
            m2 = re.search(
                r'(?i)(listen|bind|net\.Listen|TcpListener|Server|serve|'
                r'HttpListener|UdpSocket|createServer|app\.run)\s*\([^)]{0,40}?(\d{2,5})',
                stripped)
            if m2:
                port_val = int(m2.group(2))
                kind = "监听/绑定"

        if port_val is None:
            return None
        # 端口合法性（1-65535）
        if not (1 <= port_val <= 65535):
            return None
        # 排除纯年份/大计数误判（>9999 仅当是已知服务端口才视为端口）
        if port_val > 9999 and port_val not in (
                11434, 5432, 6379, 3306, 27017, 1433, 11211, 9200, 9042):
            return None

        return {
            "file": file_path,
            "line": line_num,
            "desc": f"硬编码端口: {port_val}（{kind}，建议外部化为配置/环境变量）",
            "layer": "business_logic",
            "severity": IssueSeverity.LOW,
            "confidence": Confidence.MEDIUM,
            "code_snippet": stripped[:120],
            "subtype": "hardcoded_port",
            "suggestion": (
                f"端口 {port_val} 直接写死在代码中，不利于多环境部署与运维。"
                "建议改为从配置文件或环境变量读取（如 PORT / APP_PORT），"
                "并在 README 中注明默认值与可取值范围。"
            ),
        }

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
    def _split_args(s: str) -> List[str]:
        """按顶级逗号切分参数（忽略括号内的逗号）"""
        parts, depth, cur = [], 0, ""
        for ch in s:
            if ch in "([{":
                depth += 1
                cur += ch
            elif ch in ")]}":
                depth -= 1
                cur += ch
            elif ch == "," and depth == 0:
                parts.append(cur)
                cur = ""
            else:
                cur += ch
        if cur.strip():
            parts.append(cur)
        return parts

    @staticmethod
    def _is_literal_or_const(arg: str) -> bool:
        """参数是否为字面量或安全常量（非运行期外部攻击输入）

        写死路径 / UPPER_CASE 常量 / path::to::CONST / env::temp_dir() 等
        视为静态，不触发污点判定（修复 H7 误报）。
        """
        a = arg.strip()
        if not a:
            return True
        if a[0] in ('"', "'", "`"):
            return True
        if re.match(r'^-?\d', a):
            return True
        # 常量：UPPER_CASE 或 path::to::CONST
        if re.match(r'^[A-Z][A-Z0-9_]*$', a):
            return True
        if '::' in a and re.search(r'[A-Z]', a):
            return True
        # 已知安全构造（配置/路径来源，非直接请求输入）
        if re.match(r'^(env|std|std::env|Path|std::path|std::fs)\b', a):
            return True
        return False

    @staticmethod
    def _rust_format_tainted(expr: str) -> bool:
        """Rust format! 宏是否含外部可控插值。

        v8.11 修复 H7：仅当格式字符串本身是变量，或插值参数存在运行期外部
        输入（小写标识符/函数返回值）时判为污点；写死路径/常量插值
        （如 format!("{}/temp", BASE_DIR)）视为静态，不误报注入。
        """
        for fm in re.finditer(r'format!\s*\(\s*([^,]*)\s*(?:,\s*([^)]*))?\s*\)', expr, re.DOTALL):
            fmt_str = (fm.group(1) or "").strip()
            args_part = (fm.group(2) or "").strip()
            # 格式字符串本身必须是字面量（以引号开头），否则视为动态构建 → 污点
            if not fmt_str.startswith(('"', "'", '`')):
                return True
            if not args_part:
                continue  # format!("固定串") 无插值 → 静态
            for arg in SmartDetectors._split_args(args_part):
                if not SmartDetectors._is_literal_or_const(arg):
                    return True  # 存在运行期变量 → 污点
        return False

    @staticmethod
    def _classify_ci_subtype(line: str, arg_text: str = "") -> str:
        """命令注入子类型细分：RCE / 任意文件读 / 任意文件写删"""
        cmd = (line + " " + (arg_text or ""))
        if _FILE_WRITE_PAT.search(cmd):
            return "file_write"
        if _FILE_READ_PAT.search(cmd):
            return "file_read"
        return "rce"

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
    def _ci_issue(line: str, line_num: int, file_path: str, arg_text: str = "") -> Dict:
        """命令注入问题构造（v8.11：按真实危害细分 RCE / 任意文件读 / 任意文件写删）"""
        subtype = SmartDetectors._classify_ci_subtype(line, arg_text)
        labels = {
            "rce": ("RCE 风险：外部输入经 shell 执行任意系统命令",
                    "使用参数列表调用（shell=False / arg-vector）并对参数做白名单校验，"
                    "避免把外部输入拼进 shell 字符串。"),
            "file_write": ("任意文件写入/删除风险：外部输入进入 shell 文件写/删命令",
                    "禁止把外部输入拼入 rm/del/>/Set-Content 等文件写删原语；"
                    "改用受控文件 API 并校验目标路径位于允许目录内。"),
            "file_read": ("任意文件读取风险：外部输入进入 shell 文件读命令",
                    "禁止把外部输入拼入 cat/type/Get-Content 等文件读原语；"
                    "改用受控文件读取 API 并做路径白名单校验。"),
        }
        desc, suggestion = labels.get(subtype, labels["rce"])
        return {
            "file": file_path, "line": line_num,
            "desc": desc,
            "subtype": "command_injection:" + subtype,
            "layer": "owasp_security",
            "severity": IssueSeverity.HIGH,
            "confidence": Confidence.HIGH,
            "code_snippet": line.strip()[:120],
            "suggestion": suggestion,
        }

    @staticmethod
    def _ci_resolve_severity(line: str, line_num: int, file_path: str,
                              arg_text: str, taint_ctx: object) -> Dict:
        """命令注入严重度裁决（v8.13 污点感知）。

        - taint_ctx 为 None      → 保持原 HIGH（兼容旧调用与单测）
        - 参数解析为 tainted      → 真实外部输入，保持 HIGH
        - 参数解析为 clean/guarded → 本地/已守卫值，降级为 LOW 备注（不触发 BLOCK，可审计）
        返回 dict（始终非空）。
        """
        if taint_ctx is None:
            return SmartDetectors._ci_issue(line, line_num, file_path, arg_text=arg_text)
        state = taint_ctx.resolve(arg_text or line)
        if state == "tainted":
            return SmartDetectors._ci_issue(line, line_num, file_path, arg_text=arg_text)
        # 参数传播：函数入参（未经验证的外部输入）流入 shell → 视为真实注入 HIGH
        if taint_ctx.references_param(arg_text or line):
            return SmartDetectors._ci_issue(line, line_num, file_path, arg_text=arg_text)
        note = ("污点分析：shell 参数为本地/常量值，非外部可控输入"
                if state == "clean" else
                "污点分析：参数经守卫/净化函数处理，非直接注入")
        return {
            "file": file_path, "line": line_num,
            "desc": "命令注入（本地/已守卫，降级）：shell 执行参数为本地或净化值，非外部注入",
            "subtype": "command_injection:local_or_guarded",
            "layer": "owasp_security",
            "severity": IssueSeverity.LOW,
            "confidence": Confidence.LOW,
            "taint_state": state,
            "code_snippet": line.strip()[:120],
            "suggestion": "确认该 shell 调用的参数确实不含外部可控输入；本地路径/常量安全。",
        }

    @staticmethod
    def check_command_injection(line: str, line_num: int, language: str,
                                file_path: str = "",
                                taint_ctx: object = None) -> Optional[Dict]:
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
                    # v8.11：先对完整行剥离 format! 宏（行是完整的，可正确移除内嵌 format!），
                    # 再抽取 .args()/.arg() 参数内容，避免 .args() 内嵌 format! 导致的括号截断，
                    # 以及 'format' 标识符被通用 _is_dynamic 误判为动态（修复 H7 误报，无漏报）。
                    line_no_fmt = re.sub(r'format!\s*\([^)]*\)', '', line)
                    args_body = " ".join(
                        m.group(1) for m in re.finditer(r'\.args?\(\s*([^)]*)\)', line_no_fmt))
                    # 污点判定：format! 仅当插值含外部可控输入才危险（写死路径/常量不误报）；
                    # 其余动态信号（&user_input / 变量拼接 / 函数返回值）仍须判为危险。
                    if (SmartDetectors._rust_format_tainted(line)
                            or SmartDetectors._is_dynamic(args_body)):
                        return SmartDetectors._ci_resolve_severity(
                            line, line_num, file_path, args_body, taint_ctx)
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
                    return SmartDetectors._ci_resolve_severity(
                        line, line_num, file_path, line, taint_ctx)
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
                return SmartDetectors._ci_resolve_severity(
                    line, line_num, file_path, arg, taint_ctx)
            if shell_true:
                return None
            # 字符串命令（无 shell=True）→ 动态即危险
            if SmartDetectors._is_dynamic(arg):
                return SmartDetectors._ci_resolve_severity(
                    line, line_num, file_path, arg, taint_ctx)
            return None

        # Node child_process.exec/execSync：默认走 shell → 动态即危险
        if re.search(r'child_process\.(?:exec|execSync)|execSync', line):
            if SmartDetectors._is_dynamic(arg):
                return SmartDetectors._ci_resolve_severity(
                    line, line_num, file_path, arg, taint_ctx)
            return None
        # 其余（os.system / shell_exec / Runtime.exec）：字符串执行，动态即危险
        if SmartDetectors._is_dynamic(arg):
            return SmartDetectors._ci_resolve_severity(
                line, line_num, file_path, arg, taint_ctx)
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
                             file_path: str = "",
                             taint_ctx: object = None) -> Optional[Dict]:
        """路径穿越：文件路径拼接外部输入或含 .."""
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            return None
        if not re.search(
            r'\b(open|os\.open|os\.path\.join|Path|fs\.readFile|'
            r'File(?:Stream|Info|Open)?|fopen|ifstream)\b', line):
            return None
        # v8.13：污点感知降级（消除 voicebutler 类「守卫在前」误报）
        if taint_ctx is not None:
            state = taint_ctx.resolve(line)
            if state == "guarded":
                return {
                    "file": file_path, "line": line_num,
                    "desc": "路径操作（已守卫，降级）：路径经 pathAllowed/safeArg 等校验，非直接穿越",
                    "subtype": "path_traversal:guarded",
                    "layer": "owasp_security", "severity": IssueSeverity.LOW,
                    "confidence": Confidence.MEDIUM, "taint_state": "guarded",
                    "code_snippet": line.strip()[:120],
                    "suggestion": "路径已受守卫函数校验；建议守卫同时做 os.path.realpath 规范化以抵御符号链接绕过。",
                }
            if state == "clean":
                # 本地路径操作，无外部可控输入 → 非漏洞
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
            # 规则4（反误报协议）：localhost / 127.0.0.1 / ::1 目标是本地服务，
            # 不构成网络漏洞 → 标记 scope=local，门禁降级为需人工复核（CONDITIONAL）
            is_local = bool(re.search(
                r'[\'"`]https?://(127\.0\.0\.1|localhost|::1)|'
                r'\b(?:127\.0\.0\.1|localhost|::1)\b', line))
            scope = "local" if is_local else "network"
            local_note = ("（目标为 localhost/127.0.0.1，仅本地服务暴露，"
                          "按规则4降级为需人工复核）") if is_local else ""
            return {
                "file": file_path, "line": line_num,
                "desc": "SSRF 风险：URL 来自外部可控输入，应做协议/域名白名单",
                "layer": "owasp_security", "severity": IssueSeverity.HIGH,
                "confidence": Confidence.MEDIUM,
                "scope": scope,
                "code_snippet": line.strip()[:120],
                "suggestion": "对用户输入的 URL 做协议(http/https)与内网域名白名单校验后再请求。" + local_note,
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


# ─────────────────────────────────────────────────────────────
# v8.13：同文件内污点追踪（消除「守卫在前 / 外部输入不进 sink」类误报）
# ─────────────────────────────────────────────────────────────
# resolve() 中过滤的语言关键字噪声（非变量语义）
_TAINT_KEYWORDS = {
    "if", "for", "while", "return", "func", "fn", "def", "let", "var", "const",
    "self", "this", "new", "match", "else", "then", "do", "none", "true", "false",
    "await", "async", "with", "in", "of", "and", "or", "not", "nil", "null",
    "some", "err", "ok", "move",
}
# 命名即含外部语义的变量（精确匹配集 + 安全子串集）
_TAINT_NAME_EXACT = {
    "req", "request", "params", "param", "query", "body", "form", "input",
    "payload", "user", "client", "peer", "ctx", "context", "args", "argv",
}
_TAINT_NAME_SUBSTR = ("request", "payload", "user_input", "reqbody", "reqquery",
                      "formdata", "form_body")


class TaintContext:
    """同文件内污点传播上下文。

    让 sink 检测器能区分一条调用参数的污点状态：
      - tainted  : 变量源于外部输入（request/params/input/user...）或外部语义命名
      - guarded  : 变量经守卫/净化函数处理（pathAllowed/safeArg/escape...）
      - clean    : 变量源于字面量/常量/本地构造（默认，未识别为上述二者即视为 clean）
    resolve(expr) 用于命令注入 / 路径穿越等 sink 的降级判定，
    从而消除 voicebutler 这类「守卫在前 / 外部输入不进 shell」的误报 BLOCK。
    """

    SOURCE_PAT = re.compile(
        r'(req\b|request\b|params\b|query\b|body\b|payload\b|user\b|client\b|peer\b|'
        r'context\b|socket\b|http\b|'
        r'\.Form\b|\.Input\b|Getenv|getenv|'
        r'std::env(?!::temp_dir|::temp_path|::TempDir)|'
        r'env::(?!temp_dir|temp_path|TempDir)|'
        r'(?<!\.)\bargs\b|(?<!\.)\bargv\b|(?<!\.)\bform\b|(?<!\.)\binput\b)')
    GUARD_FNS = re.compile(
        r'\b(pathAllowed|safeArg|isAllowed|allowList|allowlist|whitelist|'
        r'validate|sanitize|escape|escape_xml|escapeHtml|html_escape|'
        r'urlencode|encodeURIComponent|sanitize_|validate_|verify|'
        r'authorized|checkAuth|assertValid|realpath|filepath_clean)\s*\(')
    ASSIGN_PAT = re.compile(
        r'^\s*(?:let|var|const|private|public|protected|final|static|mut|in|'
        r'with)?\s*(?:mut\s+)?([A-Za-z_]\w*)'
        r'\s*(?::\s*[A-Za-z_][\w\[\],.<>*\s]*?)?\s*(?:=>|:=|=)\s*(.*)$')

    def __init__(self):
        self.tainted = set()
        self.guarded = set()
        self.clean = set()
        self.params = set()  # 全部函数入参（未经验证的外部输入来源）
        self.guard_notes = []

    @staticmethod
    def build(lines, language):
        ctx = TaintContext()
        lang = (language or "").lower()
        for line in lines:
            s = line.strip()
            if not s or s.startswith("//") or s.startswith("#") \
               or s.startswith("/*") or s.startswith("*"):
                continue
            # 1) 守卫调用 → 参数标 guarded
            for gm in TaintContext.GUARD_FNS.finditer(line):
                rest = line[gm.end() - 1:]
                am = re.match(r'\(\s*([A-Za-z_]\w*)', rest)
                if am:
                    var = am.group(1)
                    if var not in ("if", "for", "while", "switch", "func",
                                   "fn", "def", "match", "return"):
                        ctx.guarded.add(var)
                        ctx.guard_notes.append((var, gm.group(0).split("(")[0]))
            # 2) 赋值 → 评估 RHS 污点
            m = TaintContext.ASSIGN_PAT.match(s)
            if m:
                lhs = m.group(1)
                rhs = m.group(2)
                if not rhs:
                    continue
                if TaintContext.SOURCE_PAT.search(rhs):
                    ctx.tainted.add(lhs)
                elif (rhs[0] in ('"', "'", "`")
                       or re.match(r'^-?\d', rhs)
                       or re.match(r'^[A-Z][A-Z0-9_]*$', rhs)
                       or ('::' in rhs and re.search(r'[A-Z]', rhs))
                       or re.search(r'(temp_dir|env::|std::env|std::path|std::fs|'
                                    r'Path::|filepath\.|os\.TempDir|get_temp|cache_dir)', rhs)):
                    ctx.clean.add(lhs)
                else:
                    # 参数传播：RHS 引用了任意函数入参 → 该局部变量同样视为外部可控
                    rhs_ids = set(re.findall(r'[A-Za-z_]\w*', rhs))
                    rhs_ids = {r for r in rhs_ids
                               if r.lower() not in _TAINT_KEYWORDS}
                    if rhs_ids and any(r in ctx.params for r in rhs_ids):
                        ctx.tainted.add(lhs)
            # 3) 函数签名参数 → 外部语义参数标 tainted
            TaintContext._seed_params(s, ctx, lang)
        return ctx

    @staticmethod
    def _seed_params(s, ctx, lang):
        sig = None
        m = re.search(r'\b(?:def|fn|func)\s+\w*\s*\(([^)]*)\)', s)
        if m:
            sig = m.group(1)
        else:
            m2 = re.search(r'\(([^)]*)\)\s*=>', s)
            if m2:
                sig = m2.group(1)
        if not sig:
            return
        # 仅 JS/TS 的箭头函数 (a, b) => {} 才从 => 行抽取参数；
        # Rust/Go 的 match 分支（Some(v) =>）与 const 绑定用 => 但那是局部绑定，
        # 若当作函数参数会误把本地变量标为外部可控 → 命令注入误报。
        if "=>" in s and lang not in (
                "js", "jsx", "ts", "tsx", "javascript", "typescript",
                "mjs", "cjs", "node"):
            return
        for part in sig.split(","):
            part = part.strip()
            if not part or part in ("self", "cls", "this"):
                continue
            name = re.split(r'[\s:(\*]', part)[0].strip()
            if not name or not name[0].isalpha():
                continue
            # 所有函数入参均视为未经验证的外部输入来源（命令注入高危面）
            ctx.params.add(name)
            if name in _TAINT_NAME_EXACT or any(t in name for t in _TAINT_NAME_SUBSTR):
                ctx.tainted.add(name)
            if re.search(r'\*\w*\.?[Rr]equest', part):
                ctx.tainted.add(name)

    def resolve(self, expr):
        if not expr:
            return "clean"
        ids = set(re.findall(r'[A-Za-z_]\w*', expr))
        ids = {i for i in ids if i.lower() not in _TAINT_KEYWORDS}
        if any(i in self.guarded for i in ids):
            return "guarded"
        if any(i in self.tainted for i in ids):
            return "tainted"
        # 外部语义命名：args/argv 需排除 .args()/.argv() 方法调用误判，
        # 仅裸标识符（如函数参数 args）视为污点来源；与 SOURCE_PAT 保持一致。
        if any(i in _TAINT_NAME_EXACT for i in ids if i not in ("args", "argv")):
            return "tainted"
        if re.search(r'(?<!\.)\bargs\b|(?<!\.)\bargv\b', expr):
            return "tainted"
        if any(any(t in i for t in _TAINT_NAME_SUBSTR) for i in ids):
            return "tainted"
        return "clean"

    def references_param(self, expr):
        """表达式是否引用了任意函数入参（未经验证的外部输入来源）。"""
        if not expr:
            return False
        ids = set(re.findall(r'[A-Za-z_]\w*', expr))
        ids = {i for i in ids if i.lower() not in _TAINT_KEYWORDS}
        return any(i in self.params for i in ids)


def apply_all_detectors(line: str, line_num: int, language: str,
                        project_type: str, file_path: str,
                        context_lines: Optional[List[str]] = None,
                        line_idx: Optional[int] = None,
                        taint_ctx: object = None) -> List[Dict]:
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

    ci = detector.check_command_injection(line, line_num, language, file_path,
                                           taint_ctx=taint_ctx)
    if ci:
        issues.append(ci)

    codeinj = detector.check_code_injection(line, line_num, language, file_path)
    if codeinj:
        issues.append(codeinj)

    des = detector.check_insecure_deserialization(line, line_num, language, file_path)
    if des:
        issues.append(des)

    pt = detector.check_path_traversal(line, line_num, language, file_path,
                                        taint_ctx=taint_ctx)
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

    # 硬编码端口检测（v8.11+：配置外部化建议，独立可审查项，不触发门禁）
    hp = detector.check_hardcoded_port(line, line_num, language, file_path)
    if hp:
        issues.append(hp)

    # 空 catch/except（需要上下文窗口）
    if context_lines is not None and line_idx is not None:
        ctx = context_lines[max(0, line_idx - 1): line_idx + 2]
        ec = detector.check_empty_catch(line, line_num, ctx, file_path)
        if ec:
            issues.append(ec)

    return issues
