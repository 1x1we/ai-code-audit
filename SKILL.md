---
name: ai-code-audit
display_name: AI代码商业级发布门禁审查
description: v8.10 商业级代码审查技能（为 LLM 智能体设计的确定性门禁 + 审计化协同协议，逻辑漏洞全闭环，误报+漏报双向验证）。多生态包验证 + 上下文感知 + Python AST 逻辑分析 + 依赖漏洞(SCA)审计 + 置信度评分 + 三管过滤 + 反误报协议 + 发布门禁否决 + 智能体三态协同(审计化:推理链/复现契约/不可复现有兜底/陈旧裁决作废/SUPPLEMENT 不单方 BLOCK) + 8 类注入/反序列化/穿越漏洞检测 + 密钥检测完整收口 + 白名单 + 模块级审查 + 语言感知命令注入(根治 Rust/Tokio 误报) + f-string/JS模板插值漏报闭环。
---

规则版本: v8.10 | 脚本版本: v8.10 | 引擎: PackageResolver + SmartDetectors + ASTLogicAnalyzer + DependencyAudit + ConfidenceEngine + ReleaseArtifacts + Whitelist + AgentProtocol(审计化三态协同 v2.0, 逻辑漏洞闭环)

# AI代码商业级发布门禁 v8.0

智能发现 → 包生态验证 → 上下文感知检测 → 置信度评分 → 三管过滤 → 发布报告

**定位**：产品发布前最后一道质量门禁。脚本初筛 + 智能去噪 + 人工确认 → 商业级可发布。

> **本质：这是一个「给智能体/大模型使用的技能(skill)」**。
> 它的正确用法不是人类肉眼读报告，而是**由 LLM 审查智能体驱动**：
> ① 智能体调用本 skill 做确定性初筛（毫秒级、零 LLM 调用、0 漏报已知模式）→ 产出结构化 `report.json`；
> ② 智能体消费 `report.json` 的 `issues[]` / `release_artifacts` / `release_gate`，对每条做语义确认（CONFIRM/REJECT/SUPPLEMENT）；
> ③ 智能体把三态裁决回灌 `--apply-verdicts`，本 skill 重新评分并兜底裁决。
>
> **双层职责边界（商业级审计的关键）**：
> - **确定性层（脚本，100% 可复现）**：负责「已知、模式化缺陷」的兜底。它输出的 `release_gate.decision` 是权威硬信号，CI 硬卡直接消费它即可，**不依赖任何 LLM**。
> - **LLM 层（协同，天然非确定性）**：负责「语义确认 + 补抓规则外缺陷（越权/竞态/业务逻辑）」。它的产出**不可复现**，因此本 skill 对其施加三重约束（v8.7）：
>   1. **不可复现有兜底**：对致命类（critical/high 且属致命层，或遗留文件 critical/high）的 REJECT，**必须**附 `human_override + override_reason` 人工复核理由，否则该发现保留为 `challenged` 且门禁仍 BLOCK——非复现的 LLM 判断**无法静默放行真实漏洞**。
>   2. **可审计推理链**：每条 LLM 裁决**必须**提供 `reasoning`（根因）+ `evidence` + `confidence`；缺推理的裁决判为 `invalid`，保守保留并标 `needs_human_review`。最终报告每条发现都带 `source` 与 `llm_reasoning`，可逐条质疑。
>   3. **复现契约**：任务清单携带 `issues_hash`（确定性报告指纹）+ `determinism_contract`；智能体回灌 `determinism_manifest`（model/temperature/seed/issues_hash）后协议可校验复现性。LLM 层产出一律标 `requires_human_validation`，由人类做最终拍板。
> - **诚实边界**：「发现你不知道的问题」价值来自 SUPPLEMENT（标 `llm_supplemented` + 需人工复核），而非让 LLM 替你推翻确定性结论。脚本兜底的只是已知模式化缺陷；未知语义缺陷的判定权始终在人类。

## 快速开始

```bash
# 1. 运行脚本初筛（标准模式，自动去噪）
python scripts/code_audit_runner.py <项目目录> -o report.json --output-md report.md

# 2. 自测试（验证环境正确，50 项）
python scripts/code_audit_runner.py --self-test

# 3. 单元测试（9 套核心能力，可运行验证）
cd tests && python test_core.py

# 4. 严格模式（全部发现，不过滤）
python scripts/code_audit_runner.py <项目目录> --strict -o report.json
```

---

## v8.0 核心升级（vs v7.2）

v8.0 是一次架构级重建，聚焦三大核心能力：

### 1. 包生态验证引擎 (PackageResolver)
- **Python stdlib**：完整 3.0-3.13 标准库列表（150+ 模块），zlib/ctypes/lzma 等零误报
- **JS/TS**：扫描 node_modules + 解析 package.json + React/Vue/tailwind 等框架名自动识别
- **C#**：解析 .csproj 的 PackageReference + .NET BCL 完整命名空间 + 项目内部命名空间白名单
- **Go/Rust**：go.mod/Cargo.toml 模块解析
- **项目内部符号**：自动提取 namespace / 包名 → 不再误报为自己的幻觉

### 2. 上下文感知检测器 (SmartDetectors)
- **魔法数字**：30+ 安全上下文自动跳过（Color.FromArgb/StringBuilder/Stream API/端口号/时间常数）
- **调试残留**：按项目类型区分 → CLI 工具 print() 不标记，API/库标记
- **空 catch**：检查注释说明 + 错误处理逻辑（支持 `except: pass` / `except Exception: pass` / `catch {}`）
- **资源泄漏**：open() 无 with/using 检测
- **SQL 注入**：逐行检测字符串拼接（f-string / `+` / `.format` / `%` 格式化），参数化占位符（`?`/`%s`/`:name`）自动排除
- **高风险遗留标记**：注释中的 `TODO/FIXME/XXX/HACK` 涉及密钥/安全/绕过关键词

### 3. 发布前遗留/调试文件检测 (ReleaseArtifacts) — v8.1 新增
作为发布门禁的独立审查维度，扫描提交到仓库中**不应发布**的文件：
- **私钥/密钥文件**（`.pem`/`.key`/`.p12`/`.pfx`/`.jks`）→ 产品安全 critical/high
- **`.env` / `.env.local`**（含密钥行时置信度 high）→ 产品安全 high
- **源码映射 / 调试符号**（`*.js.map` / `*.pdb`）→ 产品安全 high
- **备份/遗留文件**（`.bak`/`.old`/`- Copy`/`副本` 等）→ 工程化 mid
- **提交的缓存/IDE 目录**（`__pycache__`/`.idea` 等）→ 工程化 mid
- **超大归档/二进制**（zip/rar/exe 等 > 5MB）→ 工程化 mid
- **调试日志**（`*.log`）→ 工程化 low

> 所有发现统一汇入置信度评分与否决管道，私钥/密钥文件会直接触发发布否决。

### 3. 置信度评分 + 三管过滤 (ConfidenceEngine)
- **置信度加权**：高置信度 ×1.0 / 中 ×0.7 / 低 ×0.3
- **自动反误报**：8 条反误报规则代码级自动执行
- **三条管道**：strict(全部) → normal(去噪) → release(阻塞级)

### 实测性能

| 项目 | 语言 | 文件 | v7.2 AI幻觉 | v8.0 AI幻觉 | v7.2评分 | v8.0评分 |
|------|------|:---:|:---:|:---:|:---:|:---:|
| WeChatNotify | C# WPF | 8 | 4 high | **0** | A (83%) | **S (94%)** |
| BearHelper | Python | 10 | 10 critical + 10 high | **0** | C (49%) | **B (70%)** |

---

## v8.1 商业级修复（发布门禁加固）

v8.1 在 v8.0 基础上完成「发布门禁」的实质性落地，修复了两处此前使门禁失效的核心逻辑错误：

1. **置信度加权方向修正**：旧实现 `effective = base*(1 - factor*0.5)` 导致高置信度反而扣得更少（与文档相反）。修正为 `有效扣分 = 基础扣分 × 置信度权重`（high ×1.0 / medium ×0.7 / low ×0.3 / unknown ×0.1），高置信问题扣分更多、更可信。
2. **发布否决机制实现**：旧版 `veto_hit` 硬编码为 `False`，门禁名存实亡。v8.1 实现「🔴 致命层 + ≥1 critical → 该层 0 分 + 否决禁发」，并与评分强绑定（否决强制判级 C）。
3. **发布门禁决策（release_gate）**：在评分之外增加独立裁决，任何「安全/致命层高/严重问题」或「提交的私钥/密钥文件」均直接 **BLOCK**，避免漏洞项目被误判为可发布。
4. **发布前遗留/调试文件检测**（见上文模块 3）。

## v8.2 商业级扩展（漏洞检测广度）

v8.1 的「门禁机制」已正确，但审计**广度**仍缺失主流漏洞类。v8.2 经对抗性探针验证，将漏报从 7/8 收敛到 0/8，新增 8 类注入/反序列化/穿越检测器（均位于 `smart_detectors.py`，命中即 high 级 `owasp_security`/`product_security`，由 `release_gate` 直接 **BLOCK**）：

| 检测器 | 覆盖风险 | 典型命中 | 误报防护 |
|--------|----------|----------|----------|
| `check_xss` | XSS | `el.innerHTML = userInput` | 纯静态字符串（`"<b>hi</b>"`）不标 |
| `check_command_injection` | 命令注入 | `os.system("ls "+u)` | 静态命令降级 mid，动态拼接 high |
| `check_code_injection` | 代码注入 | `eval(req.args.get("x"))` | `setTimeout(函数)` 不误伤 |
| `check_insecure_deserialization` | 反序列化 RCE | `pickle.loads(payload)` / `yaml.load`（非 SafeLoader） | `yaml.safe_load` 不标 |
| `check_path_traversal` | 路径穿越 | `open("../../etc/"+name)` | 仅当含 `..` 或外部变量 |
| `check_ssrf` | SSRF | `requests.get(user_url)` | 字面量 URL（`"https://..."`）不标 |
| `check_weak_crypto` | 弱加密 | `hashlib.md5(pwd)` / `DES`/`RC4`/`ECB` | MD5/SHA1 非密码场景降级 mid |
| `check_hardcoded_secret` | 硬编码密钥（通用命名） | `DB_PASS = "SuperSecret123"` | 占位符/示例值（placeholder/xxxx）排除 |

**实测收敛**（对抗探针，8 项真实漏洞）：v8.1 漏报 7 项 → v8.2 漏报 0 项；干净代码 0 误报（含参数化 SQL、CLI print、logger、input 取密码等）。

## v8.3 商业级收口（密钥检测自包含 + 复验加固）

v8.2 经复验探针发现一处**协同层盲区**：`sk-`/`AKIA` 高熵密钥仅由 `code_audit_runner.py` 兜底，逐行检测器 `smart_detectors` 不输出——而智能体协同消费的是逐行结构化输出，会看不见 AKIA。v8.3 修复并复验：

1. **密钥检测完整收口**：`sk-`/`AKIA` 直接模式并入 `smart_detectors.check_hardcoded_secret`，逐行检测器**自包含**，协同层不再有盲区。
2. **修掉 v8.1 同款误杀陷阱**：高熵密钥排除正则曾含裸 `example` 子串，导致 `AKIAIOSFODNN7EXAMPLE` 被跳过——该串恰为 AWS 官方文档示例密钥（应以 `EXAMPLE` 结尾精准豁免，而非子串匹配误杀真实密钥）。已收紧为「仅当 token 以 EXAMPLE 结尾才豁免」。
3. **删除 runner 重复密钥块**：消除 `check_security_patterns` 死代码与双报风险，单一来源（smart_detectors）保证一致性。
4. **复验通过**（独立对抗探针 + 端到端门禁）：真实漏洞 **0 漏报**、正常代码 **0 高危误报**、AWS 文档示例密钥**正确豁免**、真实 AKIA**拦截**、漏洞项目端到端 **BLOCK**、干净项目 **PASS**、密钥**无双报**。

### 发布门禁决策（release_gate）

脚本在 `report.json` 中输出 `release_gate` 字段，作为 CI / 智能体可直接消费的最终裁决：

| decision | 含义 | 触发条件 |
|----------|------|----------|
| `BLOCK` 🚫 | 禁止发布 | 否决命中 / 评分 C / 安全致命层存在高·严重问题 / 提交私钥或密钥文件 |
| `CONDITIONAL` ⚠️ | 有条件发布 | 评分 B / 存在遗留文件 / 存在 mid 级问题 |
| `PASS` ✅ | 可发布 | 无上述任何项 |

### 智能体协同审查（LLM 联动）

本 skill 设计为「脚本初筛 + 智能体深度验证」的双层架构，可与大模型智能体配合，避免单点误判：

- **脚本负责确定性初筛**：`report.json` 为结构化、可重复输出，每条 issue 含 `file:line`、`layer`、`severity`、`confidence`、`code_snippet`、`suggestion`，智能体可直接逐条读取并定位源码验证。
- **智能体负责语义验证**：对每条脚本告警执行阶段 2 的 4 步验证（读上下文 → 判误报 → 标置信度 → 记依据），尤其对 `confidence=low/medium` 的项做人工级判断，降低误报/漏报。
- **门禁兜底**：无论智能体如何调整，`release_gate` 的硬性裁决（否决、私钥、安全高危及遗留文件）始终生效，保证「不漏判致命问题」。
- **省 token 关键**：脚本是确定性、0 LLM 调用的毫秒级初筛，只把**疑似问题行**（`file:line` + `code_snippet`）交给智能体；昂贵的 LLM **只读这几行上下文**而非整个仓库，单项目审查 token 成本可降 1~2 个数量级。脚本保证「明显漏洞绝不放过」，智能体负责「语义确认 + 补抓规则外的逻辑/鉴权类缺陷」，两层互补逼近商业级无漏判。
- **协同命令（三步固化流程）**：

```bash
# ① 脚本初筛 → 仅输出「疑似任务清单」(agent_tasks)，0 token 消耗、毫秒级
python scripts/code_audit_runner.py <项目> --agent-mode --agent-tasks-out tasks.json

# ② 把 tasks.json 喂给 LLM 审查智能体，让其对每条返回三态
#    （CONFIRM / REJECT / SUPPLEMENT），见下方提示词模板

# ③ 合并裁决 → 产出最终发布结论（门禁 BLOCK 兜底 + 智能体确认）
python scripts/code_audit_runner.py <项目> --apply-verdicts verdicts.json -o final.json
```

- **三态裁决协议（agent_protocol.py，已落地可复现）**：
  - `CONFIRM`：确认真实问题，附 `agent_note`（根因）/ `agent_fix`（修复方向）。
  - `REJECT`：判定误报，必须给 `reason`（如测试桩 / 已转义 / 已白名单校验）。
  - `SUPPLEMENT`：skill 规则外的问题（鉴权绕过 / 竞态 / 越权），附 `finding`。
  - 未给结论的 task 默认 `CONFIRM`（保守）；`low` 级代码问题不进 agent 任务（自动保留，省 token）。
  - 合并后重新评分与裁决，**门禁硬性 BLOCK 始终生效**，不依赖 LLM 判断。

- **LLM 智能体提示词模板**（`agent_protocol.AGENT_SYSTEM_PROMPT`，可直接引用）：

```
你是一名资深代码安全审查专家，与「ai-code-audit 发布门禁」协同工作。
门禁已做确定性初筛，产出疑似问题清单 tasks。请逐条做语义确认，而非重扫全仓库。
对每条 task 仅返回 CONFIRM / REJECT / SUPPLEMENT 三态之一（见 tasks 字段说明）。
约束：不为无证据的问题臆造 CONFIRM；只深读 snippet 所在行及其极小上下文；
输出必须是对齐 verdicts 结构的合法 JSON，不要任何解释性文字。
```

- **协议价值**：脚本保证「已知模式明显漏洞绝不放过」（确定性），智能体负责「语义确认 + 补抓规则外缺陷」（推理），两层互补 → 商业级无漏判；昂贵的 LLM 只读疑似行，token 成本降 1~2 个数量级。

### 指定功能模块审查（模块级扫描）

`code_audit_runner.py` 的首个位置参数即扫描根，**传入任意子目录即等于对该功能模块单独审查**，无需额外参数：

```bash
# 只审查 auth 模块（仅扫 src/auth 子树，不越界其他模块）
python scripts/code_audit_runner.py ./src/auth --agent-mode -o auth_tasks.json

# 只审查某个文件
python scripts/code_audit_runner.py ./src/payment/charge.py --agent-mode

# 全量审查（默认整仓）
python scripts/code_audit_runner.py ./src
```

适用场景：PR 只改了某个模块时，对该模块单独跑门禁 + 协同，进一步缩小 LLM 阅读范围、降低 token；或按模块分批出具审查报告。

---

## v8.5 商业级补全（文档落地为真实能力）

v8.0–v8.4 的文档曾声称若干能力但代码未完全实现。v8.5 **把文档与代码对齐**：以下三项均为真实可运行实现（非占位），并经单测 + 端到端探针验证。

### 1. Python AST 逻辑分析（`ast_logic_analyzer.py`，真实 AST，非正则推断）
对单个 `.py` 文件做 `ast.parse` 后遍历语法树，覆盖：

| 检测项 | 方法 | 严重度 | 置信度 |
|------|------|:---:|:---:|
| 除零 / 取模零 | `BinOp(Div/Mod, 右操作数=字面量0)` | high | high（确定性） |
| `open()` 未用 `with` | 识别 `open()` 调用不在 `with` 上下文 | mid | high |
| 潜在无限循环 | `while True` 无 `break/return/raise/exit` | mid | medium |
| 返回类型不一致 | 函数既 `return None` 又返回非 None | low | medium |
| None 解引用（启发式） | 函数内 `x=None` 后直接 `x.attr/x[...]` 且无重赋值 | mid | low |

> **诚实边界**：这是单文件语法/控制流层面的检测，**不追踪跨函数/跨文件数据流，不做符号执行**。变量在分支中被重赋值等复杂场景可能漏报或误报，故除「除零字面量」外均给较低严重度/置信度，交由智能体协同确认。

### 2. 依赖漏洞(SCA)审计（`dependency_audit.py`）
解析多生态依赖清单并比对**内置精选漏洞库**：

| 生态 | 解析清单 |
|------|------|
| Python | `requirements*.txt` / `pyproject.toml` / `Pipfile` |
| Node | `package.json` |
| Go | `go.mod` |
| Rust | `Cargo.toml` |
| Java | `pom.xml` |

- 精确/上界钉版（`==`/`<=`/`~=`）命中已知漏洞 → 输出 `product_security` issue（critical/high/mid，依 CVE 定级），critical 直接触发门禁否决。
- 范围依赖（`^`/`~`/`>=`）若地板版本 < 修复版 → 提示「可能受害，建议升级并锁定」（medium）。
- 未锁定版本（`*`/无版本）→ low 提示「用 pip-audit / npm audit / OSV 完整核查」。

> **诚实边界**：内置库是**人工精选的子集**（数十个高危 CVE：flask/pyyaml/pillow/jinja2/requests/django、lodash/axios/minimist/jsonwebtoken/express/moment/semver/tar、log4j-core 等），**并非 OSV/NVD 全量**。它用于门禁快速拦截已知高危；完整 SCA 请用 `pip-audit` / `npm audit` / `cargo audit` / `OSV-Scanner` / `safety`。

### 3. 白名单（`audit_whitelist.py` + `--whitelist`，v8.4 文档已写、v8.5 真正实现）
`--whitelist wl.json` 支持：

| 字段 | 作用 |
|------|------|
| `exclude_files` | 文件名 glob（如 `["test_*.py"]`） |
| `exclude_dirs` | 目录名（命中路径任意一段即排除，如 `["vendor"]`） |
| `exclude_layers` | 整层跳过（如 `["code_quality"]` 不看魔法数字噪音） |
| `exclude_patterns` | 对 `desc+code_snippet` 做正则排除 |
| `known_packages` | 注入为已知包（AI 幻觉层不再误报内部库） |
| `auto_generated_dirs` / `auto_generated_patterns` | 标记自动生成代码 |

白名单在「源码扫描前排除文件 + **遗留文件扫描（release_artifacts）前排除文件** + 扫描后按层级/正则过滤 issue」三处生效，且 `known_packages` 注入 `PackageResolver`，与现有反误报协议一致。

---

## v8.6 终审修复补强（商业级权威落地）

v8.5 通过终审后发现并修复 6 项问题，全部经实跑对抗探针 + 单测复验通过，确无回归：

| # | 类型 | 问题 | 修复 | 验证 |
|----|------|------|------|------|
| F1 🔴 | 漏报 | `DB_PASSWORD`/`db_password` 硬编码密钥此前漏检（最常见密钥变量名之一） | 正则 `DB_?(?:PASS(?:WORD|WD)?\|PWD)` 覆盖后续词字符 | DB_PASSWORD 命中、单测不回归 |
| F2 🟡 | 一致性 | 白名单未作用于遗留文件扫描（仅自身 EXCLUDE_DIRS），白名单 `.env`/测试目录仍会触发 BLOCK | `scan_release_artifacts` 增加 `whitelist` 参数，调用 `is_file_excluded` 跳过 | `exclude_files` glob 与 `exclude_dirs` 均正确排除 `.env` |
| F3 🟡 | 性能 | 遗留文件 `rglob` 读取全量文件，无上限 | 改为惰性遍历 + `max_files`（默认 300）硬上限，超限即停 | `max_files=2` 仅扫 2 个、`=999` 扫全量 |
| F4 💭 | 隐患 | `ConfidenceEngine` 规则5（localhost/CORS 自动判误报）为死代码，却是潜在漏报地雷（含 localhost 的真实 SQLi 可能被静默丢弃） | 删除规则5 及未用的 `LOCALHOST_PATTERNS` | 含 `127.0.0.1` 的 SQLi 不再被丢弃 |
| F5 💭 | 误报 | AST 返回类型不一致把 `return None` 惯用法误标为代码异味 | `None` 视为中性，仅当混合 ≥2 种非 None 类型时标记 | `return 1 / return None` 不报；`return 1 / return 'ok'` 报 |
| F7 💭 | 整洁 | `is_test_file` 死代码 | 删除 | — |

**诚实边界（发行须保留）**：AST 为单文件静态（无数据流）；依赖 CVE 库为精选子集（非 NVD 全量，需配合 `pip-audit`/`npm audit`）；定位为「确定性门禁 + LLM 智能体协同」双层架构，不替代人类对逻辑/鉴权/竞态的语义判断。

**终审结论**：自测 50/50、单测 14/14、漏报探针 0 漏报（BLOCK）、误报探针 0 高危误报（PASS）、边界/协同往返全绿 → 达到商业级发行标准。

---

## v8.7 协同层审计化（回应商业级三问：不可复现 / 无推理链 / 不可追溯）

v8.5~v8.6 解决了「确定性初筛」的可复现，但 LLM 三态确认层仍有三个商业级缺口，v8.7 全部闭环：

| # | 商业级质疑 | v8.6 缺陷 | v8.7 修复（已实跑验证） |
|----|-----------|-----------|------------------------|
| G1 | 同一批 issues[]，两次 CONFIRM/REJECT 比例可能不同（不可复现） | `apply_verdicts` 直接信任 LLM 裁决、无兜底 | **硬性地板**：致命类 REJECT 无 `human_override+override_reason` → 保留为 `challenged`、门禁仍 BLOCK；非复现判断无法静默放行真实漏洞。复现契约 `issues_hash`+`determinism_manifest` 可校验 |
| G2 | LLM 为什么 REJECT 一条 SQL 注入？没有推理链（不可解释） | 裁决只需 `reason`（可空），无证据/置信度 | **每条裁决必须 `reasoning`+`evidence`+`confidence`**；缺推理判 `invalid`→保守保留+`needs_human_review`。最终报告每条发现带 `source`+`llm_reasoning`+`audit_trail`，可逐条质疑 |
| G3 | 商业审计报告需每个判断有据可查、可追溯、可质疑 | 终态是「LLM 协同裁决」，裁定权在不可复现的模型 | **裁定权回归人类**：LLM 层产出一律标 `requires_human_validation`；致命类放行必须有 `human_override` 人工复核理由（写入 `human_overrides`，带理由、可追溯）；`release_gate` 仍提供确定性硬信号供 CI 直卡 |

**协议版本升至 2.0**（`agent_protocol.PROTOCOL_VERSION`），任务清单新增 `issues_hash` / `determinism_contract` / `deterministic_evidence`，提示词强制 `temperature=0`+固定 model+回填 manifest。

**验证（端到端 CLI 探针，v8.7 新增 `test_verdict_audit_and_floor` 单测）**：
- 场景1 全 REJECT 无复核 → `BLOCK` + `deterministic_floor_blocked=True` + 3 条 `challenged`（密钥/SQLi/.env），`human_overrides=0`；
- 场景2 全 REJECT + 合法 `human_override` → `PASS` + 3 条 `human_overrides`（含可追溯理由）；
- 场景3 CONFIRM+SUPPLEMENT → `supplemented[0].source=llm_supplemented` + `requires_human_validation=True` + 推理链 + `audit_trail` 5 条 + `validation.reproducibility=verified`。

**诚实边界（发行须保留，回应「脚本只能兜底已知模式」）**：确定性层兜底的仅是**已知、模式化**缺陷；「发现你不知道的问题」依赖 LLM 的 SUPPLEMENT，而 LLM 天然非确定性——故 SUPPLEMENT 一律标 `requires_human_validation`，判定权在人类。本 skill 不宣称 LLM 层可复现，只保证：**确定性层 100% 可复现 + LLM 层不可复现有兜底 + 所有判断可追溯**。

---

## v8.8 逻辑漏洞闭环（最终商业级终审，确保无逻辑漏洞）

v8.7 解决了「协同层审计化三问」，但终审中又发现两处**逻辑漏洞**（方向都不安全），v8.8 全部闭合：

| # | 商业级质疑 | v8.7 缺陷 | v8.8 修复（已实跑验证） |
|----|-----------|-----------|------------------------|
| H1 | 裁决回灌的 `issues_hash` 与当前报告不一致时怎么办？ | `validate_verdicts` 检测到 `hash_mismatch` 只写进 `validation.notes`，**仍按 ID 把旧裁决套用到当前报告**——旧报告 T001=`.env` 带 `human_override` 放行，改代码后新报告 T001=SQL 注入，旧 override 会错误删掉真实 SQLi 导致 `PASS`（误放真实漏洞） | `apply_verdicts` 新增 `untrusted` 信号：`hash_mismatch` 时**所有 REJECT/SUPPLEMENT 作废**，仅保留确定性确认结果，门禁以确定性层为准。陈旧裁决无法误放任何真实漏洞 |
| H2 | LLM 补抓的缺陷会不会单方面卡发布？ | SUPPLEMENT（severity=high + business_logic）直接进 `_decide_gate`，不经 `human_override` 就能 unilateral BLOCK，与「LLM 层有界、最终拍板在人类」自相矛盾，且同代码两次审查结果不一（非复现 BLOCK） | 门禁裁决**仅基于确定性确认结果**：SUPPLEMENT 绝不自动 BLOCK，只强制升级到 `CONDITIONAL`（需人工复核）。发布拍板权始终在人类/确定性层，LLM 只能「确认/质疑/补抓建议」，不能单方放行也不能单方 BLOCK |

**协议语义最终收敛为（清晰、可辩护的商业级契约）**：
- 确定性层（脚本）：100% 可复现，是唯一能自主 BLOCK 的力量；
- LLM 层（协同）：① CONFIRM → 保留并附推理链；② REJECT 致命类 → 须 `human_override` 背书，否则保留为 `challenged`、继续 BLOCK；③ REJECT 非致命类 → 可剔除；④ SUPPLEMENT → 升级为 CONDITIONAL（需人工复核），永不自动 BLOCK；
- `determinism_manifest.issues_hash` 不匹配 → 整个裁决集作废，门禁以确定性层为准。

**验证（v8.8 新增 `test_verdict_robustness_v8_8` 单测 + 端到端 CLI 探针）**：
- 陈旧裁决（错误 `issues_hash` + `human_override` 想放行 SQLi）→ `BLOCK` + `verdicts_untrusted=True` + `reproducibility=hash_mismatch` + `human_overrides=0` + T001 以 `source=deterministic` 保留（不附陈旧推理）；
- 干净项目 + 仅 SUPPLEMENT（高危及越权）→ `CONDITIONAL`（绝不 `BLOCK`）+ `requires_human_validation=True`。

---

## v8.9 真实发行淬炼（基于 voicebutler 项目实战，根治命令注入误报）

v8.8 在逻辑上已闭环，但把它**真正跑在一个 Rust/Tokio + React/Tauri 桌面项目（voicebutler）上**时，暴露出确定性层最刺眼的一类误报：命令注入检测器把 Rust 的异步任务派发与参数向量进程调用全部误判为 HIGH 命令注入，一次性刷出 8 条高危，几乎淹没真实问题。v8.9 据此根治：

| # | 商业级质疑（来自真实发行） | v8.8 缺陷 | v8.9 修复（已实跑验证） |
|----|-----------|-----------|------------------------|
| C1 | Rust 项目里 `tokio::spawn(async {...})`（异步任务）和 `Command::new(...).args([...]).spawn()`（参数向量，无 shell）为什么被标成「命令注入」？ | 检测器正则含**裸 `spawn`** 且 `language` 参数从未用于消歧，把一切含 `spawn` 的行（含 Tokio 异步任务、arg-vector 进程调用）都当命令执行 | `check_command_injection` 重写为**语言感知 + 执行原语分类**：仅「经 shell 解释字符串执行」(`os.system`/`subprocess(shell=True)`/`child_process.exec`/`Runtime.exec`/`sh -c`/`cmd /C`/`powershell -Command`) 且含动态输入才判注入；`tokio::spawn`/`Handle::spawn`（异步任务）、`subprocess.run([...])`/`Command::new(prog).args([...])`/`exec.Command(prog,args)`/`child_process.spawn(prog,[args])`（参数向量，无 shell）一律**不误报** |
| C2 | 同样 `Command::new("powershell").args(["-Command", &script])` 这种「真·shell 执行含变量」又会不会漏？ | v8.8 把这类也归进「arg-vector 不误报」一刀切丢掉了（LLM 复核时还曾误判为安全） | v8.9 精准识别：程序名是 shell 解释器（`"cmd"`/`"sh"`/`"powershell"` 等引号前缀）+ 参数含变量/format! → **正确标出**为 shell 执行（交由协同层判断输入是否可控）。voicebutler 的 `tts/mod.rs:167`(powershell 播音频)、`compat/mod.rs`(cmd /C)、`bridge/main.go`(Go `exec.Command("cmd","/C",req.Command)`) 均被**正确命中**，而 `tokio::spawn` 全部不再误报 |

**实测对比（voicebutler 同一项目）**：v8.8 初筛 HIGH=8（7 条为 Tokio 异步任务/arg-vector 误报，仅 1 条真实）；v8.9 初筛 HIGH=7（**全部为真实 shell 执行原语**：bridge 未鉴权 localhost RCE ×4、compat cmd /C ×2、tts powershell ×1），误报清零、真实命中率显著提升。

**验证（v8.9 新增 `test_command_injection_language_aware` 单测，17 条用例覆盖 Rust/Go/Python/Node/Java 五语言 shell 与 arg-vector 双向）**：单测 16/16 → **17/17 全绿**；自测 50/50 不变；端到端 CLI 在 voicebutler 复跑确认 HIGH 误报清零。

---

## v8.10 最终商业级淬炼（闭环「漏报」盲区，协议逻辑复跑验证）

v8.9 解决了**误报**（Rust/Tokio 上命令注入假阳性清零）。在 v8.9 终验阶段，用对抗探针做**双向**验证时，发现确定性层存在一处**漏报（false negative）**：`_is_dynamic` 在做「剥除字符串字面量」消噪时，会把 `os.system(f"rm -rf {user_input}")` 这种 **f-string 插值**整体剥掉，剩下一个裸 `f` 被误判为静态字面量——于是教科书级命令注入被**静默放过**。这是一个安全工具绝不该有的盲区。v8.10 据此闭环：

| # | 终验发现（来自对抗探针） | v8.9 缺陷 | v8.10 修复（已实跑验证） |
|----|-----------|-----------|------------------------|
| D1 | `os.system(f"rm -rf {user_input}")`（Python f-string 插值）、`` child_process.exec(`echo ${name}`) ``（JS 模板字符串插值）这类**字符串内部含外部可控插值**的注入，为什么没报？ | `_is_dynamic` 先把 `"..."` 字面量整体剥除再判动态，f-string / JS 模板字符串的 `{var}` / `${var}` 插值被一并剥掉，剩 `f` 误判静态 → **漏报** | 在剥除之前先抽验**插值标记**：`\$\{`(JS 模板) 与 `\{[A-Za-z_][^}]*\}`(f-string/插值，且 `{` 后紧跟标识符以排除 dict 字面量 `{"k":}` 与集合 `{1,2}`) → 命中即判动态；剥除逻辑保留以继续防 `x = "1 + 1"` 类误报。**真注入与静态误报双向均过** |

**协议两层逻辑漏洞复跑验证（v8.10 `probe_v89.py` 端到端探针，全绿）**：
- **H1 陈旧裁决误放（漏洞A）**：回填 `determinism_manifest.issues_hash` 与当前报告不符 → `validation.reproducibility=hash_mismatch` → `untrusted=True` → 所有 REJECT/SUPPLEMENT 作废，阻塞类 HIGH 不被静默丢弃，门禁维持 `BLOCK`（`human_overrides=0`、`confirmed_issues=1`）。
- **H2 SUPPLEMENT 单方 BLOCK（漏洞B）**：仅 SUPPLEMENT（high + 审计层）且无其他阻塞项 → 门禁 `CONDITIONAL`（绝不 `BLOCK`），`supplemented_findings=1`、`untrusted=False`。

**验证（v8.10 新增 f-string / JS 模板插值用例并入 `test_command_injection_language_aware`）**：单测 **17/17 全绿**（注入探测器 19/19 子项）；自测 **50/50** 无回归；voicebutler 同项目复跑 HIGH=7（误报仍为 0，真实命中不变）；协议闭环探针 **全 PASS**。

---

## 核心原则

1. **零误报优先**：宁可漏报不可误报，每条结论必须有代码证据
2. **修复不改业务**：标记问题但提供约束规则，不擅自修改代码
3. **分级渐进**：低 → 中 → 高 → 致命，渐进式审查
4. **项目类型自适应**：Web/桌面/API/CLI/库，不同场景不同规则
5. **脚本确定性 + 智能去噪**：正则初筛提供客观数据 → 智能检测器上下文感知过滤
6. **置信度透明**：每条 issue 标注 high/medium/low 置信度
7. **🔴 致命 → 禁发 · 🟠 严重 → 需修复**

---

## ⚠️ 反误报协议（强制执行）

v8.0 在代码层面自动执行标注「自动」的规则。标注「人工确认」的需开发者判断。

### 规则 1：先读全貌再下结论（人工确认）
- 禁止只 grep 关键词就下结论
- 必须读完相关函数/类的完整实现
- 必须搜索所有调用路径（退出路径、错误路径、生命周期路径）

### 规则 2：区分设计决策与 Bug（人工确认）
- 看到"看似有问题"的代码 → 先问"为什么要这样写？"
- 搜索相关上下文：是否有注释说明？是否有配套清理逻辑？
- CORS/全局变量/轮询等 → 必须理解架构意图再判断

### 规则 3：定时器/资源泄漏验证（自动 + 人工确认）
- [ ] `setInterval`（长期）or `setTimeout`（一次性）？一次性不构成泄漏
- [ ] 是否有对应的清理函数？清理函数是否在退出路径被调用？
- [ ] 搜索 `cleanup`/`dispose`/`destroy`/`before-quit`/`unmount` 确认清理链

### 规则 4：安全问题验证（自动 + 人工确认）
- [ ] 该设计是否是功能需要？（如 CORS * 可能是自定义协议跨域需要）
- [ ] 攻击面是否实际可达？（如 localhost-only 服务不构成网络漏洞）
- [ ] 是否有其他防护层？（如 contextIsolation/sandbox/nodeIntegration:false）

### 规则 5：性能问题验证 — 硬性约束（自动）
**A 级（已实测，可标 P0/P1）**：
- [ ] 有实测 CPU/内存/帧率数据（Chrome DevTools/process.memoryUsage()/benchmark）
- [ ] 对比基准：优化前 vs 优化后的量化差异

**B 级（理论推演，只能标为 💡建议优化）**：
- [ ] 未实测 → 禁止写为「Bug」或「问题」
- [ ] 禁止使用「内存泄漏」「CPU占用X%」「性能瓶颈」等定性词汇

**铁律：不跑基准测试，不允许说 CPU/内存的具体数字。**

### 规则 6：包名/导入验证（自动）
- Python stdlib（zlib/ctypes/lzma/os/json 等）→ 自动跳过
- 项目内部命名空间（.csproj namespace）→ 自动白名单
- node_modules 已安装的包 → 自动识别
- 未匹配的包 → 标注「待确认」（低置信度）

### 规则 7：报告分级标注（自动）
- ✅ **已确认**：有直接代码证据 + 清理链不存在/不完整
- ⚠️ **待确认**：有代码证据但可能有未读的上下文
- 💡 **建议优化**：非 Bug 但可改进（需说明为什么不是 Bug）

### 规则 8：建议不得使现状变差（人工确认）
- 每条优化建议必须评估「改了会不会更差」
- 如果优化会引入新问题（如：改 rAF → setInterval 导致动画卡顿），则该建议必须标注 ⚠️ 风险并保留现状
- 宁可不优化，不可优化变差

---

## 执行流程（严格顺序）

```
阶段 0: 智能项目发现 → 溯源到项目根
    ↓
阶段 0.5: 项目类型识别 → Web|桌面|API|CLI|SDK|移动端
    ↓
阶段 1: 脚本初筛（安全规则 + 代码质量 + 导入检测）
    ↓
阶段 1.5: 智能去噪（PackageResolver + SmartDetectors + ConfidenceEngine）【v8.0 新增】
    ↓
阶段 2: 逐 issue 验证（读代码确认/排除误报）
    ↓
阶段 3: 补充发现（脚本漏检的问题，必须附代码证据）
    ↓
阶段 A: 模块功能审查 · 阶段 B: 模块协同分析
    ↓
阶段 C: 四层运营审查 → 评分 → 路线图 → 报告
```

**关键约束**：阶段 3 的每条补充发现，必须经过阶段 2 同等的验证流程。

---

## 阶段 0：智能项目发现

**⚠️ 最关键。先判断路径类型再溯源。**

| 典型文件 | 判断 | 处理 |
|------|------|------|
| `.exe/.dll/.so/.class/.jar` | 编译产物 | ❌ 向上回溯 |
| `node_modules/dist/build/target/vendor` | 构建目录 | ❌ 向上回溯 |
| `.cs/.py/.js/.ts/.java/.cpp/.go/.rs/.vue` | 源码 | ✅ 审计 |
| `.csproj/package.json/Cargo.toml/go.mod/pom.xml/build.gradle` | 项目根 | ✅ 全量 |

溯源：检查 → 判断 → 编译产物则 cd .. → 找标识文件 → 从根列源码 → 排除构建目录 → Monorepo 分项目审计

```bash
python scripts/code_audit_runner.py <根目录> --output report.json [--output-md r.md]
```

❌ 禁止仅审用户路径 ✅ 必须溯源全量审计 报告写明「用户指定 vs 实际范围」

### 阶段 0.5：项目类型与自动代码

**项目类型**（自动检测）：Web前端 | 桌面 | API | CLI | SDK | 移动端

**裁剪矩阵**（✓必须 ○可选 —跳过）：

| 审查项 | Web | 桌面 | API | CLI | SDK |
|------|:---:|:---:|:---:|:---:|:---:|
| AI幻觉/代码质量/业务/异常/工程化 | ✓ | ✓ | ✓ | ✓ | ✓ |
| OWASP安全 | ✓ | ✓ | ✓ | ○ | ○ |
| 内存性能 | ✓ | ✓ | ✓ | ○ | ○ |
| 产品攻防 | ✓ | ✓ | ○ | — | — |
| Win32/GDI | — | ✓ | — | — | — |

**自动代码**：头部"auto-generated/DO NOT EDIT" · `*_pb2.py/*.pb.go` · generated/目录 → 排除质量检查，保留安全审查

---

## 阶段 1：脚本初筛 + 智能去噪

### 脚本自动检测
10 语言检测 / 安全规则 / 导入检测 / 调试残留 / 魔法数字 / 模块归类 / 评分

### v8.0 智能去噪（新增）
- **PackageResolver**：自动跳过 Python stdlib / node_modules 已安装包 / .csproj 项目命名空间
- **SmartDetectors**：自动跳过 Color.FromArgb / StringBuilder / CLI print() 等安全上下文
- **ConfidenceEngine**：自动执行 8 条反误报规则 → 三管过滤

---

## 阶段 2：逐 issue 验证（反误报核心）

对脚本报告的每个 issue，执行 4 步验证：

**步骤 1：读完整上下文** — 读 issue 所在函数完整实现，搜索所有调用方和清理逻辑

**步骤 2：判断是否误报**

| 脚本告警 | 典型误报 | 验证方法 |
|------|------|------|
| AI幻觉 | 项目内部命名空间、Python标准库 | 检查 package.json/.csproj + stdlib 列表 |
| 硬编码密钥 | 测试值(test/123)、环境变量引用 | 检查是否 test/目录、.env 引用 |
| 调试残留 | 条件编译(if dev)、日志框架(logger.debug) | 检查条件上下文 |
| 魔法数字 | Color.FromArgb、StringBuilder、端口号 | v8.0 自动跳过 30+ 安全上下文 |
| 空catch | 有意忽略(ENOENT)、接口占位 | 检查注释和错误类型 |
| SQL注入 | ORM查询、已参数化 | 检查 ORM/参数化 |
| 内存泄漏 | 一次性 setTimeout | 区分 setInterval vs setTimeout |
| 性能问题 | 框架标准模式(rAF动画) | 必须实测 |

**步骤 3：标注置信度** — ✅已确认 / ❌误报(附原因) / ⚠️待确认

**步骤 4：记录验证依据** — `文件:行号 → 问题 → 验证过程 → 结论`

---

## 阶段 3：补充发现

脚本漏检的问题类型（LLM 分析补充，必须附代码证据）：

| 类型 | 验证方法 |
|------|------|
| 资源释放链 | 搜索 create → destroy/close/dispose 配对 |
| 事件监听器泄漏 | 搜索 addEventListener → removeEventListener 配对 |
| 定时器泄漏 | 搜索 setInterval → clearInterval 配对 |
| 组件卸载清理 | 搜索 useEffect → return cleanup 配对 |
| 异步操作取消 | 搜索 fetch/async → AbortController 配对 |
| 上帝组件/函数 | 统计行数/子组件数 |

每条补充发现必须经过阶段 2 同等的 4 步验证流程。

---

## 阶段 A-B：模块审查与协同分析

- **阶段 A**：逐模块卡片（≤15 行）— 逻辑正确性/功能完整性/实现程度/Bug风险/代码质量
- **阶段 B**：调用链完整性 · 数据一致性 · 事件传播 · 错误传播 · 接口契约

---

## 八层代码审计

| 层 | 要点 | 否决 |
|---|------|:---:|
| 1.AI幻觉 | 包/API真实？项目内引用？标准库？ | 🔴 |
| 2.代码质量 | 魔法数字？调试残留？空函数？命名？ | — |
| 3.业务逻辑 | 空实现？分支完整？事务？输入校验？竞态？ | 🔴 |
| 4.OWASP | SQL拼接？XSS？密钥硬编码？路径遍历？SSRF？XXE？反序列化？ | 🔴 |
| 5.内存性能 | 监听器解绑？定时器清除？连接关闭？资源泄漏？ | 🔴 |
| 6.异常容错 | 空catch？超时重试？降级兜底？ | — |
| 7.工程化 | 测试？硬编码？环境区分？依赖锁定？ | — |
| 8.攻防 | 资源加密？本地明文？Token过期？依赖漏洞？ | 🔴 |

**语言专项**：桌面=GDI/线程安全 · Java=@Transactional+private/try-with-resources · Go=goroutine泄漏/忽略error · Rust=unwrap/unsafe · C++=strcpy/sprintf/gets · Vue=v-html/.native

---

## 四层运营审查

C1 UX/UI(🟠) · C2 性能(🟠) · C3 部署(🟠) · C4 合规(🔴)

---

## 置信度加权评分（v8.0）

### 各层满分

| 层级 | 满分 | 层次 |
|------|:---:|------|
| AI幻觉 | 15 | 🔴 致命 |
| 代码质量 | 8 | 普通 |
| 业务逻辑 | 15 | 🔴 致命 |
| OWASP安全 | 15 | 🔴 致命 |
| 内存性能 | 8 | 🔴 致命 |
| 异常容错 | 6 | 普通 |
| 工程化 | 5 | 普通 |
| 产品攻防 | 8 | 🔴 致命 |
| **总计** | **80** | |

### 置信度加权

```
有效扣分 = 基础扣分 × (1 - 置信度权重)

高置信度 (high)    → ×1.0  → 全额扣分
中置信度 (medium)  → ×0.7  → 扣 70%
低置信度 (low)     → ×0.3  → 扣 30%
未知 (unknown)     → ×0.1  → 几乎不扣分
```

🔴致命层 + ≥1 critical → 该层 0 分 + 否决

### 等级判定

| 等级 | 分数区间 | 含义 |
|:---:|------|------|
| S | ≥ 88% | 可直接发布 |
| A | 75-88% | 修复低危后发布（1-3天） |
| B | 57-75% | 修复中高危后发布（1-2周） |
| C | < 57% | 禁止发布 |

---

## 修复路线图

P0 阻断 → P1 高优(1周) → P2 优化(2周)。含工时 + 评分提升预估。

| 问题 | 工时 | 提升 | 问题 | 工时 | 提升 |
|------|:---:|:---:|------|:---:|:---:|
| 密钥迁移 | 2-4h | +3~5 | SQL注入 | 0.5-1h/处 | +2~3 |
| 空catch | 15min/处 | +0.5 | 调试清理 | 15min/文件 | +0.5 |
| 函数拆分 | 2-8h/个 | +1~3 | JWT/SSRF/XXE | 0.5-2h/处 | +2 |
| goroutine泄漏 | 1-3h/处 | +2 | unwrap→? | 10min/处 | +0.3 |
| try-with-resources | 15min/处 | +0.5 | 单元测试 | 1-3天 | +2~3 |
| CI/CD | 4-8h | +3 | 合规 | 4-8h | +3 |

---

## 发布报告

```
基本信息 → 📊评分卡 → ✅已确认问题 → ❌已排除误报 → ⚠️待确认项 → 💡优化建议 → 🛤️路线图 → 🚪门禁
最终结论：✅可发行 / ⚠️有条件发行 / 🚫禁止发行
```

### 输出前自检清单

- [ ] 每条「已确认」有代码证据？（文件:行号 + 代码片段）
- [ ] 读完了相关上下文？（清理链/调用方/退出路径）
- [ ] 性能结论有实测数据？无则降级为 💡
- [ ] 优化建议评估了「会不会更差」？会则标注 ⚠️
- [ ] 脚本告警逐一验证？误报记录了排除原因？
- [ ] 「待确认项」诚实标注了不确定性？
- [ ] 包名检查通过了生态验证？【v8.0 新增】
- [ ] 魔法数字检查跳过了安全上下文？【v8.0 新增】

---

## 审查模式

| 模式 | 参数 | 场景 |
|------|------|------|
| 全量 | `./src -o report.json` | 发布前 |
| 严格 | `--strict -o report.json` | 查看全部，不过滤 |
| 白名单 | `--whitelist wl.json` | 排除测试/生成/内部库 |
| 协同初筛 | `--agent-mode --agent-tasks-out tasks.json` | 仅输出疑似任务清单（0 token 初筛） |
| 协同合并 | `--apply-verdicts verdicts.json -o final.json` | 合并 LLM 三态裁决 → 最终发布结论 |
| MD报告 | `--output-md report.md` | 人类可读 |
| 自测 | `--self-test` | 验证脚本（50项） |
| 指定类型 | `--project-type api/web/desktop` | 覆盖检测 |

## 可重复性保障

| 组件 | 可重复性 | 保障方式 |
|------|:---:|------|
| 脚本初筛 | 完全确定性 | 相同输入 → 相同输出 |
| 智能去噪 | 完全确定性 | 规则驱动，无随机因素 |
| 脚本评分 | 完全确定性 | 公式固定，issue 计数 → 分数 |
| 确定性门禁 `release_gate` | 完全确定性 | 纯脚本裁决，CI 可直接硬卡，不依赖 LLM |
| LLM 协同确认 | **天然非确定性** | **不宣称可复现**；以三重约束兜底：①致命类 REJECT 无 `human_override+override_reason` → 保留 `challenged`、门禁仍 BLOCK；②每条裁决须 `reasoning`+`evidence`+`confidence`，缺推理判 `invalid` 保守保留；③`issues_hash`+`determinism_manifest` 可校验复现性，产出一律标 `requires_human_validation`，裁定权在人类 |

## 白名单

```json
{"exclude_files":["test_*.py"],"exclude_dirs":["vendor"],"exclude_rules":{"magic_number":["config.py"]},"known_packages":["my_lib"],"auto_generated_dirs":["generated"],"auto_generated_patterns":["*_pb2.py"]}
```

## 外部工具

radon cc · eslint · golangci-lint · cargo clippy · spotbugs · npm audit / pip-audit / cargo audit · jscpd · pytest --cov · ZAP/Burp

---

## 附录 A：常见误报与 v8.0 处理

| 检测项 | 典型误报 | v8.0 处理方式 |
|------|------|------|
| AI幻觉 | 项目自身命名空间、Python 标准库 | 自动白名单（parse .csproj + stdlib 列表） |
| 魔法数字 | Color.FromArgb()、StringBuilder()、端口号 | 30+ 安全上下文自动跳过 |
| 调试残留 | CLI 工具的 print() | 区分 CLI/桌面 vs API/库 |
| 空catch | 有意忽略（ENOENT）、接口占位 | 检查注释 + 错误类型 |
| 硬编码密钥 | 测试值（test/123/placeholder） | 排除 test/example/placeholder 上下文 |
| SQL注入 | ORM 查询、已参数化 | 检测占位符和 ORM 调用 |
| 内存泄漏 | 一次性 setTimeout | 区分 setInterval vs setTimeout |
| 性能问题 | 框架标准模式（rAF 动画） | 必须实测，不许理论推演 |

---

## 附录 B：测试基础设施（v8.0 真实测试）

### 可运行测试集

| 测试模块 | 位置 | 用例数 | 说明 |
|------|------|:---:|------|
| 脚本自测试 | `--self-test` | 50 | 包解析/魔法数字/调试/空catch/SQL/遗留文件/置信度/否决/AST/依赖/白名单 全链路 |
| 包解析器 | `tests/test_core.py` | 33 | Python stdlib + PyPI + npm + C# BCL |
| 魔法数字 | `tests/test_core.py` | 10 | 安全上下文跳过 + 真实标记 |
| 调试残留 | `tests/test_core.py` | 7 | CLI vs API vs Desktop 区分 |
| 过滤管道 | `tests/test_core.py` | 5 | strict/normal/release 三管验证 |
| 置信度评分 | `tests/test_core.py` | 3 | 无问题/高置信/低置信评分正确性 |
| 空 catch | `tests/test_core.py` | 5 | except/catch 空块 上下文感知 |
| 发布前遗留文件 | `tests/test_core.py` | 6 | .env/.pem/.bak/.map/超大zip/.log |
| 否决 + 置信度方向 | `tests/test_core.py` | 3 | 否决触发 + 高置信扣更多 |
| 注入类检测器 | `tests/test_core.py` | 18 | 8 类注入/反序列化/穿越 漏报+误报双向 |
| 协同协议 | `tests/test_core.py` | 11 | 初筛/三态合并/全驳回/补抓 round-trip |
| AST 逻辑分析 | `tests/test_core.py` | 5 | 除零/open/with/无限循环 命中+不误报 |
| 依赖审计 | `tests/test_core.py` | 5 | CVE 命中/范围依赖/未锁定/已修复不命中 |
| 白名单 | `tests/test_core.py` | 4 | 层级/正则/文件排除/已知包注入 |
| 遗留不双计 | `tests/test_core.py` | 4 | .env 不双计/协同任务不重复 |

### 运行方式

```bash
python scripts/code_audit_runner.py --self-test    # 50 项
cd tests && python test_core.py                      # 9 套核心测试
```

### 真实的第三方项目实测

| 项目 | 类型 | AI幻觉误报 | 评分 |
|------|------|:---:|:---:|
| WeChatNotify | C# WPF 桌面应用 | **0** (v7.2: 4) | **S 94%** (v7.2: A 83%) |
| BearHelper | Python CLI 工具集 | **0** (v7.2: 20) | **B 70%** (v7.2: C 49%) |

---

## 附录 C：已知局限（诚实声明）

正则扫描的固有边界，需要 AST/数据流分析才能解决：

| 局限 | 示例 | 影响 | v8.0 缓解 |
|------|------|:---:|------|
| 变量追踪 | `query = "..."; execute(query)` 无法追踪拼接来源 | 中 | 置信度降级 + 人工确认 |
| 动态调用 | `getattr(obj, 'loads')` 无法识别 | 低 | 低置信度标记 |
| 字符串拼接 | `"sk_" + "test_" + "abc"` 无法识别为密钥 | 低 | 排除 test/example 上下文 |
| 条件上下文 | `if DEBUG: print()` 无法区分调试/正式 | 低 | 检查条件关键词 |
| 框架特有模式 | Django ORM · Spring注解 · React Hooks 未深度覆盖 | 中 | 框架名识别但行为不分析 |
| 跨文件分析 | A 文件调用 B 文件的函数，无法追踪跨文件数据流 | 中 | 标记「建议手动审查调用链」 |

**应对方法**：脚本负责初筛，v8.0 智能引擎负责去噪，LLM 负责深度验证，人工做最终决策。

---

## 附录 D：脚本输出 JSON 解读

report.json 结构：

```json
{
  "meta": {"script_version": "8.0", "audit_type": "full", "new_engine": true},
  "summary": {
    "files_scanned": 8, "total_lines": 1500,
    "project_type": "desktop",
    "project_context": {                    // v8.0 新增
      "project_name": "WeChatNotify",
      "internal_namespaces": ["WeChatNotify", "WeChatNotify.Core", ...]
    },
    "issues_by_severity": {"critical": 0, "high": 0, "mid": 0, "low": 16},
    "total_issues": 16,
    "filtered_issues": 3,                  // v8.0 新增
    "filter_reasons": {...},               // v8.0 新增
    "total_raw_issues": 19                 // v8.0 新增
  },
  "scoring": {
    "total_score": 74.8, "total_max": 80,
    "percentage": 93.5, "grade": "S",
    "veto_hit": false, "veto_layers": [],
    "layers": {"ai_hallucination": {"score": 15.0, "max": 15}, ...}
  },
  "release_gate": {
    "decision": "PASS",
    "grade": "S",
    "veto_hit": false,
    "veto_layers": [],
    "reasons": ["未发现致命否决项与遗留文件，达到发布门禁"],
    "artifact_summary": {}
  },
  "release_artifacts": [
    {"file": "/proj/.env", "line": 1, "desc": "提交了环境/密钥配置文件: .env",
     "layer": "product_security", "severity": "high", "confidence": "high",
     "code_snippet": ".env", "suggestion": "..."}
  ],
  "issues": {"critical": [...], "high": [...], "mid": [...], "low": [...]}
}
```

决策逻辑（以 `release_gate.decision` 为准，智能体/CI 直接消费）：
- `decision=BLOCK` 🚫 → 禁止发布（否决命中 / 评分 C / 安全致命层高·严重问题 / 提交私钥或密钥文件）
- `decision=CONDITIONAL` ⚠️ → 有条件发布（评分 B / 存在遗留文件 / 存在 mid 级问题）
- `decision=PASS` ✅ → 可直接发布
- 辅助字段：`veto_hit=true` → 致命层 critical 命中，强制 C 级；`artifact_summary` → 遗留文件按严重度计数

---

## 附录 E：CI/CD 集成

### GitHub Actions

```yaml
name: Code Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Run Audit
        run: |
          python scripts/code_audit_runner.py . -o report.json --output-md report.md
          python -c "
          import json, sys
          with open('report.json') as f: d = json.load(f)
          grade = d['scoring']['grade']
          print(f'Grade: {grade}')
          sys.exit(0 if grade in ('S','A') else 1)
          "
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: audit-report
          path: report.md
```

### GitLab CI

```yaml
code-audit:
  stage: test
  script:
    - python scripts/code_audit_runner.py . -o report.json
    - python -c "import json,sys; d=json.load(open('report.json')); sys.exit(0 if d['scoring']['grade'] in ('S','A') else 1)"
  artifacts:
    paths: [report.json]
```

---

## 附录 F：修复代码示例

### SQL 注入 → 参数化
```python
# ❌ cursor.execute("SELECT * FROM users WHERE id = '%s'" % uid)
# ✅ cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
```

### 密钥硬编码 → 环境变量
```python
# ❌ API_KEY = "sk_live_abc123"
# ✅ API_KEY = os.environ["API_KEY"]
```

### 空 catch → 日志记录
```javascript
// ❌ try { risky(); } catch(e) {}
// ✅ try { risky(); } catch(e) { logger.error("risky failed", e); }
```

### 魔法数字 → 命名常量
```csharp
// ❌ var sb = new StringBuilder(512);
// ✅ const int MaxWindowTitleLength = 512; var sb = new StringBuilder(MaxWindowTitleLength);
```

### MD5 → bcrypt
```python
# ❌ hashlib.md5(password.encode()).hexdigest()
# ✅ bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### CORS 修复
```javascript
// ❌ res.header('Access-Control-Allow-Origin', '*');
// ✅ const allowed = ['https://example.com'];
//    if (allowed.includes(req.headers.origin)) res.header('Access-Control-Allow-Origin', req.headers.origin);
```

### 日志脱敏
```python
# ❌ logger.info(f"Login: {username} password={password}")
# ✅ logger.info(f"Login: {username} password=***")
```

---

## 附录 G：API 安全与许可证合规

| 检测 | 说明 | 严重度 |
|------|------|:---:|
| 认证缺失 | API 端点无认证检查 | high |
| 限流缺失 | 无限流/防刷机制 | mid |
| 输入未校验 | 用户输入直接使用 | high |
| 错误信息泄露 | 返回详细错误堆栈 | mid |
| 敏感数据暴露 | API 返回不必要的敏感字段 | high |

---

## 附录 H：逻辑漏洞检测能力

### Python AST 级检测（v8.5 真实实现，`ast_logic_analyzer.py`）

> 单文件 AST 分析，不追踪跨文件数据流；除「除零字面量」外均为启发式，置信度较低，建议由智能体协同确认。

| 检测项 | 方法 | 严重度 |
|------|------|:---:|
| 除零/取模零 | AST 分析 `x / 0`、`x % 0`（分母为字面量 0） | high |
| None 解引用 | 函数内 `x=None` 后直接 `x.attr`/`x[...]` 且无重赋值 | mid |
| 无限循环 | AST 分析 `while True` 无 `break/return/raise/exit` | mid |
| 资源泄漏 | AST 分析 `open()` 不在 `with` 上下文 | mid |
| 返回类型不一致 | AST 分析函数既返回 None 又返回非 None | low |

### 能力边界

**能检测（AST/正则级）**：已知安全模式 20+ 种 · 代码质量 · 逻辑漏洞 · 上下文感知

**不能检测（需语义/数据流分析）**：竞态条件 · 数组越界 · 业务逻辑错误 · 跨文件数据流

---

## 附录 I：与商业工具对比

| 维度 | 本 Skill (v8.5) | Bandit | Semgrep | SonarQube |
|------|---------|--------|---------|-----------|
| 语言覆盖 | 10 种 | 1 种 | 30+ | 30+ |
| AI 幻觉检测 | ✅ 独创 | ❌ | ❌ | ❌ |
| 生态感知 | ✅ PyPI/npm/NuGet | ❌ | 有限 | ❌ |
| 置信度评分 | ✅ | ❌ | ❌ | ❌ |
| 数据流分析 | ❌ | ❌ | ✅ | ✅ |
| 免费使用 | ✅ | ✅ | ✅ | 社区版 |

**定位**：作为 SAST 工具链的第一道防线 — 快速去噪 + 生态验证，配合重度 SAST 工具进行深度分析。

---

## 附录 J：版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| v6.2 | 初始 | 9 语言静态分析 |
| v7.0 | | 修复正则损坏 · 语法错误 · 补全 JWT/C++/Vue 检测 · 新增自测试 |
| v7.1-7.2 | | 补全已知包 · node: 前缀 · 相对导入排除 · AST 逻辑漏洞 · 资源泄漏检测 |
| v8.0 | 2026-07 | **商业级重建**：PackageResolver（多生态包验证）· SmartDetectors（上下文感知 30+ 模式）· ConfidenceEngine（置信度评分 + 三管过滤）· 真实测试基础设施 · AI 幻觉 high/critical 误报率 → 0% |
| v8.1 | 2026-07 | **发布门禁落地**：修复置信度加权方向反转·实现发布否决机制（致命层+critical→禁发）·新增 ReleaseArtifacts 发布前遗留/调试文件检测·独立 release_gate 裁决（BLOCK/CONDITIONAL/PASS）·自测扩至 44 项 + 单测新增空catch/遗留文件/否决三套·支持智能体协同审查 |
| v8.2 | 2026-07 | **漏洞广度扩展**：经对抗探针验证，将漏报从 7/8 收敛到 0/8，新增 8 类检测器（XSS/命令注入/代码注入/不安全反序列化/路径穿越/SSRF/弱加密/通用硬编码密钥命名），全部 high 级 `owasp_security`/`product_security` 由 `release_gate` 直接 BLOCK；单测增至 9 套 |
| v8.3 | 2026-07 | **复验收口**：密钥检测完整收口 smart_detectors（协同层无盲区）·修复 v8.1 同款 `example` 子串误杀真实密钥陷阱（改以 EXAMPLE 结尾精准豁免）·删除 runner 重复密钥块与死代码·独立对抗探针 + 端到端复验：真实漏洞 0 漏报、正常代码 0 高危误报、AWS 示例密钥正确豁免、漏洞项目 BLOCK、干净项目 PASS |
| v8.4 | 2026-07 | **协同协议固化 + 无误判收口**：新增 `agent_protocol.py` 固化「skill 初筛→LLM 三态确认(CONFIRM/REJECT/SUPPLEMENT)→最终裁决」可复用流水线，CLI 增 `--agent-mode`/`--apply-verdicts`·修复命令/代码注入对**静态字符串**的误报(`_is_dynamic` 剥离字面量再判拼接)·修复 `os.system("clear")`/`eval("1+1")` 误报安全层·对抗探针 漏报 0/11、高危误报 0/12·端到端协同验证通过·支持指定子目录/模块级审查 |
| v8.5 | 2026-07 | **文档落地为真实能力（对齐 LLM 智能体定位）**：① 新增 `ast_logic_analyzer.py` 真实 Python AST 逻辑分析（除零/无限循环/None解引用/open未with/返回类型不一致）② 新增 `dependency_audit.py` 依赖漏洞(SCA)审计（多生态清单解析 + 内置精选 CVE 子集）③ 真正实现 `--whitelist`（文档 v8.4 已写、此前未实现；支持排除文件/目录/层级/正则 + 注入已知包）④ **修复遗留文件双计 bug**：`.env` 等不再同时计入 `issues[]` 与 `release_artifacts`（协同任务不再重复出两条）⑤ 自测扩至 50 项、单测新增 AST/依赖/白名单/不双计四套·明确「skill 本质是为 LLM 智能体设计的确定性门禁 + 协同协议」 |
| v8.6 | 2026-07 | **终审修复补强（商业级权威落地）**：修复 6 项问题——①🔴 `DB_PASSWORD`/`db_password` 硬编码密钥漏检（正则收口）②🟡 白名单未作用于遗留文件扫描（`scan_release_artifacts` 注入 `whitelist`）③🟡 遗留文件 `rglob` 读全量无上限（惰性遍历 + `max_files=300` 硬上限）④💭 删除 `ConfidenceEngine` 规则5 死代码（localhost 误报过滤，潜在漏报地雷）⑤💭 AST 返回类型不一致误标 `return None` 惯用法（`None` 中性化）⑥💭 删除 `is_test_file` 死代码·自测 50/50、单测 14/14 全绿·漏报探针 0 漏报(BLOCK)、误报探针 0 高危误报(PASS) |
| v8.7 | 2026-07 | **协同层审计化（回应商业级三问：不可复现 / 无推理链 / 不可追溯）**：重构 `agent_protocol.py` 至协议 v2.0——①**不可复现有兜底**：致命类(critical/high 且属致命层，或遗留文件 critical/high) REJECT 无 `human_override+override_reason` → 保留为 `challenged`、门禁仍 BLOCK，非复现 LLM 判断无法静默放行真实漏洞；合法 `human_override` 可放宽且理由可追溯 ②**可审计推理链**：每条裁决须 `reasoning`+`evidence`+`confidence`，缺推理判 `invalid` 保守保留 + `needs_human_review`；终态每条发现带 `source`+`llm_reasoning`+`audit_trail` 可逐条质疑 ③**复现契约**：任务清单携 `issues_hash`+`determinism_contract`+`deterministic_evidence`，提示词强制 `temperature=0`+固定 model+回填 `determinism_manifest`；LLM 产出一律标 `requires_human_validation`，裁定权回归人类·诚实边界：确定性层 100% 可复现、LLM 层不宣称可复现、SUPPLEMENT 为「发现未知问题」的唯一通道且需人工复核·新增单测 `test_verdict_audit_and_floor`（端到端验证三场景：全拒无复核仍 BLOCK、全拒+复核可放宽、SUPPLEMENT 标需人工复核）·自测 50/50、单测 15/15 全绿 |
| v8.8 | 2026-07 | **逻辑漏洞闭环（最终商业级终审，确保无逻辑漏洞）**：终审中发现两处方向均不安全的逻辑漏洞并全部闭合——①🔴 **陈旧裁决误放漏洞(H1)**：`apply_verdicts` 检测到 `hash_mismatch` 原只写 `validation.notes` 仍按 ID 套用旧裁决（旧报告 T001=`.env` 带 `human_override` 放行，改码后新报告 T001=SQLi，旧 override 会误删真实 SQLi 致 `PASS`）；修复为 `untrusted` 信号：`hash_mismatch` 时所有 REJECT/SUPPLEMENT 作废，仅保留确定性确认结果，门禁以确定性层为准 ②🔴 **SUPPLEMENT 单方 BLOCK(H2)**：LLM 补抓(high+business_logic)原直接进 `_decide_gate` 不经 `human_override` 就能 unilateral BLOCK，与「LLM 层有界、拍板在人类」自相矛盾且非复现；修复为门禁裁决仅基于确定性确认结果，SUPPLEMENT 绝不自动 BLOCK、只强制升级 `CONDITIONAL`（需人工复核）·协议语义最终收敛（确定性层唯一可自主 BLOCK；LLM 只 CONFIRM/REJECT-需复核/SUPPLEMENT-建议）·新增单测 `test_verdict_robustness_v8_8` + 端到端 CLI 探针（陈旧裁决→BLOCK/untrusted/0 放行；仅 SUPPLEMENT→CONDITIONAL）·自测 50/50、单测 16/16 全绿 |
| v8.9 | 2026-07 | **真实发行淬炼（voicebutler 实战根治命令注入误报）**：把 v8.8 跑在 Rust/Tokio+React/Tauri 桌面项目上，暴露确定性层最刺眼误报——命令注入检测器因含裸 `spawn` 且 `language` 未用于消歧，把 `tokio::spawn(async {...})`(异步任务) 与 `Command::new(...).args([...]).spawn()`(参数向量无 shell) 误判为 HIGH 命令注入（一次性 8 条高危淹没问题）；重写为**语言感知 + 执行原语分类**：仅「shell 解释字符串执行」(`os.system`/`subprocess(shell=True)`/`child_process.exec`/`Runtime.exec`/`sh -c`/`cmd /C`/`powershell -Command`) 且含动态输入才判注入，异步任务/arg-vector 一律不误报；同时精准保留真·shell 执行命中（如 `Command::new("powershell").args(["-Command",&script])`）。实测：voicebutler 同项目 v8.8 HIGH=8(7 误报) → v8.9 HIGH=7(全真实 shell 原语)，误报清零·新增单测 `test_command_injection_language_aware`(17 用例覆盖 Rust/Go/Python/Node/Java)·单测 16/16 → **17/17 全绿** |
| v8.10 | 2026-07 | **最终商业级淬炼（闭环漏报盲区 + 协议逻辑复跑）**：v8.9 终验用对抗探针做**双向**验证时，发现 `_is_dynamic` 在做「剥除字符串字面量」消噪时，会把 `os.system(f"rm -rf {user_input}")`(f-string 插值) 与 `` child_process.exec(`echo ${name}`) ``(JS 模板插值) 这类**字符串内部含外部可控插值**的命令注入整体剥掉、静默放过——属安全工具绝不能有的**漏报(false negative)**；修复为在剥除前先抽验插值标记(`\$\{` 与 `\{[A-Za-z_][^}]*\}`，并排除 dict 字面量/集合)，真注入与静态误报双向均过。同时**复跑验证协议两层逻辑漏洞闭环**：H1 陈旧裁决 `hash_mismatch`→`untrusted`→门禁维持 BLOCK(阻塞 HIGH 不被静默丢弃)；H2 仅 SUPPLEMENT→`CONDITIONAL`(绝不单方 BLOCK)。·新增 f-string/JS 模板插值用例并入 `test_command_injection_language_aware`·单测 **17/17 全绿**(注入 19/19)、自测 **50/50** 无回归、voicebutler 复跑 HIGH=7 误报仍 0、协议闭环探针全 PASS |

---

## 语言覆盖总览

| 语言 | 扩展名 | AST | 包验证 | 检测规则 |
|------|------|:---:|:---:|------|
| Python | .py | ✅ | PyPI + stdlib (150+) | 完整 |
| JavaScript | .js/.jsx/.mjs | ❌ | npm + node_modules | 完整 |
| TypeScript | .ts/.tsx | ❌ | npm + node_modules | 完整 |
| Vue | .vue | ❌ | npm | 模板级 |
| C# | .cs | ❌ | NuGet + .csproj + BCL | 完整 |
| Go | .go | ❌ | go.mod + stdlib | 基础 |
| Rust | .rs | ❌ | Cargo.toml | 基础 |
| C/C++ | .c/.cpp/.h | ❌ | 头文件 | 基础 |
| Java | .java | ❌ | Maven/Gradle | 基础 |
| Kotlin | .kt/.kts | ❌ | Gradle | 基础 |

---

## 注意事项

1. 不跳过任何层 · 不放过任何问题 · 修复先展示方案
2. 合并同类仅展开 Top5
3. 裁剪项标注"已裁剪"
4. AI 幻觉分"待验证"/"已确认"
5. 自动代码不参与质量评分
6. 代码层脚本客观计算 · 功能/运营层 LLM 评估(含依据链)
7. 同版本 → 100% 可重复
8. **报告输出前自检**：逐条检查反误报协议 8 条规则，不符合降级或删除
9. **性能类发现无实测数据 → 自动降级为 💡建议**
10. **优化建议必须评估「会不会更差」→ 会更差则保留现状**

---

**许可证**：MIT License — 可自由使用、修改、分发。
