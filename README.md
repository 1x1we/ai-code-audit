# AI 代码商业级发布门禁审查 (ai-code-audit)

> **定位**：产品发布前最后一道质量门禁。为 LLM 智能体提供「确定性初筛 + 审计化协同协议」，输出可直接用于发布决策的量化评分报告与分阶段修复路线图。

![规则版本](https://img.shields.io/badge/规则版本-v8.13-blue) ![脚本版本](https://img.shields.io/badge/脚本版本-v8.13-blue) ![Python](https://img.shields.io/badge/python-3.11%2B-green) ![License](https://img.shields.io/badge/license-MIT-green)

---

## 一、一句话说清楚

`ai-code-audit` 是一个**给 LLM 智能体使用的代码审计技能**：先用纯 Python 脚本对项目做毫秒级、零 Token 的确定性初筛，产出结构化报告；再由智能体对疑似问题做语义级三态确认（CONFIRM / REJECT / SUPPLEMENT）；最终给出 `BLOCK / CONDITIONAL / PASS` 的发布门禁结论。它不是要替代人类或重级 SAST 工具，而是要做**发布前最后一道可复现、可审计、可集成的质量门禁**。

---

## 二、解决什么痛点（商业价值）

### 痛点 1：AI 生成代码快，但「能不能发」没人敢拍板

AIGC / Cursor / Copilot 让代码产出速度提升数倍，但生成的代码往往带着：
- 硬编码密钥（`API_KEY = "sk-..."`）
- SQL 拼接注入
- 不安全反序列化（`pickle.loads` / `yaml.load`）
- 空 catch / 资源泄漏
- 调试残留直接进生产

**结果**：功能能跑，但发布前需要人逐行Review，成本高、周期长、标准不统一。

**价值**：`ai-code-audit` 把「能不能发」变成可量化、可自动化的门禁决策。跑一遍就给出评分、等级、阻塞项和修复路线图，发布决策从「主观拍脑袋」变成「客观看报告」。

### 痛点 2：纯 LLM 审查贵、慢、不可复现

让 GPT/Claude 直接读整个仓库做安全审查：
- **贵**：一次完整审查动辄几十万 Token，中大型项目成本不可接受。
- **慢**：需要多轮上下文，无法嵌入 CI。
- **不可复现**：同样代码两次审查结论可能不同，CI 无法直接当作硬门禁。
- **幻觉**：容易把项目内部库、Python 标准库、框架 API 误判为问题。

**价值**：本 skill 把 LLM 从「全仓库扫描」降级为「只读疑似问题行」，Token 成本下降 1~2 个数量级；同时脚本层 100% 可复现，CI 可以直接消费 `release_gate.decision`。

### 痛点 3：传统 SAST 工具误报率高，需要大量人工过滤

Bandit、Semgrep、SonarQube 等工具能发现模式化问题，但：
- 对多语言项目配置繁琐；
- 对 `Color.FromArgb(7, 193, 96)` 这类安全上下文报魔法数字；
- 对 CLI 工具的 `print()` 报调试残留；
- 对 Rust `tokio::spawn` 报命令注入；
- 对项目内部库报 AI 幻觉。

**价值**：本 skill 内置**上下文感知检测器**（SmartDetectors）和**包生态验证引擎**（PackageResolver），对上述典型误报做自动去噪。在 WeChatNotify（C# WPF）和 BearHelper（Python CLI）实测中，AI 幻觉误报从 v7.2 的 4~20 条降至 **0 条**。

### 痛点 4：安全审查结论无法被审计和质疑

很多 AI 审查工具输出一段文字，没有代码行号、没有证据链、没有置信度，出了问题无法追溯。

**价值**：本 skill 每条发现都带 `file:line`、`code_snippet`、`confidence`、`suggestion`、`source`；LLM 协同裁决必须提供 `reasoning` + `evidence` + `confidence`，且致命类问题必须人工复核才能放行。审计、合规、安全团队可以逐条质疑。

---

## 三、核心能力（v8.13 真实实现）

| 能力 | 说明 | 是否已真实实现 |
|------|------|:---:|
| **多语言扫描** | Python / JS / TS / Vue / C# / Go / Rust / C/C++ / Java / Kotlin | ✅ |
| **包生态验证** | Python stdlib、PyPI、npm、node_modules、C# BCL / NuGet、Go / Rust 模块 | ✅ |
| **上下文感知** | 魔法数字安全上下文、CLI 调试残留豁免、空 catch 注释识别、参数化 SQL 排除 | ✅ |
| **8 类安全注入** | SQL 注入、XSS、命令注入、代码注入、路径穿越、SSRF、不安全反序列化、弱加密 | ✅ |
| **密钥硬编码** | `sk-*`、AWS AKIA、通用命名 `DB_PASSWORD` / `API_KEY` 等 | ✅ |
| **Python AST 逻辑分析** | 除零、open 未 with、无限循环、None 解引用、返回类型不一致 | ✅ |
| **依赖漏洞 SCA** | requirements.txt / package.json / go.mod / Cargo.toml / pom.xml 解析 + 精选 CVE 库 | ✅ |
| **发布前遗留文件** | `.env`、`.pem`、`.key`、`.js.map`、`.bak`、超大二进制等 | ✅ |
| **同文件内污点传播** | `TaintContext` 逐文件追踪 tainted/guarded/clean 三态，根治「守卫在前 / 外部输入不进 sink」类误报（v8.13） | ✅ |
| **TSX/JSX 魔法数字豁免** | 跳过 Tailwind 类名 / framer-motion / style 对象 / 引号串等样式噪声，仅报代码逻辑数字（v8.13） | ✅ |
| **置信度评分** | 高/中/低置信度加权，80 分制 S/A/B/C 等级 | ✅ |
| **发布门禁** | `BLOCK` / `CONDITIONAL` / `PASS` 三态硬决策 + 致命类硬地板兜底 | ✅ |
| **三层协同协议** | 技能确定性初筛 + 智能体三态审查（CONFIRM/REJECT/SUPPLEMENT）+ 人工查看，复现契约 `issues_hash`（v8.13） | ✅ |
| **白名单** | 文件/目录/层级/正则排除、已知包注入 | ✅ |
| **模块级审查** | 传入子目录即可只审该模块 | ✅ |

---

## 四、为什么 AI 智能体有审查能力，还需要这个 skill？

这是用户最常问的问题。答案是：**LLM 很强，但单独做发布门禁不够安全、不够经济、不够稳定**。本 skill 不是要和 LLM 竞争，而是给 LLM 智能体一个**可复用的确定性底盘**。

### 1. 确定性 vs 非确定性

- **脚本层（本 skill）**：纯 Python 正则 + AST，相同输入 100% 输出相同结果。CI 可以直接 `if release_gate.decision == 'BLOCK': fail()`。
- **LLM 层**：大模型天然非确定性。即使 `temperature=0`，模型升级、prompt 微调都会改变结论。让 LLM 直接决定「能不能发布」是商业风险。

**本 skill 的边界**：确定性层负责「已知模式化缺陷」的兜底；LLM 层负责「语义确认 + 补抓规则外缺陷」，但致命类放行必须人工复核。

### 2. 成本 vs 覆盖

- 全仓库 LLM 审查：几万~几十万 Token。
- 本 skill 初筛：0 Token。
- 智能体只读疑似行：通常只有几十到几百行，Token 成本下降 1~2 个数量级。

### 3. 标准化 vs 自由发挥

没有 skill 时，每个智能体都要自己决定：
- 扫描哪些文件？
- 严重度怎么分？
- 误报怎么排除？
- 报告格式是什么？

本 skill 输出统一 JSON：`issues[]`、`release_gate`、`scoring`、`release_artifacts`。智能体不用重复造轮子，直接消费结构化结果。

### 4. 反幻觉 vs 裸 LLM 误判

LLM 会把项目内部库、Python 标准库、框架 API 误判为「未知导入」。本 skill 内置 `PackageResolver`，自动识别 150+ Python stdlib、npm 已安装包、C# BCL 等，先把误报消掉，再让 LLM 做有价值的工作。

### 5. 审计 vs 黑盒

裸 LLM 说「这行没问题」，你问它为什么，它可能给出一段看似合理的解释。本 skill 要求 LLM 裁决必须有 `reasoning` + `evidence` + `confidence`；致命类 REJECT 必须有人工复核理由。所有判断可追溯、可质疑。

**总结**：智能体是「大脑」，本 skill 是「底盘 + 安全带 + 仪表盘」。大脑决定路线，但刹车和限速必须确定可复现。

---

## 五、Token 消耗大不大？

**直接回答：基础扫描 0 Token；协同模式极省 Token。**

### 1. 纯脚本扫描（`python scripts/code_audit_runner.py <项目>`）

- **0 LLM Token**。
- 运行时间：毫秒~秒级（取决于项目大小）。
- 输出：`report.json` + `report.md`。
- 适用：CI 硬门禁、每次提交自动跑、日常自检。

### 2. 协同初筛（`--agent-mode`）

- **0 LLM Token**。
- 只输出疑似问题清单 `tasks.json`，供 LLM 智能体确认。
- 清单已经过去噪，只包含中高危问题，行数通常远小于全仓库。

### 3. LLM 三态确认

这是唯一消耗 Token 的环节。但与传统「全仓库 LLM 审查」相比：

| 方式 | 单次审查 Token | 说明 |
|------|------|------|
| 全仓库 LLM 审查 | 50K~500K+ | 读所有源码、文件结构、依赖 |
| 本 skill + LLM 协同 | 1K~20K | 只读 `tasks.json` 中的 `file:line` + `code_snippet` |

**为什么省？** 因为脚本已经把 90% 以上的噪音去掉了。LLM 只读它该读的地方。

### 4. 实际估算

以 voicebutler（Rust + React + Go，约 6K 行代码）为例：
- 脚本扫描：~1 秒，0 Token，产出 7 个 HIGH 级命令注入 + 3 个 MID 路径穿越 + 若干 low 级问题。（注：v8.13 同文件污点传播会把「守卫在前」的命令注入 sink 降级为 LOW，真实 RCE 仍保持 HIGH，故实测 HIGH 数会低于此基线，但真实漏洞零漏报。）
- LLM 协同：只读这 10 余条疑似问题的上下文，预计 Token 在数千量级。
- 全仓库 LLM 审查：预计需要数万 Token。

**结论**：对预算敏感、需要高频审查的团队，本 skill 是更经济的方案。

---

## 六、快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/your-org/ai-code-audit.git
cd ai-code-audit

# 2. 运行自测（验证环境，50 项）
python scripts/code_audit_runner.py --self-test

# 3. 审查项目（标准模式，自动去噪）
python scripts/code_audit_runner.py /path/to/project -o report.json --output-md report.md

# 4. 查看门禁结论
cat report.json | python -c "import json,sys; print(json.load(sys.stdin)['release_gate'])"
```

### 协同模式（三步）

```bash
# ① 脚本初筛，产出疑似任务清单（0 Token）
python scripts/code_audit_runner.py /path/to/project \
  --agent-mode --agent-tasks-out tasks.json

# ② 把 tasks.json 交给 LLM 智能体做三态确认（CONFIRM / REJECT / SUPPLEMENT）
#    输出 verdicts.json

# ③ 合并裁决，产出最终发布结论
python scripts/code_audit_runner.py /path/to/project \
  --apply-verdicts verdicts.json -o final.json
```

### CI 集成示例（GitHub Actions）

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
          d = json.load(open('report.json'))
          print('Grade:', d['scoring']['grade'])
          print('Gate:', d['release_gate']['decision'])
          sys.exit(0 if d['release_gate']['decision'] == 'PASS' else 1)
          "
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: audit-report
          path: report.md
```

---

## 七、架构：确定性层 + 智能体协同层 + 人工查看（三层）

```
┌─────────────────────────────────────────────────────────────┐
│                        用户项目                              │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│  【第一层 · 技能专家辅助（确定性，0 Token，可复现）】            │
│  阶段 0：项目发现 + 类型识别                                    │
│  阶段 1：脚本初筛（正则 + AST + 依赖解析 + 同文件污点传播）      │
│  · PackageResolver（多生态包验证）                              │
│  · SmartDetectors（上下文感知，自动去噪）                       │
│  · TaintContext（同文件内污点追踪：tainted/guarded/clean）      │
│  · ASTLogicAnalyzer（Python 单文件逻辑）                        │
│  · DependencyAudit（SCA 依赖漏洞）                             │
│  · ReleaseArtifacts（遗留文件）                                │
│  · ConfidenceEngine（置信度加权 + 三管过滤）                     │
│  产出：report.json（每条约 code_snippet/confidence/taint_state）│
└──────────────┬──────────────────────────────────────────────┘
               │  report.json / tasks.json（疑似清单）
               ▼
┌─────────────────────────────────────────────────────────────┐
│  【第二层 · 智能体审查（LLM 三态确认）】                        │
│  · CONFIRM   → 确认真实问题                                   │
│  · REJECT    → 判定误报（致命类需 human_override + 理由）       │
│  · SUPPLEMENT → 补抓规则外问题（不直接 BLOCK）                  │
│  · 审计链：reasoning + evidence + confidence + issues_hash     │
└──────────────┬──────────────────────────────────────────────┘
               │  verdicts.json
               ▼
┌─────────────────────────────────────────────────────────────┐
│  【第三层 · 人工查看（最终裁决与发布拍板）】                    │
│  · 所有 skill/agent 结论均可在报告溯源                          │
│  · 致命类 REJECT 必须人工复核背书，否则硬地板继续 BLOCK         │
│  · release_gate.decision = BLOCK / CONDITIONAL / PASS         │
└─────────────────────────────────────────────────────────────┘
```

> **三层职责边界**：技能是「确定性底盘 + 安全带」，负责已知模式化缺陷兜底与零 Token 初筛；智能体是「语义大脑」，只审疑似行并附推理链；人类是「最终拍板者」，发布门禁的放行权永远在人。三层通过 `issues_hash` 复现契约串联，确定性层始终兜底，陈旧裁决自动作废。

---

## 八、发布门禁三态

| 决策 | 含义 | 触发条件 |
|------|------|----------|
| `BLOCK` 🚫 | 禁止发布 | 致命层 critical / 安全/致命层存在 high（非本地、污点未消除、智能体未 REJECT）/ 提交私钥或密钥文件 |
| `CONDITIONAL` ⚠️ | 有条件发布 | 评分 B / 存在遗留文件 / 存在 mid 级问题 / 有 SUPPLEMENT 需复核 |
| `PASS` ✅ | 可发布 | 无上述任何项 |

**门禁口径三合一（确定性保证）**：脚本内联门禁、`decide_gate_with_agent`、`_decide_gate` 三套逻辑使用完全相同的 `NON_OVERRIDABLE_LAYERS` / `NON_OVERRIDABLE_SEVERITIES`，杜绝漂移。

**污点降级**：命令注入 / 路径穿越 sink 若经 `TaintContext` 判定为 `clean`（本地/常量构造，如 `std::env::temp_dir()`）或 `guarded`（经 `pathAllowed`/`escape` 等守卫）则降级为 LOW 或跳过，不触发 BLOCK——这是 v8.13 根治 voicebutler「守卫在前」类误报 BLOCK 的核心机制。

**硬地板（致命类不可被静默推翻）**：智能体对致命类发现 REJECT 时，必须携带 `human_override=true` + `override_reason`，否则确定性层仍判定 `BLOCK`；换言之，**没有合法人工背书，致命类发现永远拦住发布**。复现契约 `issues_hash` 校验防止陈旧裁决蒙混过关。

---

## 九、评分卡（80 分制）

| 层级 | 满分 | 性质 |
|------|:----:|------|
| AI 幻觉 | 15 | 致命 |
| 代码质量 | 8 | 普通 |
| 业务逻辑 | 15 | 致命 |
| OWASP 安全 | 15 | 致命 |
| 内存性能 | 8 | 致命 |
| 异常容错 | 6 | 普通 |
| 工程化 | 5 | 普通 |
| 产品攻防 | 8 | 致命 |
| **总计** | **80** | |

| 等级 | 分数区间 | 含义 |
|:----:|:--------:|------|
| S | ≥ 88% | 可直接发布 |
| A | 75-88% | 修复低危后发布（1-3 天） |
| B | 57-75% | 修复中高危后发布（1-2 周） |
| C | < 57% | 禁止发布 |

---

## 十、适用场景

| 场景 | 为什么适合 |
|------|------------|
| **AI 生成代码项目** | 快速识别 AIGC 常见的密钥、注入、反序列化问题 |
| **发布前门禁** | 给出 `BLOCK / CONDITIONAL / PASS` 硬决策 |
| **CI/CD 集成** | 0 Token、可复现，直接卡门禁 |
| **PR 审查** | 只改一个模块？只扫该模块，Token 更省 |
| **安全合规审计** | 每条发现带证据链、可追溯 |
| **多语言团队** | 一套规则覆盖 Python/JS/C#/Go/Rust 等 |

---

## 十一、诚实边界与已知局限

我们坚持不虚假宣传。以下是本 skill 不擅长、需要配合其他工具或人工处理的场景：

| 局限 | 示例 | 建议 |
|------|------|------|
| 跨文件数据流 | `query = "..."; execute(query)` 无法追踪拼接来源 | 结合 SonarQube / Semgrep / CodeQL |
| 复杂业务逻辑 | 越权、竞态、事务边界 | 必须人工 + 领域专家审查 |
| 完整 SCA 数据库 | 内置只有精选 CVE 子集 | 配合 `pip-audit` / `npm audit` / OSV-Scanner |
| 跨函数分析 | 变量在分支中重赋值 | 单文件 AST 会保守降级置信度 |
| 数组越界 / 类型错误 | 需符号执行或类型系统 | 使用编译器 / 类型检查器 |

**定位重申**：本 skill 是 SAST 工具链的**第一道防线**——快速去噪、生态验证、发布门禁。深度语义分析仍需重级 SAST 和人工审计。

---

## 十二、验证与测试

所有宣称的能力都有真实可运行测试验证：

| 测试 | 数量 | 命令 |
|------|:----:|------|
| 脚本自测试 | 50 项 | `python scripts/code_audit_runner.py --self-test` |
| 核心单元测试 | 28 套 | `cd tests && python test_core.py` |

> **v8.13 验证覆盖（关键回归用例）**：
> - 同文件污点三态（tainted/guarded/clean）+ `resolve` 判定；
> - 命令注入污点降级：本地/已守卫 shell 参数 → LOW（可审计不静默丢弃），真实外部输入 → HIGH，无 `taint_ctx` 时保持 HIGH 兼容；
> - 路径穿越：守卫在前 → LOW，未守卫外部输入 → MID，纯本地 → 跳过；
> - **match 臂绑定非参数（v8.13 修复回归）**：Rust `Some(v) =>` 不再误当函数参数污染命令注入；JS 箭头函数参数仍正确捕获；
> - TSX/JSX 魔法数字豁免：样式噪声跳过、逻辑比较仍报；
> - 三层协同门禁：智能体 REJECT（含人工背书）→ 放行；无人工背书 → 硬地板继续 BLOCK。
>
> **端到端合成验证**：`_e2e_vb/tts.rs`（voicebutler 风格）经完整 runner 审计——
> 真实 RCE（`Command::new("sh").arg("-c").arg(text)`，`text` 为函数参数）→ HIGH → 门禁 **BLOCK**；
> 本地 `temp_dir` 拼接的 `pwsh` 调用 → **不再误报**（根治 v8.9 以来误 BLOCK）；
> 三层协同链路 skill(BLOCK) → 智能体 REJECT + 人工 override → 合并门禁 **PASS** 全验证通过。

### 真实项目实测

| 项目 | 类型 | AI 幻觉误报 | 评分 |
|------|------|:---:|:---:|
| WeChatNotify | C# WPF 桌面应用 | 0 | S 94% |
| BearHelper | Python CLI 工具集 | 0 | B 70% |
| voicebutler | Rust/Tauri + Go 桌面应用 | 0 | B 57% |

---

## 十三、版本演进（v8.13）

- **v8.0**：商业级重建，多生态包验证 + 上下文感知 + 置信度评分。
- **v8.1**：发布门禁落地（否决机制、置信度方向修正、遗留文件检测）。
- **v8.2**：新增 8 类注入/反序列化/穿越检测，漏报从 7/8 收敛到 0/8。
- **v8.3**：密钥检测完整收口，修复 `example` 子串误杀真实密钥。
- **v8.4**：协同协议固化，LLM 三态确认（CONFIRM/REJECT/SUPPLEMENT）。
- **v8.5**：文档落地为真实能力（Python AST、依赖 SCA、白名单）。
- **v8.6**：终审修复补强（DB_PASSWORD 漏检、白名单作用于遗留文件、死代码清理）。
- **v8.7**：协同层审计化（不可复现有兜底、可审计推理链、复现契约）。
- **v8.8**：逻辑漏洞闭环（陈旧裁决作废、SUPPLEMENT 不单方 BLOCK）。
- **v8.9**：真实项目淬炼（voicebutler），根治 Rust/Tokio 命令注入误报。
- **v8.10**：最终闭环 f-string / JS 模板插值漏报，协议逻辑复跑验证全绿。
- **v8.11**：端口硬编码检测增强（独立可审查发现项）、H7 误报根治、命令注入按真实危害细分 RCE/任意文件读/写删、门禁吸收反误报规则4（localhost 降级人工复核）。
- **v8.12**：端口硬编码检测升级为独立发现类，22 项测试全绿。
- **v8.13（商业权威级）**：同文件内污点传播 `TaintContext`（tainted/guarded/clean 三态，根治「守卫在前 / 外部输入不进 sink」类误报 BLOCK）；TSX/JSX 魔法数字豁免（仅报代码逻辑数字）；三层协同协议（技能专家辅助 + 智能体审查 + 人工查看），三套门禁口径合一 + 致命类硬地板；单元测试 28/28，自测试 50/50，真实 RCE 零漏报 + 误报零。

---

## 十四、许可证

MIT License — 可自由使用、修改、分发。

---

## 十五、联系与贡献

如果你发现误报、漏报，或有新的检测需求，欢迎提交 Issue 或 PR。我们尤其欢迎基于真实项目的淬炼反馈——正是 voicebutler 这样的真实项目，让 v8.9/v8.10 的命令注入检测达到了商业级可用标准。

---

## 十六、一键发布到 GitHub

仓库根目录已内置 `publish.bat`，**在本机双击即可一键推送**（无需记命令）：

1. 确保本机已安装 Git 且已登录 GitHub（凭据助手已缓存 token / 已配置 SSH）。
2. 双击 `publish.bat`。
3. 脚本自动：检查工作树是否干净 → 缺失则补建 `origin` 远程 → 本地分支改名 `main` → `git push -u origin main --force-with-lease`。
4. 窗口显示 `PUBLISH OK` 即成功；若显示 `PUSH FAILED` 多为 GitHub 登录/token 问题，按提示处理即可。

> 说明：`--force-with-lease` 会用本地 v8.13 覆盖 GitHub 上旧的 v8.10 提交历史（二者无共同祖先），属于预期的"重新上传"。脚本为纯 ASCII + CRLF + 无 BOM，规避 Windows bat 中文路径一闪而过的经典坑。
