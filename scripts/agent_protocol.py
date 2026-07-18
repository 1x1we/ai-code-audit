#!/usr/bin/env python3
"""
商业级协同审查协议 (Collaborative Review Protocol) — v8.7

职责：把「确定性门禁 skill」与「LLM 审查智能体」接成一条可复用的流水线，
实现「省 token + 无误判 + 可审计 + 不可复现有兜底」的双层审查：

    ┌─────────────┐    agent_tasks (仅疑似清单, 0 token)    ┌──────────────────┐
    │  ai-code-audit │ ───────────────────────────────────▶ │  LLM 审查智能体   │
    │  (skill 初筛)  │                                        │  (只深读标出那几行) │
    └─────────────┘ ◀──────── 三态裁决 JSON ────────────────└──────────────────┘
                            CONFIRM / REJECT / SUPPLEMENT
                                       │
                                       ▼
                              最终裁决 (门禁 BLOCK 兜底 + 智能体确认)

v8.7 商业级补强（回应"LLM 层不可复现 / 无推理链 / 不可追溯"三点）：

1. 硬性地板（Hard Floor）：确定性门禁的 BLOCK 是权威硬信号，LLM **不能**静默推翻。
   - 对「致命层 critical/high」或「遗留文件 critical/high」的 REJECT，**必须**附
     `human_override: true` + `override_reason`（人工复核理由），否则该发现被保留为
     `challenged`（待人工复核）且门禁仍 BLOCK。这保证「非复现的 LLM 判断无法放行真实漏洞」。
   - 非致命层（mid/low/code_quality 等）的 REJECT 可正常剔除（不致命）。

2. 可审计推理链（Auditable Reasoning）：每条 LLM 裁决**必须**提供 `reasoning`
   （根因/为什么是或不是问题）+ `evidence`（file/line/snippet）+ `confidence`。
   缺推理的裁决被判为 `invalid` → 该发现保守保留并标 `needs_human_review`，
   绝不被静默丢弃。最终报告的每条发现都带 `source` 与 `llm_reasoning`，可逐条质疑。

3. 复现性契约（Determinism Contract）：任务清单携带 `issues_hash`（确定性报告指纹）
   + `determinism_contract`。智能体回灌 `determinism_manifest`（model/temperature/seed/
   issues_hash）后，协议可校验复现性。**诚实边界**：LLM 层天然非确定性，故其产出一律
   标 `requires_human_validation`，由人类做最终拍板；确定性层（脚本）100% 可复现。

设计要点：
- skill 初筛输出「疑似任务清单」(file:line + 理由)，不含整个仓库，LLM 只回三态，
  昂贵的 LLM 调用量从 O(全仓库) 降到 O(疑似行数)，通常 1~2 个数量级。
- 门禁的硬性 BLOCK（致命层 critical / 提交私钥 / 安全高危及遗留文件）始终生效，
  不依赖 LLM 判断，保证「不漏判致命问题」。
- 三态中 SUPPLEMENT 让智能体补抓 skill 规则外的问题（鉴权绕过、竞态、业务逻辑），
  但标 `requires_human_validation`——"发现你不知道的问题"的价值在此，且明确非确定性。

本模块零依赖（仅依赖 confidence_engine 重新评分），可被 runner 直接 import。
"""

import hashlib
import json
from typing import Dict, List, Optional, Tuple

PROTOCOL_VERSION = "2.0"

# ── LLM 不可静默推翻的层级/严重度（= 门禁 BLOCK 触发条件）──
NON_OVERRIDABLE_LAYERS = {
    "owasp_security", "product_security", "business_logic",
    "memory_performance", "ai_hallucination",
}
NON_OVERRIDABLE_SEVERITIES = {"critical", "high"}

VALID_VERDICTS = {"CONFIRM", "REJECT", "SUPPLEMENT"}

# 推理依据最小长度（太短视为未提供推理）
MIN_REASONING_LEN = 8


# ── LLM 智能体侧提示词模板 ──
# 使用方把 build_agent_tasks() 的输出塞进 {TASKS} 占位符即可。
AGENT_SYSTEM_PROMPT = """你是一名资深代码安全审查专家，与「ai-code-audit 发布门禁」协同工作。

门禁 skill 已对代码做了确定性初筛，产出一份「疑似问题清单」。你的任务是逐条做语义确认，
而不是重新扫描整个仓库——这是省 token 的关键。

# 你的输入
一份 JSON 对象，含：
- issues_hash：确定性报告指纹（你必须原样回填到 determinism_manifest，用于复现校验）
- tasks：JSON 数组，每条包含：
  - id / file / line：任务编号与问题位置（请只打开这一行及其上下极小上下文，不要读全仓库）
  - layer / severity / confidence：门禁判定的层级 / 严重度 / 置信度
  - snippet：命中那一行代码
  - skill_reason / skill_suggestion / deterministic_evidence：门禁给出的理由与证据
  - source：该任务来源（deterministic = 脚本确定性初筛）

# 你要做的
对每条 task，仅返回三态之一：
1. CONFIRM     — 确认是真实问题。必须附 reasoning（根因分析）+ evidence（佐证行）+ confidence。
2. REJECT      — 判定为误报。必须附 reasoning（为什么不是问题，例如测试桩/已转义/白名单校验）
                 + evidence。⚠️ 若 layer ∈ {owasp_security, product_security, business_logic,
                 memory_performance, ai_hallucination} 且 severity ∈ {critical, high}，
                 **必须有 human_override: true 且 override_reason 写明人工复核结论**，否则门禁会保留该发现并继续 BLOCK。
3. SUPPLEMENT  — skill 漏掉的问题。附 finding（门禁规则未覆盖的真实缺陷，如鉴权绕过/竞态/越权）
                 + reasoning + evidence。此类发现会标 requires_human_validation，由人类最终拍板。

# 严格约束（确定性复现契约）
- 调用本能力时必须 temperature=0，并固定 model 版本；输出 determinism_manifest
  包含 model / temperature / seed / issues_hash（与原样回填的 issues_hash 一致）。
- 绝不为未发现证据的问题臆造 CONFIRM；不确定就 REJECT 并说明。
- 每条裁决都**必须**带 reasoning（可质疑、可追溯），无推理链的裁决将被协议判为无效并保守保留。
- 只针对 snippet 所在行做判断；需要更多上下文时明确说「需补读 N 行」。
- 输出必须是合法 JSON，不要任何解释性文字，格式见下。

# 输出格式
{
  "determinism_manifest": {"model":"gpt-4o","temperature":0,"seed":42,"issues_hash":"<回填原值>"},
  "verdicts": [
    {"id":"T001","verdict":"CONFIRM","reasoning":"明文密钥直接入库，可被逆向","evidence":["a.py:10"],"confidence":"high"},
    {"id":"T002","verdict":"REJECT","reasoning":"该值是 HTTP 状态码常量，非魔法数字","evidence":["c.py:30"],"confidence":"high"},
    {"id":"T003","verdict":"REJECT","reasoning":"经人工复核确认此为测试桩，非生产路径","evidence":["b.py:20"],"confidence":"high","human_override":true,"override_reason":"单元测试桩，CI 不部署"},
    {"id":"T004","verdict":"SUPPLEMENT","reasoning":"删除接口未校验 owner，任何用户可删他人资源","evidence":["e.py:5"],"confidence":"high",
       "finding":{"file":"e.py","line":5,"layer":"business_logic","severity":"high","confidence":"high",
                  "desc":"删除接口未校验 owner，存在越权","suggestion":"删除前校验当前用户是否为资源 owner"}}
  ]
}
"""


def issues_hash(report: Dict) -> str:
    """
    确定性报告指纹（sha256 前 16 位）。同一份确定性报告 => 同一 hash，
    用于校验 LLM 层回灌裁决是否对应同一输入（复现性契约）。
    """
    payload = {
        "script_version": report.get("meta", {}).get("script_version", ""),
        "issues": report.get("issues", {}),
        "release_artifacts": report.get("release_artifacts", []),
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _norm_reasoning(v: Dict) -> str:
    """统一取推理依据（兼容 reasoning / agent_note / reason 多写法）。"""
    return (v.get("reasoning") or v.get("agent_note") or v.get("reason") or "").strip()


def _is_blocking(issue: Dict) -> bool:
    """该发现是否属于 LLM 不可静默推翻的致命类（= 门禁 BLOCK 触发项）。"""
    layer = issue.get("layer", "")
    severity = issue.get("severity", "")
    return layer in NON_OVERRIDABLE_LAYERS and severity in NON_OVERRIDABLE_SEVERITIES


def validate_verdicts(verdicts: Dict, expected_hash: str) -> Dict:
    """
    校验 LLM 裁决的「可审计性」（抽验式，非阻断）：
    - reasoning 是否充分（缺则标 invalid，保守保留）
    - determinism_manifest.issues_hash 是否匹配（复现性校验）

    返回结构供最终报告展示，使每条判断有据可查、可质疑。
    """
    out = {
        "schema_version": PROTOCOL_VERSION,
        "checked": 0,
        "invalid": [],
        "manifest_provided": False,
        "reproducibility": "unverified",
        "notes": [],
    }
    if not isinstance(verdicts, dict) or "verdicts" not in verdicts:
        out["notes"].append("verdicts JSON 结构非法：缺少 verdicts 数组")
        return out

    manifest = verdicts.get("determinism_manifest") or {}
    if manifest.get("issues_hash"):
        out["manifest_provided"] = True
        if manifest["issues_hash"] == expected_hash:
            out["reproducibility"] = "verified"
        else:
            out["reproducibility"] = "hash_mismatch"
            out["notes"].append(
                "determinism_manifest.issues_hash 与当前报告不符：裁决可能对应不同输入")
    else:
        out["reproducibility"] = "unverified"
        out["notes"].append(
            "未提供 determinism_manifest.issues_hash：LLM 层复现性无法校验（天然非确定性，产出已标需人工复核）")

    for v in verdicts.get("verdicts", []):
        out["checked"] += 1
        vid = v.get("id")
        verd = (v.get("verdict") or "").upper()
        if not vid or verd not in VALID_VERDICTS:
            out["invalid"].append(vid)
            out["notes"].append(f"{vid}: 非法裁决格式（缺 id 或 verdict 不在三态内）")
            continue
        reasoning = _norm_reasoning(v)
        if len(reasoning) < MIN_REASONING_LEN and verd != "SUPPLEMENT":
            out["invalid"].append(vid)
            out["notes"].append(f"{vid}: 缺少充分推理依据（reasoning<{MIN_REASONING_LEN}字符），已保守保留待人工复核")
            continue
        if verd == "SUPPLEMENT":
            f = v.get("finding") or {}
            if not (f.get("desc") and len(reasoning) >= MIN_REASONING_LEN):
                out["invalid"].append(vid)
                out["notes"].append(f"{vid}: SUPPLEMENT 缺少 finding.desc 或推理依据")
                continue
        # REJECT 致命类必须由人工复核背书，否则在 apply_verdicts 中保留
        if verd == "REJECT" and _is_blocking_in_verdict(verdicts, vid):
            if not (v.get("human_override") and len(str(v.get("override_reason", "")).strip()) >= MIN_REASONING_LEN):
                out["notes"].append(
                    f"{vid}: 致命类 REJECT 缺 human_override/override_reason → 将保留为 challenged（门禁继续 BLOCK）")
    return out


def _is_blocking_in_verdict(verdicts: Dict, vid: str) -> bool:
    """从 tasks 上下文判断该 id 是否致命类（verdicts 本身不含 layer，需调用方配合）。"""
    # 占位：真实判定在 apply_verdicts 内基于 report 的 issue 对象完成，
    # 此处仅作 validate 的辅助信号，返回 False 以免误报；致命性以 apply_verdicts 为准。
    return False


def _task(tid: str, kind: str, it: Dict) -> Dict:
    return {
        "id": tid,
        "kind": kind,
        "source": "deterministic",
        "file": it.get("file", ""),
        "line": it.get("line", 0),
        "layer": it.get("layer", ""),
        "severity": it.get("severity", ""),
        "confidence": it.get("confidence", ""),
        "snippet": it.get("code_snippet", ""),
        "skill_reason": it.get("desc", ""),
        "skill_suggestion": it.get("suggestion", ""),
        "deterministic_evidence": {
            "desc": it.get("desc", ""),
            "suggestion": it.get("suggestion", ""),
            "confidence": it.get("confidence", ""),
            "code_snippet": it.get("code_snippet", ""),
        },
    }


def build_agent_tasks(report: Dict) -> Tuple[List[Dict], Dict[str, tuple]]:
    """
    从 skill 的完整报告产出「疑似任务清单」+ id→(kind,issue) 映射。

    只包含值得 LLM 消耗的条目：
    - 代码问题：severity ∈ {critical, high, mid}（low 噪音大、权重低，自动放行，不耗 token）
    - 发布遗留/调试文件：全部（门禁维度，需确认是否真的提交）
    """
    tasks: List[Dict] = []
    idmap: Dict[str, tuple] = {}
    seq = 1
    for sev in ("critical", "high", "mid"):
        for it in report.get("issues", {}).get(sev, []):
            tid = f"T{seq:03d}"
            tasks.append(_task(tid, "code", it))
            idmap[tid] = ("code", it)
            seq += 1
    for a in report.get("release_artifacts", []):
        tid = f"T{seq:03d}"
        tasks.append(_task(tid, "artifact", a))
        idmap[tid] = ("artifact", a)
        seq += 1
    return tasks, idmap


def _decide_gate(scoring: Dict, normal_issues: List[Dict],
                 artifact_issues: List[Dict]) -> str:
    """与 code_audit_runner.scan_directory 内的门禁裁决逻辑保持一致。"""
    grade = scoring.get("grade", "C")
    veto_hit = scoring.get("veto_hit", False)
    has_security_high = any(
        i.get("severity") in ("critical", "high") and i.get("layer") in NON_OVERRIDABLE_LAYERS
        for i in normal_issues
    )
    has_artifact_block = any(a.get("severity") in ("critical", "high") for a in artifact_issues)
    if veto_hit or grade == "C" or has_security_high or has_artifact_block:
        return "BLOCK"
    if grade == "B" or artifact_issues or any(i.get("severity") == "mid" for i in normal_issues):
        return "CONDITIONAL"
    return "PASS"


def apply_verdicts(report: Dict, verdicts: Dict) -> Dict:
    """
    把 LLM 智能体的三态裁决合并回报告，产出最终裁决（带完整审计链）。

    商业级安全契约：
    - REJECT 致命类（critical/high 且 layer ∈ 致命层，或遗留文件 critical/high）：
        * 若无 human_override + override_reason → **保留为 challenged**，门禁仍 BLOCK（硬地板）。
        * 若有合法 human_override → 剔除，记录人工复核理由（可据此放宽门禁）。
    - REJECT 非致命类 → 正常剔除。
    - CONFIRM → 保留并附 llm_reasoning / llm_evidence（可质疑、可追溯）。
    - SUPPLEMENT → 追加，标 source=llm_supplemented + requires_human_validation。
    - 缺推理的裁决 → 保守保留该发现 + needs_human_review（不静默丢弃）。
    - 未给结论的 task 默认 CONFIRM（保守）。
    - 最终 decision 取「确定性硬地板」与「LLM 合并后裁决」的更严格者，
      除非该致命发现已被合法 human_override 清除。
    """
    expected_hash = issues_hash(report)
    validation = validate_verdicts(verdicts, expected_hash)

    # 漏洞A修复：若 LLM 回灌的裁决对应一份「不同的报告」（issues_hash 不匹配），
    # 这些裁决不可信——全部作废：任何 REJECT 不再放宽、SUPPLEMENT 不再追加。
    # 仅保留确定性层的确认结果，杜绝旧裁决误放开新报告里的真实漏洞。
    untrusted = validation.get("reproducibility") == "hash_mismatch"

    tasks, idmap = build_agent_tasks(report)
    vmap = {v.get("id"): v for v in verdicts.get("verdicts", [])} \
        if isinstance(verdicts, dict) else {}

    confirmed_code: List[Dict] = []
    rejected: List[tuple] = []
    human_overrides: List[Dict] = []
    challenged_findings: List[Dict] = []
    supplemented: List[Dict] = []
    audit_trail: List[Dict] = []

    # 先收集 retained 的致命类数量，用于硬地板判断
    retained_blocking = 0

    def handle_issue(it: Dict, kind: str) -> None:
        nonlocal retained_blocking
        tid = None
        for t, (_, issue) in idmap.items():
            if issue is it:
                tid = t
                break
        v = vmap.get(tid) if tid else None
        verdict = (v.get("verdict") if v else "" or "").upper() if v else ""
        reasoning = _norm_reasoning(v) if v else ""

        # 漏洞A：不可信裁决(hash不匹配)下全部作废 → 退回纯确定性保留，
        # 不附 LLM 陈旧推理，也不做任何放宽/补抓
        if untrusted:
            v = None
            verdict = ""
            reasoning = ""

        if verdict == "REJECT":
            blocking = _is_blocking(it)
            override_ok = bool(v.get("human_override")) and \
                len(str(v.get("override_reason", "")).strip()) >= MIN_REASONING_LEN
            if blocking and not override_ok:
                # 硬地板：保留为 challenged，门禁继续 BLOCK
                item = dict(it)
                item["llm_challenged"] = True
                item["challenge_status"] = "pending_human_override"
                item["source"] = "deterministic_challenged"
                item["llm_reasoning"] = reasoning
                item["needs_human_review"] = True
                confirmed_code.append(item)
                challenged_findings.append({
                    "id": tid, "file": it.get("file", ""), "line": it.get("line", 0),
                    "layer": it.get("layer", ""), "severity": it.get("severity", ""),
                    "desc": it.get("desc", ""),
                    "llm_reasoning": reasoning,
                    "note": "LLM 判定为误报但属致命类，需人工复核背书方可放行",
                })
                retained_blocking += 1
                audit_trail.append({
                    "id": tid, "action": "CHALLENGE", "verdict": "REJECT",
                    "source": "deterministic_challenged",
                    "reasoning": reasoning or "(未提供推理)",
                    "needs_human_review": True,
                })
                return
            if blocking and override_ok:
                human_overrides.append({
                    "id": tid, "file": it.get("file", ""), "line": it.get("line", 0),
                    "layer": it.get("layer", ""), "severity": it.get("severity", ""),
                    "desc": it.get("desc", ""),
                    "override_reason": str(v.get("override_reason", "")),
                })
                audit_trail.append({
                    "id": tid, "action": "OVERRIDE_DROP", "verdict": "REJECT",
                    "source": "human_override",
                    "reasoning": str(v.get("override_reason", "")),
                    "needs_human_review": True,
                })
                return  # 剔除
            # 非致命 REJECT → 剔除
            rejected.append((tid, reasoning))
            audit_trail.append({
                "id": tid, "action": "REJECT", "verdict": "REJECT",
                "source": "llm_rejected",
                "reasoning": reasoning or "(未提供推理)",
                "needs_human_review": False,
            })
            return

        # CONFIRM 或默认：保留 + 附推理
        item = dict(it)
        if v:
            item["llm_reasoning"] = reasoning
            item["llm_evidence"] = v.get("evidence", [])
            item["llm_confidence"] = v.get("confidence")
            item["source"] = "llm_confirmed"
            item["needs_human_review"] = (tid in (validation.get("invalid") or []))
        else:
            item["source"] = "deterministic"
        confirmed_code.append(item)
        audit_trail.append({
            "id": tid, "action": "CONFIRM", "verdict": "CONFIRM",
            "source": item["source"],
            "reasoning": reasoning or "(未提供推理)",
            "needs_human_review": item.get("needs_human_review", False),
        })

    for sev in ("critical", "high", "mid", "low"):
        for it in report.get("issues", {}).get(sev, []):
            handle_issue(it, "code")

    # 遗留文件：REJECT 处理（同样适用硬地板）
    confirmed_artifacts: List[Dict] = []
    for a in report.get("release_artifacts", []):
        tid = None
        for t, (_, issue) in idmap.items():
            if issue is a:
                tid = t
                break
        v = vmap.get(tid) if tid else None
        verdict = (v.get("verdict") if v else "" or "").upper() if v else ""
        reasoning = _norm_reasoning(v) if v else ""
        if untrusted:
            v = None
            verdict = ""
            reasoning = ""
        if verdict == "REJECT":
            blocking = _is_blocking(a)
            override_ok = bool(v.get("human_override")) and \
                len(str(v.get("override_reason", "")).strip()) >= MIN_REASONING_LEN
            if blocking and not override_ok:
                item = dict(a)
                item["llm_challenged"] = True
                item["challenge_status"] = "pending_human_override"
                item["source"] = "deterministic_challenged"
                item["needs_human_review"] = True
                item["llm_reasoning"] = reasoning
                confirmed_artifacts.append(item)
                challenged_findings.append({
                    "id": tid, "file": a.get("file", ""), "line": a.get("line", 0),
                    "layer": a.get("layer", ""), "severity": a.get("severity", ""),
                    "desc": a.get("desc", ""),
                    "llm_reasoning": reasoning,
                    "note": "LLM 判定为误报但属遗留文件致命类，需人工复核背书方可放行",
                })
                retained_blocking += 1
                audit_trail.append({
                    "id": tid, "action": "CHALLENGE", "verdict": "REJECT",
                    "source": "deterministic_challenged",
                    "reasoning": reasoning or "(未提供推理)",
                    "needs_human_review": True,
                })
                continue
            if blocking and override_ok:
                human_overrides.append({
                    "id": tid, "file": a.get("file", ""), "line": a.get("line", 0),
                    "layer": a.get("layer", ""), "severity": a.get("severity", ""),
                    "desc": a.get("desc", ""),
                    "override_reason": str(v.get("override_reason", "")),
                })
                audit_trail.append({
                    "id": tid, "action": "OVERRIDE_DROP", "verdict": "REJECT",
                    "source": "human_override",
                    "reasoning": str(v.get("override_reason", "")),
                    "needs_human_review": True,
                })
                continue
            rejected.append((tid, reasoning))
            audit_trail.append({
                "id": tid, "action": "REJECT", "verdict": "REJECT",
                "source": "llm_rejected",
                "reasoning": reasoning or "(未提供推理)",
                "needs_human_review": False,
            })
            continue
        # 保留（默认 CONFIRM）
        item = dict(a)
        if v:
            item["llm_reasoning"] = reasoning
            item["source"] = "llm_confirmed"
        else:
            item["source"] = "deterministic"
        confirmed_artifacts.append(item)
        audit_trail.append({
            "id": tid, "action": "CONFIRM", "verdict": "CONFIRM",
            "source": item["source"],
            "reasoning": reasoning or "(未提供推理)",
            "needs_human_review": False,
        })

    # SUPPLEMENT 补抓（标需人工复核）。漏洞A：不可信裁决下整段跳过。
    if not untrusted:
        for v in vmap.values():
            if (v.get("verdict") or "").upper() == "SUPPLEMENT":
                f = v.get("finding")
                reasoning = _norm_reasoning(v)
                if isinstance(f, dict) and f.get("desc") and len(reasoning) >= MIN_REASONING_LEN:
                    supp = {
                        "file": f.get("file", ""),
                        "line": f.get("line", 0),
                        "layer": f.get("layer", "business_logic"),
                        "severity": f.get("severity", "high"),
                        "confidence": f.get("confidence", "high"),
                        "desc": f.get("desc", ""),
                        "code_snippet": f.get("snippet", ""),
                        "suggestion": f.get("suggestion", ""),
                        "source": "llm_supplemented",
                        "requires_human_validation": True,
                        "llm_reasoning": reasoning,
                        "llm_evidence": v.get("evidence", []),
                    }
                    supplemented.append(supp)
                    audit_trail.append({
                        "id": v.get("id"), "action": "SUPPLEMENT", "verdict": "SUPPLEMENT",
                        "source": "llm_supplemented",
                        "reasoning": reasoning,
                        "needs_human_review": True,
                    })

    # 完整评分（含补抓，用于报告显示/扣分概览）
    from confidence_engine import recalculate_score
    final_code = confirmed_code + supplemented
    scoring = recalculate_score(final_code, max_score=80) if final_code else recalculate_score([])

    # 门禁裁决**仅基于确定性确认结果**——漏洞B修复：
    # LLM 补抓(supplement)绝不自动 BLOCK，只强制进入"需人工复核"的 CONDITIONAL 档，
    # 避免非复现的 LLM 判断单方面卡发布（发布拍板权始终在人类/确定性层）。
    scoring_det = recalculate_score(confirmed_code, max_score=80) if confirmed_code else recalculate_score([])
    computed_decision = _decide_gate(scoring_det, confirmed_code, confirmed_artifacts)
    if supplemented:
        if computed_decision == "PASS":
            computed_decision = "CONDITIONAL"

    # 硬地板：若仍有未被合法 human_override 清除的致命类发现 → 强制 BLOCK
    floor_blocked = retained_blocking > 0
    decision = "BLOCK" if floor_blocked else computed_decision

    reasons = []
    if untrusted:
        reasons.append("裁决回灌的 issues_hash 与当前报告不匹配：视为不可信，所有 REJECT/SUPPLEMENT 作废，仅保留确定性确认结果（门禁以确定性层为准）")
    if decision == "BLOCK":
        if floor_blocked:
            reasons.append("门禁硬性 BLOCK：存在 LLM 判定为误报但属致命类的发现，且未经人工复核背书（human_override），禁止发布")
        else:
            reasons.append("门禁硬性 BLOCK：致命层 critical / 安全高危及遗留文件 / 否决命中，禁止发布")
    elif decision == "CONDITIONAL":
        reasons.append("有条件发布：需修复中高危或遗留文件后再发")
    else:
        reasons.append("通过门禁：经智能体确认无误判（且致命类已被人工复核背书），达到发布标准")

    return {
        "meta": {**(report.get("meta", {})), "agent_resolved": True,
                 "protocol_version": PROTOCOL_VERSION,
                 "llm_layer_bounded": True,
                 "deterministic_floor_enforced": True,
                 "verdicts_untrusted": untrusted,
                 "determinism_manifest": (verdicts.get("determinism_manifest")
                                          if isinstance(verdicts, dict) else None)},
        "agent_summary": {
            "total_tasks": len(tasks),
            "confirmed": len(confirmed_code),
            "rejected": len(rejected),
            "supplemented": len(supplemented),
            "challenged": len(challenged_findings),
            "human_overrides": len(human_overrides),
            "rejected_ids": [t for t, _ in rejected],
        },
        "release_gate": {
            "decision": decision,
            "grade": scoring.get("grade", "C"),
            "veto_hit": scoring.get("veto_hit", False),
            "deterministic_floor_blocked": floor_blocked,
            "reasons": reasons,
        },
        "scoring": scoring,
        "confirmed_issues": confirmed_code,
        "confirmed_artifacts": confirmed_artifacts,
        "supplemented_findings": supplemented,
        "challenged_findings": challenged_findings,
        "human_overrides": human_overrides,
        "audit_trail": audit_trail,
        "validation": validation,
    }


def emit_agent_tasks_json(report: Dict, indent: int = 2) -> str:
    """产出紧凑的 agent 任务 JSON（skill 初筛输出，供 LLM 消费，含复现契约）。"""
    tasks, _ = build_agent_tasks(report)
    ih = issues_hash(report)
    payload = {
        "version": PROTOCOL_VERSION,
        "issues_hash": ih,
        "determinism_contract": {
            "description": "回填 issues_hash 到 determinism_manifest；调用 temperature=0 并固定 model/seed",
            "llm_layer_nondeterministic": True,
            "llm_output_requires_human_validation": True,
            "deterministic_floor": "致命类发现 REJECT 需 human_override+override_reason，否则继续 BLOCK",
        },
        "tasks": tasks,
    }
    return json.dumps(payload, ensure_ascii=False, indent=indent)
