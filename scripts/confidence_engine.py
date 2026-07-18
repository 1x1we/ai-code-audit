#!/usr/bin/env python3
"""商业级置信度引擎 — 三管输出 · 自动反误报 · 评分修正

v8.1 修复记录：
- 修复置信度加权方向反转：高置信度 ×1.0 全额扣分、低置信度 ×0.3 扣 30%
  （旧实现 effective = base*(1 - factor*0.5) 导致高置信反而扣得更少，与文档相反）
- 实现发布否决机制：致命层 + ≥1 critical → 该层 0 分 + 否决禁发
"""

from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass


@dataclass
class FilteredReport:
    """过滤后的审计报告"""
    strict: List[Dict]     # 所有问题
    normal: List[Dict]     # 去噪后（高/中置信度 + 阻塞级）
    release: List[Dict]    # 仅阻塞级
    filtered_out: int      # 被过滤的问题数
    filter_reasons: Dict[str, int]  # 过滤原因统计


class ConfidenceEngine:
    """置信度评分 + 自动反误报过滤管道"""

    # 致命层：任一 critical 即触发否决（与 SKILL.md 八层审计的 🔴 标记对齐）
    FATAL_LAYERS = {
        "ai_hallucination", "business_logic", "owasp_security",
        "memory_performance", "product_security",
    }

    # ── 反误报过滤规则（自动执行 SKILL.md 反误报协议）──

    # 规则1：已知安全上下文中的数字
    SAFE_NUMBER_ORIGINS = {
        "Color.FromArgb", "Color(", "rgb(", "rgba(", "hsl(",
        "StringBuilder(", "new byte[", "malloc(", "calloc(",
        "Stream.Read", "Stream.Write", "Thread.Sleep",
        "Path.Combine", "Math.",
    }

    # 规则2：框架标准模式 → 非问题
    FRAMEWORK_PATTERNS = {
        "console.log": {"project_types": {"cli", "desktop"}, "reason": "CLI/桌面工具的标准输出"},
        "print(": {"project_types": {"cli", "desktop"}, "reason": "CLI工具的标准输出"},
        "Debug.WriteLine": {"project_types": {"desktop"}, "reason": "桌面应用的调试输出"},
    }

    # 规则3：一次性定时器（setTimeout vs setInterval）
    ONE_SHOT_PATTERNS = {"setTimeout", "ThreadPool.QueueUserWorkItem"}

    def __init__(self, project_type: str = "unknown"):
        self.project_type = project_type
        self._suppress_reasons: Dict[str, int] = {}

    def filter(self, issues: List[Dict], mode: str = "normal") -> FilteredReport:
        """
        三管过滤

        strict: 全部保留
        normal: 去噪（低置信度 + 低严重度 降级移除）
        release: 仅保留 critical + high（阻塞级，且需达到最低置信度）
        """
        strict = list(issues)
        normal = []
        release = []
        filtered = 0

        for issue in issues:
            severity = issue.get("severity", "low")
            confidence = issue.get("confidence", "unknown")

            # ── 执行反误报规则 ──
            if self._is_false_positive(issue):
                self._increment_reason("false_positive_auto")
                filtered += 1
                continue

            # ── normal 管：仅保留高/中置信度 + 严重问题 ──
            is_blocking = severity in ("critical", "high")
            is_confident = confidence in ("high", "medium")

            if is_blocking or is_confident or severity == "mid":
                normal.append(issue)
            else:
                filtered += 1
                self._increment_reason("low_confidence_filtered")

            # ── release 管：仅阻塞级 ──
            if is_blocking and is_confident:
                release.append(issue)

        return FilteredReport(
            strict=strict,
            normal=normal,
            release=release,
            filtered_out=filtered,
            filter_reasons=dict(self._suppress_reasons),
        )

    def _is_false_positive(self, issue: Dict) -> bool:
        """执行反误报协议规则（上下文感知）"""
        desc = issue.get("desc", "")
        layer = issue.get("layer", "")
        code_snippet = issue.get("code_snippet", "")
        confidence = issue.get("confidence", "unknown")

        # 规则1：AI幻觉标记 → 低置信度时视为需人工确认
        if "AI幻觉" in desc or layer == "ai_hallucination":
            if confidence == "unknown":
                self._increment_reason("hallucination_low_confidence")
                return True

        # 规则2：魔法数字在安全上下文中
        if "魔法数字" in desc and code_snippet:
            for safe_origin in self.SAFE_NUMBER_ORIGINS:
                if safe_origin in code_snippet:
                    self._increment_reason(f"magic_number_safe_context:{safe_origin}")
                    return True

        # 规则3：调试输出在合理场景中
        if "调试" in desc or "残留" in desc:
            for pattern, config in self.FRAMEWORK_PATTERNS.items():
                if pattern in code_snippet and self.project_type in config["project_types"]:
                    self._increment_reason(f"debug_allowed:{pattern}")
                    return True

        # 规则4：一次性 setTimeout → 非泄漏
        if "泄漏" in desc or "清除" in desc:
            for pattern in self.ONE_SHOT_PATTERNS:
                if pattern in code_snippet:
                    self._increment_reason(f"one_shot_timer:{pattern}")
                    return True

        return False

    def _increment_reason(self, reason: str):
        self._suppress_reasons[reason] = self._suppress_reasons.get(reason, 0) + 1


def recalculate_score(issues: List[Dict], max_score: float = 80) -> Dict[str, Any]:
    """
    基于置信度重新计算评分（v8.1 修正）

    有效扣分 = 基础扣分(按严重度) × 置信度权重
      高置信度 high  → ×1.0  全额扣分
      中置信度 medium→ ×0.7  扣 70%
      低置信度 low   → ×0.3  扣 30%
      未知     unknown→ ×0.1  几乎不扣分

    否决：致命层（FATAL_LAYERS）+ ≥1 个 critical
         → 该层记 0 分，且整体判级强制为 C（禁止发布）
    """
    weights = {"high": 1.0, "medium": 0.7, "low": 0.3, "unknown": 0.1}
    severity_weights = {"critical": 3.0, "high": 2.0, "mid": 1.0, "low": 0.5}

    layer_max = {
        "ai_hallucination": 15, "code_quality": 8, "business_logic": 15,
        "owasp_security": 15, "memory_performance": 8, "exception_handling": 6,
        "engineering": 5, "product_security": 8,
    }

    layer_deductions = {k: 0.0 for k in layer_max}
    layer_counts = {k: {"critical": 0, "high": 0, "mid": 0, "low": 0} for k in layer_max}

    for issue in issues:
        layer = issue.get("layer", "code_quality")
        severity = issue.get("severity", "low")
        confidence = issue.get("confidence", "low")

        if layer in layer_counts:
            layer_counts[layer][severity] = layer_counts[layer].get(severity, 0) + 1

        # 置信度加权扣分（方向正确：高置信扣更多）
        base_deduction = severity_weights.get(severity, 0.5)
        confidence_weight = weights.get(confidence, 0.1)
        effective_deduction = base_deduction * confidence_weight

        if layer in layer_deductions:
            layer_deductions[layer] = min(
                layer_max[layer], layer_deductions[layer] + effective_deduction
            )

    # 否决机制：致命层出现 critical → 该层 0 分 + 整体否决
    veto_hit = False
    veto_layers = []
    for layer in ConfidenceEngine.FATAL_LAYERS:
        if layer_counts.get(layer, {}).get("critical", 0) > 0:
            veto_hit = True
            veto_layers.append(layer)
            layer_deductions[layer] = layer_max[layer]  # 该层 0 分

    # 计算各层得分
    layer_scores = {}
    total_deduction = 0
    for layer, max_s in layer_max.items():
        deduction = min(layer_deductions[layer], max_s)
        score = max(0, max_s - deduction)
        layer_scores[layer] = {
            "score": round(score, 1),
            "max": max_s,
            "deduction": round(deduction, 1),
            "counts": layer_counts[layer],
        }
        total_deduction += deduction

    total_score = round(max(0, max_score - total_deduction), 1)
    percentage = round(total_score / max_score * 100, 1)

    # 等级判定（与 SKILL.md 对齐）
    if percentage >= 88:
        grade = "S"
    elif percentage >= 75:
        grade = "A"
    elif percentage >= 57:
        grade = "B"
    else:
        grade = "C"

    # 否决强制降级为禁止发布
    if veto_hit and grade != "C":
        grade = "C"

    return {
        "total_score": total_score,
        "total_max": max_score,
        "percentage": percentage,
        "grade": grade,
        "veto_hit": veto_hit,
        "veto_layers": veto_layers,
        "layers": layer_scores,
    }
