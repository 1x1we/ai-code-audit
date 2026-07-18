#!/usr/bin/env python3
"""Python AST 逻辑漏洞分析器（v8.5 新增）— 真实 AST 级检测，非正则推断。

覆盖（单文件内，无跨文件数据流）：
- 除零 / 取模零：BinOp(Div|Mod, 右操作数为字面量 0) → high（确定性）
- while True 无 break/return/raise：潜在无限循环 → mid（AST 确认）
- 返回类型不一致：函数混合返回 ≥2 种非 None 类型（如 int 与 str）→ low（代码异味）；
  None 视为中性（return None 是 Python 最常见的提前返回/默认返回惯用法，不标记，避免误报）
- None 解引用：函数内 name=None 后直接 name.attr/name[...] 且其间无重赋值 → mid（启发式，低置信）
- open() 未使用 with：资源句柄泄漏 → mid（替代旧正则，更准）

注意：这是「语法/控制流」层面的检测，不追踪跨函数/跨文件的数据流，
也不做符号执行。变量在某分支被重赋值等复杂场景可能漏报或误报，
故除「除零字面量」外均给出较低严重度/置信度，交由智能体协同确认。
"""

import ast
from typing import Dict, List, Set, Optional

_CONF_HIGH = "high"
_CONF_MED = "medium"
_CONF_LOW = "low"


def _mk(file_path: str, line: int, desc: str, layer: str, severity: str,
        confidence: str, suggestion: str, code: str = "") -> Dict:
    return {
        "file": file_path, "line": line, "desc": desc,
        "layer": layer, "severity": severity, "confidence": confidence,
        "code_snippet": code or desc[:120], "suggestion": suggestion,
    }


def _safe_unparse(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _is_zero_literal(node) -> bool:
    return (isinstance(node, ast.Constant)
            and isinstance(node.value, (int, float))
            and node.value == 0)


def _is_true_constant(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_none(node) -> bool:
    return (isinstance(node, ast.Constant) and node.value is None) or (
        isinstance(node, ast.NameConstant) and node.value is None)


def _is_open_call(node) -> bool:
    f = getattr(node, "func", None)
    if isinstance(f, ast.Name):
        return f.id == "open"
    if isinstance(f, ast.Attribute):
        return f.attr == "open"
    return False


def analyze_python_ast(content: str, file_path: str) -> List[Dict]:
    """对单个 .py 文件做 AST 分析，返回 issue 列表（空列表表示无发现/解析失败）。"""
    issues: List[Dict] = []
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return issues

    # 1) 除零 / 取模零（字面量 0 分母，确定性 high）
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Mod)):
            if _is_zero_literal(node.right):
                op = "/" if isinstance(node.op, ast.Div) else "%"
                issues.append(_mk(
                    file_path, node.lineno,
                    f"除零/取模零风险：表达式含 `{_safe_unparse(node.left)} {op} 0`",
                    "business_logic", "high", _CONF_HIGH,
                    "分母字面量为 0，运行时会抛出 ZeroDivisionError。",
                    "在运算前校验分母非零，或对可能为 0 的分母做兜底处理。",
                ))

    # 2) while True 潜在无限循环（无退出路径）
    for node in ast.walk(tree):
        if isinstance(node, ast.While) and _is_true_constant(node.test):
            has_break = any(isinstance(n, ast.Break) for n in ast.walk(node))
            has_return = any(isinstance(n, ast.Return) for n in ast.walk(node))
            has_raise = any(isinstance(n, ast.Raise) for n in ast.walk(node))
            has_exit = any(
                isinstance(n, ast.Call) and isinstance(getattr(n, "func", None), ast.Attribute)
                and n.func.attr in ("exit", "quit")
                for n in ast.walk(node)
            )
            if not (has_break or has_return or has_raise or has_exit):
                issues.append(_mk(
                    file_path, node.lineno,
                    "潜在无限循环：while True 循环体内无 break / return / raise / exit",
                    "business_logic", "mid", _CONF_MED,
                    "循环缺少退出路径，运行时会永久阻塞当前线程。",
                    "确认是否需要退出条件；若是有意的服务循环，应保留显式退出（如信号处理 break / sys.exit）。",
                ))

    # 3) open() 的安全集合：在 with 项上下文中的 open 调用
    open_calls_safe: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                ce = item.context_expr
                if isinstance(ce, ast.Call) and _is_open_call(ce):
                    open_calls_safe.add(id(ce))

    # 4) 函数级分析
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check_return_types(node, file_path, issues)
            _check_none_deref(node, file_path, issues)

    # 5) open() 未 with：整模块遍历（覆盖模块级 + 函数内）
    _check_open_calls(tree, file_path, issues, open_calls_safe)

    return issues


def _infer_return_type(node) -> Optional[str]:
    """粗略推断返回表达式的顶层类型（仅用于不一致检测，非数据流分析）。

    返回粗粒度类型标签；无法归类返回 None（不计入不一致判定）。
    """
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return "bool"
        if isinstance(node.value, (int, float)):
            return "number"
        if isinstance(node.value, str):
            return "str"
        return None  # None / 其他字面量视为中性
    if isinstance(node, ast.List):
        return "list"
    if isinstance(node, ast.Tuple):
        return "tuple"
    if isinstance(node, ast.Set):
        return "set"
    if isinstance(node, ast.Dict):
        return "dict"
    if isinstance(node, ast.Name):
        return f"var:{node.id}"  # 变量名作粗粒度类型提示
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Name):
            return f"call:{f.id}"
        if isinstance(f, ast.Attribute):
            return f"call:{f.attr}"
    # 条件表达式 / 其它复杂形式：难以静态判定，跳过以免误报
    return None


def _check_return_types(func, file_path: str, issues: List[Dict]) -> None:
    """检测函数返回类型不一致。

    仅当函数混合返回 ≥2 种**非 None** 类型时才标记（如 int 与 str）。
    `return None` 是 Python 最常见的提前返回 / 默认返回惯用法，视为中性，
    不计入判定，从而避免对正常代码的大量误报。
    """
    return_types: Set[str] = set()
    for n in ast.walk(func):
        if isinstance(n, ast.Return) and n.value is not None:
            t = _infer_return_type(n.value)
            if t:
                return_types.add(t)
    if len(return_types) >= 2:
        types_str = " / ".join(sorted(return_types))
        issues.append(_mk(
            file_path, func.lineno,
            f"函数 {func.name} 返回类型不一致（混合返回 {types_str}）",
            "business_logic", "low", _CONF_MED,
            "同一函数混合返回多种非 None 类型，调用方易触发类型错误。",
            "统一返回类型，或用 Union/Optional[T] 并在调用处显式处理。",
        ))


def _check_none_deref(func, file_path: str, issues: List[Dict]) -> None:
    """函数内线性近似：name=None 之后、重赋值之前直接 .attr/[] 访问 → 标记。"""
    none_bound: Set[str] = set()
    for stmt in func.body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Assign):
                for tgt in sub.targets:
                    if isinstance(tgt, ast.Name):
                        if _is_none(sub.value):
                            none_bound.add(tgt.id)
                        else:
                            none_bound.discard(tgt.id)
            if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                if sub.value.id in none_bound:
                    issues.append(_mk(
                        file_path, sub.lineno,
                        f"可能的 None 解引用：{sub.value.id}.{sub.attr}（{sub.value.id} 此前被赋值为 None）",
                        "business_logic", "mid", _CONF_LOW,
                        "在赋值 None 后直接访问其属性，可能触发 AttributeError。",
                        "访问前判空，或确保该变量在使用前已被赋予非 None 值。",
                    ))
                    none_bound.discard(sub.value.id)
            if isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name):
                if sub.value.id in none_bound:
                    issues.append(_mk(
                        file_path, sub.lineno,
                        f"可能的 None 下标访问：{sub.value.id}[...]（{sub.value.id} 此前被赋值为 None）",
                        "business_logic", "mid", _CONF_LOW,
                        "对可能为 None 的变量做下标访问，可能触发 TypeError。",
                        "下标访问前判空。",
                    ))
                    none_bound.discard(sub.value.id)


def _check_open_calls(func, file_path: str, issues: List[Dict], safe: Set[int]) -> None:
    for n in ast.walk(func):
        if isinstance(n, ast.Call) and _is_open_call(n) and id(n) not in safe:
            issues.append(_mk(
                file_path, n.lineno,
                "open() 未使用 with 语句 — 文件句柄可能泄漏",
                "memory_performance", "mid", _CONF_HIGH,
                "open() 的返回值未在 with 中使用，异常路径下句柄可能未关闭。",
                "使用 with open(path) as f: 自动管理生命周期。",
            ))
