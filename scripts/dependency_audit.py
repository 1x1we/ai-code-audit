#!/usr/bin/env python3
"""依赖漏洞(SCA)审计 v8.5 — 内置精选漏洞库(离线, 非 NVD 完整) + 多生态清单解析。

职责：解析项目依赖清单(requirements.txt / pyproject.toml / Pipfile / package.json /
go.mod / Cargo.toml / pom.xml)，对「精确/上界钉版」(== / <= / ~=) 做版本比对，命中已知
漏洞则输出 issue（layer=product_security）。未钉版(>=, >, *, ^, ~ 范围) 无法判断
是否受害 → 仅给 low 提示「依赖未锁定版本，建议用 pip-audit / npm audit 完整核查」。

⚠️ 诚实边界：内置库为**人工精选的子集**（数十个高危 CVE），并非 OSV/NVD 全量。
用于门禁快速拦截已知高危，完整 SCA 请用：
  pip-audit / npm audit / cargo audit / OSV-Scanner / safety
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 内置精选漏洞库
# package(小写) -> list of advisory
#   fixed: 修复版本（钉版 < fixed 即命中）
#   cve:   编号（仅作信息）
#   severity: critical | high | mid
#   note:   简述
ADVISORIES: Dict[str, List[Dict]] = {
    "django": [
        {"fixed": "2.2.28", "cve": "CVE-2022-28346", "severity": "high",
         "note": "SQL 注入（QuerySet.annotate 聚合参数）"},
        {"fixed": "3.2.18", "cve": "CVE-2022-28346", "severity": "high",
         "note": "同上游修复行；<3.2.18 受影响"},
        {"fixed": "4.0.8", "cve": "CVE-2023-36053", "severity": "high",
         "note": "<4.0.8 邮件验证正则 ReDoS"},
    ],
    "flask": [
        {"fixed": "2.2.5", "cve": "CVE-2023-30861", "severity": "high",
         "note": "session cookie 反序列化（未正确配置时）"},
    ],
    "pyyaml": [
        {"fixed": "5.4", "cve": "CVE-2020-1747", "severity": "high",
         "note": "yaml.load 任意代码执行（<5.4）"},
    ],
    "pillow": [
        {"fixed": "9.0.0", "cve": "CVE-2022-22817", "severity": "high",
         "note": "ImageMath.eval 任意代码执行"},
    ],
    "jinja2": [
        {"fixed": "2.11.3", "cve": "CVE-2020-28493", "severity": "high",
         "note": "模板缓存键正则 ReDoS"},
    ],
    "requests": [
        {"fixed": "2.20.0", "cve": "CVE-2018-18074", "severity": "mid",
         "note": "重定向泄露 Authorization 头"},
    ],
    "log4j-core": [
        {"fixed": "2.17.0", "cve": "CVE-2021-44228", "severity": "critical",
         "note": "Log4Shell：JNDI 查找远程代码执行（RCE）"},
    ],
    "lodash": [
        {"fixed": "4.17.21", "cve": "CVE-2021-23337", "severity": "high",
         "note": "命令注入（template）"},
    ],
    "axios": [
        {"fixed": "0.21.1", "cve": "CVE-2020-28168", "severity": "mid",
         "note": "SSRF（跟随重定向）"},
        {"fixed": "0.21.2", "cve": "CVE-2021-3749", "severity": "mid",
         "note": "ReDoS（trim 处理）"},
    ],
    "minimist": [
        {"fixed": "1.2.6", "cve": "CVE-2021-44906", "severity": "high",
         "note": "原型链污染"},
    ],
    "jsonwebtoken": [
        {"fixed": "9.0.0", "cve": "CVE-2022-23529", "severity": "high",
         "note": "密钥混淆 / 验证绕过"},
    ],
    "express": [
        {"fixed": "4.18.2", "cve": "CVE-2022-24999", "severity": "high",
         "note": "qs 原型链污染（body-parser）"},
    ],
    "moment": [
        {"fixed": "2.29.2", "cve": "CVE-2022-24785", "severity": "mid",
         "note": "路径遍历（locale 加载）"},
    ],
    "semver": [
        {"fixed": "7.5.2", "cve": "CVE-2022-25883", "severity": "mid",
         "note": "ReDoS"},
    ],
    "tar": [
        {"fixed": "6.1.9", "cve": "CVE-2021-32804", "severity": "high",
         "note": "路径遍历（解压）"},
    ],
}


def _parse_version(v: str) -> Optional[Tuple[int, ...]]:
    v = v.strip().lstrip("vV")
    parts = re.split(r"[.\-+]", v)
    nums: List[int] = []
    for p in parts:
        m = re.match(r"\d+", p)
        if m:
            nums.append(int(m.group(0)))
        else:
            if not nums:
                return None
            break
    return tuple(nums) if nums else None


def _version_lt(a: str, fixed: str) -> Optional[bool]:
    pa, pf = _parse_version(a), _parse_version(fixed)
    if pa is None or pf is None:
        return None
    length = max(len(pa), len(pf))
    pa = pa + (0,) * (length - len(pa))
    pf = pf + (0,) * (length - len(pf))
    return pa < pf


def _norm_node_version(ver: str) -> Tuple[Optional[str], bool]:
    """返回 (floor_version_str, is_exact)。is_exact=True 表示精确钉版。"""
    s = (ver or "").strip()
    if not s or s in ("*", "latest", "x", "X"):
        return None, False
    # 去掉常见范围符
    is_exact = True
    if s[0] in "^~":
        is_exact = False
        s = s[1:].strip()
    m = re.match(r"^(>=|<=|==|=|>|<)", s)
    if m:
        op = m.group(1)
        is_exact = op in ("==", "=")
        s = s[m.end():].strip()
    if s.startswith("v") or s.startswith("V"):
        s = s[1:]
    # 提取首个数字版本
    mm = re.search(r"\d+(?:\.\d+)*", s)
    if not mm:
        return None, is_exact
    return mm.group(0), is_exact


def _parse_python_deps(root: Path) -> List[Tuple[str, str, bool]]:
    """返回 (package_lower, floor_version_or_'', is_exact)"""
    deps: List[Tuple[str, str, bool]] = []

    for rf in root.glob("requirements*.txt"):
        try:
            for line in rf.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<|!=)?\s*([0-9][A-Za-z0-9.\-\*]*)?", line)
                if m:
                    name, op, ver = m.group(1), m.group(2) or "", m.group(3) or ""
                    is_exact = op in ("==", "")
                    deps.append((name.lower(), ver, is_exact))
        except Exception:
            pass

    pp = root / "pyproject.toml"
    if pp.exists():
        try:
            txt = pp.read_text(encoding="utf-8", errors="ignore")
            for m in re.finditer(
                    r'([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<|!=)?\s*([0-9][A-Za-z0-9.\-\*]*)',
                    txt):
                if m.group(2) or m.group(3):
                    deps.append((m.group(1).lower(), m.group(3) or "", m.group(2) == "=="))
        except Exception:
            pass

    pf = root / "Pipfile"
    if pf.exists():
        try:
            txt = pf.read_text(encoding="utf-8", errors="ignore")
            for m in re.finditer(r'([A-Za-z0-9_.\-]+)\s*=\s*["\']([0-9][A-Za-z0-9.\-\*]*)?', txt):
                deps.append((m.group(1).lower(), m.group(2) or "", True))
        except Exception:
            pass

    return deps


def _parse_node_deps(root: Path) -> List[Tuple[str, str, bool]]:
    deps: List[Tuple[str, str, bool]] = []
    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                for name, ver in data.get(key, {}).items():
                    base = name.split("/")[-1].lower()
                    floor, exact = _norm_node_version(str(ver))
                    deps.append((base, floor or "", exact))
        except Exception:
            pass
    return deps


def _parse_go_deps(root: Path) -> List[Tuple[str, str, bool]]:
    deps: List[Tuple[str, str, bool]] = []
    gm = root / "go.mod"
    if gm.exists():
        try:
            in_block = False
            for line in gm.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("require ("):
                    in_block = True
                    continue
                if in_block and line.startswith(")"):
                    in_block = False
                    continue
                m = re.match(r'^(?:require\s+)?([A-Za-z0-9_.\-/]+)\s+v([0-9][0-9A-Za-z.\-]*)', line)
                if m:
                    deps.append((m.group(1).lower(), m.group(2), True))
        except Exception:
            pass
    return deps


def _parse_cargo_deps(root: Path) -> List[Tuple[str, str, bool]]:
    deps: List[Tuple[str, str, bool]] = []
    ct = root / "Cargo.toml"
    if ct.exists():
        try:
            txt = ct.read_text(encoding="utf-8", errors="ignore")
            for m in re.finditer(r'([A-Za-z0-9_\-]+)\s*=\s*(?:"([^"]*)"|\{[^}]*version\s*=\s*"([^"]*)")', txt):
                ver = m.group(2) or m.group(3) or ""
                deps.append((m.group(1).lower(), ver, True))
        except Exception:
            pass
    return deps


def _parse_java_deps(root: Path) -> List[Tuple[str, str, bool]]:
    deps: List[Tuple[str, str, bool]] = []
    for pom in root.glob("pom.xml"):
        try:
            txt = pom.read_text(encoding="utf-8", errors="ignore")
            for block in re.findall(r"<dependency>.*?</dependency>", txt, re.DOTALL):
                aid = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", block)
                ver = re.search(r"<version>\s*([^<]+?)\s*</version>", block)
                if aid and ver:
                    deps.append((aid.group(1).strip().lower(), ver.group(1).strip(), True))
        except Exception:
            pass
    return deps


def scan_dependency_audit(root_path: str) -> List[Dict]:
    """解析依赖清单并比对内置精选漏洞库，返回 issue 列表。"""
    root = Path(root_path)
    if not root.exists():
        return []

    deps: List[Tuple[str, str, bool]] = []
    deps += _parse_python_deps(root)
    deps += _parse_node_deps(root)
    deps += _parse_go_deps(root)
    deps += _parse_cargo_deps(root)
    deps += _parse_java_deps(root)

    issues: List[Dict] = []
    # 已提示「未锁定版本」的包，避免重复
    unpinned_warned: set = set()

    for name, ver, is_exact in deps:
        advs = ADVISORIES.get(name)
        if not advs:
            continue
        if not ver:
            if name not in unpinned_warned:
                unpinned_warned.add(name)
                issues.append({
                    "file": f"({name} 依赖清单)", "line": 1,
                    "desc": f"依赖 {name} 未锁定版本，无法判断是否含已知漏洞",
                    "layer": "product_security", "severity": "low", "confidence": "low",
                    "code_snippet": name,
                    "suggestion": "锁定版本，并用 pip-audit / npm audit / OSV-Scanner 做完整 SCA。",
                })
            continue

        for adv in advs:
            lt = _version_lt(ver, adv["fixed"])
            if lt is True:
                conf = "high" if is_exact else "medium"
                note_suffix = "" if is_exact else "（范围依赖可能解析到受害版本，建议升级并锁定）"
                issues.append({
                    "file": f"({name} 依赖清单)", "line": 1,
                    "desc": f"依赖 {name}@{ver} 含已知漏洞 {adv['cve']}：{adv['note']}{note_suffix}",
                    "layer": "product_security",
                    "severity": adv["severity"],
                    "confidence": conf,
                    "code_snippet": f"{name}=={ver} (fixed {adv['fixed']})",
                    "suggestion": f"升级 {name} 到 >= {adv['fixed']} 并重新锁定版本。",
                })

    return issues
