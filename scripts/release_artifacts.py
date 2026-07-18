#!/usr/bin/env python3
"""发布前遗留/调试文件检测 v1.0 — 门禁新增维度

扫描提交到源码仓库中的「不应发布」文件，作为发布门禁的新增审查维度：
- 私钥 / 密钥文件（.pem/.key/.p12/.pfx/.jks 等）
- 含密钥的 .env / .env.local
- 源码映射 / 调试符号（*.js.map / *.pdb）
- 备份 / 遗留文件（.bak / .old / - Copy / 副本 等）
- 提交的缓存 / IDE 目录（__pycache__ / .idea 等）
- 超大归档 / 二进制（zip/rar/exe 等超过阈值）
- 调试日志（*.log）

所有发现统一为 issue 格式，自动汇入置信度评分与否决管道。
"""

import re
from pathlib import Path
from typing import List, Dict, Set

# 不扫描的构建/依赖目录（其内部的遗留文件不计入门禁）
# 注意：不含 ".env" —— 提交 .env 文件正是门禁要捕获的遗留项
EXCLUDE_DIRS: Set[str] = {
    "node_modules", "__pycache__", "venv", ".venv", "env",
    "dist", "build", "target", ".git", "coverage", ".next", ".nuxt",
    "bin", "obj", "packages", ".vs", "Debug", "Release",
    "Pods", ".gradle", ".idea", ".vscode",
}

# 私钥 / 密钥文件（入库即高危）
PRIVATE_KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore", ".jks")

# 备份 / 遗留文件命名
BACKUP_RES = [
    re.compile(r"\.bak\d*$", re.IGNORECASE),
    re.compile(r"\.old$", re.IGNORECASE),
    re.compile(r"\.orig$", re.IGNORECASE),
    re.compile(r"\.tmp$", re.IGNORECASE),
    re.compile(r"\.save$", re.IGNORECASE),
    re.compile(r"~\s*$", re.IGNORECASE),
    re.compile(r"\.swp$", re.IGNORECASE),
    re.compile(r"\s-\s?copy\b", re.IGNORECASE),
    re.compile(r"副本"),
]

SOURCE_MAP_RE = re.compile(r"\.(js|css|mjs)\.map$", re.IGNORECASE)
DEBUG_SYM_RE = re.compile(r"\.pdb$", re.IGNORECASE)
LOG_RE = re.compile(r"\.log$", re.IGNORECASE)
ENV_RE = re.compile(r"^\.env(\.[A-Za-z0-9_-]+)?$", re.IGNORECASE)
ENV_EXCLUDE_RE = re.compile(r"(\.example|\.sample|\.template)$", re.IGNORECASE)
ARCHIVE_SUFFIXES = (".zip", ".rar", ".7z", ".tar.gz", ".tgz", ".exe",
                    ".msi", ".dmg", ".apk", ".iso")
# 提交的缓存 / IDE 目录（不应纳入版本控制）
COMMITTED_CACHE_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache",
                        ".ruff_cache", ".tox", ".idea", ".vscode",
                        ".vs", "Thumbs.db", "desktop.ini"}

SECRET_LINE_RE = re.compile(
    r'(password|secret|api[_-]?key|token|private[_-]?key|access[_-]?key)\s*[=:]\s*\S+',
    re.IGNORECASE)


def _mb(path: Path) -> float:
    try:
        return path.stat().st_size / (1024 * 1024)
    except Exception:
        return 0.0


def scan_release_artifacts(root_path: str, size_threshold_mb: float = 5.0,
                           whitelist=None, max_files: int = 300) -> List[Dict]:
    """扫描发布前不应提交的遗留/调试文件，返回 issue 列表。

    whitelist: 可选白名单对象（需提供 is_file_excluded(str) 方法）；
               命中 exclude_files/dirs/patterns 的文件直接跳过，与源码扫描一致。
    max_files: 扫描上限。rglob 为惰性遍历，达到上限即停止后续文件系统枚举，
               避免超大仓库读取全量文件造成性能问题（默认 300）。
    """
    root = Path(root_path)
    if not root.exists():
        return []

    issues: List[Dict] = []
    seen_dirs: Set[str] = set()
    scanned = 0

    for f in root.rglob("*"):
        if scanned >= max_files:
            break
        try:
            rel = f.relative_to(root)
        except Exception:
            continue

        # 白名单：用户显式排除的文件/目录直接跳过（修复 v8.6 F2）
        if whitelist is not None and whitelist.is_file_excluded(str(f)):
            continue

        parts = set(rel.parts)
        if parts & EXCLUDE_DIRS:
            continue

        if not f.is_file():
            # 提交的缓存 / IDE 目录
            if f.name in COMMITTED_CACHE_DIRS:
                d = str(rel)
                if d not in seen_dirs:
                    seen_dirs.add(d)
                    issues.append({
                        "file": str(f), "line": 1,
                        "desc": f"提交了不应纳入版本控制的目录: {f.name}/",
                        "layer": "engineering", "severity": "mid",
                        "confidence": "medium",
                        "code_snippet": d,
                        "suggestion": f"将 {f.name}/ 加入 .gitignore，避免缓存/IDE 文件污染发布包。",
                    })
            continue

        scanned += 1
        name = f.name
        suffix = f.suffix.lower()

        # 1) 私钥 / 密钥文件
        if suffix in PRIVATE_KEY_SUFFIXES:
            sev = "high" if suffix == ".pem" else "critical"
            issues.append({
                "file": str(f), "line": 1,
                "desc": f"提交了疑似私钥/密钥文件: {name}",
                "layer": "product_security", "severity": sev,
                "confidence": "medium",
                "code_snippet": name,
                "suggestion": "私钥严禁入库。确认后从仓库删除并加入 .gitignore；如已泄露立即轮换。",
            })
            continue

        # 2) .env / .env.local（含密钥）
        if ENV_RE.match(name) and not ENV_EXCLUDE_RE.search(name):
            sev, conf = "high", "medium"
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
                if SECRET_LINE_RE.search(txt):
                    conf = "high"
            except Exception:
                pass
            issues.append({
                "file": str(f), "line": 1,
                "desc": f"提交了环境/密钥配置文件: {name}",
                "layer": "product_security", "severity": sev,
                "confidence": conf,
                "code_snippet": name,
                "suggestion": "将 .env 加入 .gitignore，密钥改由环境变量或密钥管理服务注入。",
            })
            continue

        # 3) 源码映射 / 调试符号
        if SOURCE_MAP_RE.search(name):
            issues.append({
                "file": str(f), "line": 1,
                "desc": f"提交了源码映射文件: {name}（可泄露原始源码）",
                "layer": "product_security", "severity": "high",
                "confidence": "medium",
                "code_snippet": name,
                "suggestion": "生产构建不应发布 *.map；如必须保留请放到非公开路径。",
            })
            continue
        if DEBUG_SYM_RE.search(name):
            issues.append({
                "file": str(f), "line": 1,
                "desc": f"提交了调试符号文件: {name}",
                "layer": "product_security", "severity": "high",
                "confidence": "medium",
                "code_snippet": name,
                "suggestion": "调试符号 (.pdb) 不应随发布包分发，避免泄露内部结构与符号。",
            })
            continue

        # 4) 备份 / 遗留文件
        if any(p.search(name) for p in BACKUP_RES):
            issues.append({
                "file": str(f), "line": 1,
                "desc": f"遗留/备份文件: {name}",
                "layer": "engineering", "severity": "mid",
                "confidence": "high",
                "code_snippet": name,
                "suggestion": "备份/遗留文件不应进入发布包，删除或加入 .gitignore。",
            })
            continue

        # 5) 调试日志
        if LOG_RE.search(name):
            issues.append({
                "file": str(f), "line": 1,
                "desc": f"提交了调试日志文件: {name}",
                "layer": "engineering", "severity": "low",
                "confidence": "medium",
                "code_snippet": name,
                "suggestion": "日志文件不应入库，加入 .gitignore。",
            })
            continue

        # 6) 超大归档 / 二进制
        if suffix in ARCHIVE_SUFFIXES and _mb(f) > size_threshold_mb:
            issues.append({
                "file": str(f), "line": 1,
                "desc": f"超大归档/二进制: {name} ({_mb(f):.1f}MB)",
                "layer": "engineering", "severity": "mid",
                "confidence": "medium",
                "code_snippet": f"{name} {_mb(f):.1f}MB",
                "suggestion": f"超过 {size_threshold_mb:.0f}MB 的归档/二进制不应随源码发布，建议走制品仓库/对象存储。",
            })
            continue

    return issues
