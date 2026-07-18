#!/usr/bin/env python3
"""审计白名单 v8.5 — 排除文件/目录/层级/规则，注入已知包，避免对测试/生成代码/内部库误判。

JSON 格式（SKILL.md「白名单」章节定义）：
{
  "exclude_files": ["test_*.py", "*.generated.*"],   # 文件名 glob
  "exclude_dirs":  ["vendor", "generated"],            # 目录名（命中路径任意一段即排除）
  "exclude_layers": ["code_quality"],                  # 整层跳过（如不想看魔法数字噪音）
  "exclude_patterns": ["第三方SDK.*内部实现"],          # 对 desc+code_snippet 做正则排除
  "known_packages": ["my_internal_lib"],               # 注入为已知包（AI 幻觉层不再误报）
  "auto_generated_dirs": ["generated"],
  "auto_generated_patterns": ["*_pb2.py"]
}
"""

import fnmatch
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set


class Whitelist:
    def __init__(self, data: Dict):
        self.exclude_files: List[str] = data.get("exclude_files", [])
        self.exclude_dirs: List[str] = data.get("exclude_dirs", [])
        self.exclude_layers: Set[str] = set(data.get("exclude_layers", []))
        self.exclude_patterns: List[str] = data.get("exclude_patterns", [])
        self.known_packages: List[str] = data.get("known_packages", [])
        self.auto_generated_dirs: List[str] = data.get("auto_generated_dirs", [])
        self.auto_generated_patterns: List[str] = data.get("auto_generated_patterns", [])
        self._pat: List[re.Pattern] = []
        for p in self.exclude_patterns:
            try:
                self._pat.append(re.compile(p))
            except re.error:
                pass

    def is_file_excluded(self, path: str) -> bool:
        p = Path(path)
        if self.exclude_dirs and set(p.parts) & set(self.exclude_dirs):
            return True
        for pat in self.exclude_files:
            if fnmatch.fnmatch(p.name, pat) or fnmatch.fnmatch(p.as_posix(), pat):
                return True
        return False

    def is_issue_excluded(self, issue: Dict) -> bool:
        if issue.get("layer") in self.exclude_layers:
            return True
        if self._pat:
            text = issue.get("desc", "") + " " + issue.get("code_snippet", "")
            for rx in self._pat:
                if rx.search(text):
                    return True
        return False


def load_whitelist(path: Optional[str]) -> Optional[Whitelist]:
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return Whitelist(json.load(f))
    except Exception:
        return None
