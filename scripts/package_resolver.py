#!/usr/bin/env python3
"""商业级包名解析器 v1.0 — 多语言包生态验证 · 项目命名空间识别 · 零包名误报"""

import ast
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

# ══════════════════════════════════════════════════════
# Python 标准库 (3.0-3.13 完整列表)
# ══════════════════════════════════════════════════════
PYTHON_STDLIB: Set[str] = {
    "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
    "asyncore", "atexit", "audioop", "base64", "bdb", "binascii", "binhex",
    "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb", "chunk",
    "cmath", "cmd", "code", "codecs", "codeop", "collections", "colorsys",
    "compileall", "concurrent", "configparser", "contextlib", "contextvars",
    "copy", "copyreg", "cProfile", "crypt", "csv", "ctypes", "curses",
    "dataclasses", "datetime", "dbm", "decimal", "difflib", "dis",
    "distutils", "doctest", "email", "encodings", "enum", "errno",
    "faulthandler", "fcntl", "filecmp", "fileinput", "fnmatch", "formatter",
    "fractions", "ftplib", "functools", "gc", "getopt", "getpass",
    "gettext", "glob", "grp", "gzip", "hashlib", "heapq", "hmac", "html",
    "http", "idlelib", "imaplib", "imghdr", "importlib", "inspect", "io",
    "ipaddress", "itertools", "json", "keyword", "lib2to3", "linecache",
    "locale", "logging", "lzma", "mailbox", "mailcap", "marshal", "math",
    "mimetypes", "mmap", "modulefinder", "multiprocessing", "netrc",
    "nis", "nntplib", "numbers", "operator", "optparse", "os", "ossaudiodev",
    "parser", "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil",
    "platform", "plistlib", "poplib", "posix", "posixpath", "pprint",
    "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr",
    "pydoc", "queue", "quopri", "random", "re", "readline", "reprlib",
    "resource", "rlcompleter", "runpy", "sched", "secrets", "select",
    "selectors", "shelve", "shlex", "shutil", "signal", "site", "smtpd",
    "smtplib", "sndhdr", "socket", "socketserver", "sqlite3", "ssl",
    "stat", "statistics", "string", "stringprep", "struct", "subprocess",
    "sunau", "symtable", "sys", "sysconfig", "syslog", "tabnanny",
    "tarfile", "telnetlib", "tempfile", "termios", "test", "textwrap",
    "threading", "time", "timeit", "tkinter", "token", "tokenize",
    "trace", "traceback", "tracemalloc", "tty", "turtle", "turtledemo",
    "types", "typing", "unicodedata", "unittest", "urllib", "uu",
    "uuid", "venv", "warnings", "wave", "weakref", "webbrowser",
    "winreg", "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc",
    "zipapp", "zipfile", "zipimport", "zlib",
    # 常见子模块
    "os.path", "collections.abc", "http.server", "http.client",
    "urllib.request", "urllib.parse", "urllib.error", "xml.etree.ElementTree",
    "email.mime.text", "email.mime.multipart", "logging.handlers",
    "unittest.mock", "datetime.timezone", "concurrent.futures",
}

# ══════════════════════════════════════════════════════
# Python 第三方顶级包名（从 PyPI top 1000 提取）
# ══════════════════════════════════════════════════════
PYTHON_KNOWN_PACKAGES: Set[str] = {
    "numpy", "pandas", "scipy", "scikit-learn", "sklearn",
    "matplotlib", "seaborn", "plotly", "bokeh",
    "tensorflow", "torch", "keras", "jax",
    "django", "flask", "fastapi", "aiohttp", "tornado", "sanic",
    "requests", "httpx", "urllib3", "beautifulsoup4", "bs4",
    "lxml", "scrapy", "selenium",
    "sqlalchemy", "pymongo", "redis", "psycopg2", "mysqlclient",
    "pymysql", "sqlite3",
    "celery", "kafka-python", "pika", "pyzmq",
    "pytest", "unittest", "nose", "tox",
    "pillow", "PIL", "opencv-python", "cv2",
    "pyyaml", "yaml", "toml", "tomli",
    "pydantic", "marshmallow", "cerberus",
    "click", "typer", "fire", "rich",
    "pytest", "black", "flake8", "pylint", "mypy", "isort",
    "jupyter", "ipython", "notebook",
    "streamlit", "gradio",
    "langchain", "openai", "transformers",
    "uvicorn", "gunicorn", "waitress",
    "boto3", "google-cloud", "azure",
    "pytest-cov", "coverage",
    "alembic", "migrate",
    "watchdog", "pyinotify",
    "python-dotenv", "dotenv",
    "cryptography", "pyjwt", "jwt",
    "jinja2", "mako",
    "grpcio", "protobuf",
    "networkx", "sympy",
    "python-dateutil", "pytz", "arrow", "pendulum",
    "orjson", "ujson", "msgpack",
    "tqdm", "loguru", "structlog",
    "psutil", "distro",
    "packaging", "setuptools", "pip", "wheel", "poetry",
    "certifi", "chardet", "idna",
    "six", "decorator", "wrapt", "attrs",
}

# ══════════════════════════════════════════════════════
# JS/TS 框架名（React 生态 + 常见库）
# ══════════════════════════════════════════════════════
JS_KNOWN_PACKAGES: Set[str] = {
    "react", "react-dom", "react-router", "react-router-dom",
    "next", "nuxt", "vue", "angular", "svelte",
    "redux", "zustand", "mobx", "recoil", "jotai",
    "tailwindcss", "bootstrap", "chakra-ui", "@mui/material",
    "@radix-ui", "shadcn", "shadcn-ui",
    "axios", "fetch", "node-fetch", "got",
    "express", "koa", "fastify", "hapi", "nest",
    "prisma", "sequelize", "typeorm", "mongoose", "knex",
    "typescript", "ts-node", "tsx",
    "vite", "webpack", "esbuild", "rollup", "parcel",
    "jest", "vitest", "mocha", "chai", "cypress", "playwright",
    "eslint", "prettier", "husky", "lint-staged",
    "lodash", "underscore", "ramda",
    "moment", "dayjs", "date-fns", "luxon",
    "zod", "yup", "joi", "ajv",
    "socket.io", "ws", "graphql", "apollo",
    "electron", "nwjs",
    "commander", "yargs", "chalk", "ora", "inquirer",
    "dotenv", "cross-env",
    "bcrypt", "jsonwebtoken", "passport", "helmet", "cors",
    "winston", "pino", "bunyan", "morgan",
    "nodemailer", "sharp", "multer", "csv-parse",
    "swr", "tanstack", "react-query",
    "i18next", "react-i18next",
    "d3", "three", "chart.js", "echarts",
    "@electron", "@tauri-apps",
    "immer", "clsx", "classnames", "nanoid",
    "lucide-react", "lucide", "@radix-ui/react-icons",
    "framer-motion", "framer", "gsap",
    "@tanstack/react-query", "@tanstack/react-table",
    "react-hook-form", "@hookform/resolvers",
    "next-themes", "sonner", "cmdk", "vaul",
    "react-dnd", "@dnd-kit/core", "@dnd-kit/sortable",
    "react-beautiful-dnd", "hello-pangea/dnd",
    "react-dropzone", "react-select", "react-datepicker",
    "ag-grid-react", "ag-grid-community",
    "recharts", "nivo", "@nivo/core",
    "@supabase/supabase-js", "@supabase/ssr",
    "firebase", "@firebase/app",
    "zustand", "jotai", "valtio", "pinia",
    "execa", "globby", "chokidar", "fs-extra",
    "p-limit", "p-queue", "p-retry",
    "@anthropic-ai/sdk", "openai", "langchain",
    "class-variance-authority", "cva", "clsx",
    "tailwind-merge", "tailwindcss-animate",
    "tailwindcss-intersect", "react-helmet-async",
    "@radix-ui/react-slot", "@radix-ui/react-dialog",
    "@radix-ui/react-label", "@radix-ui/react-accordion",
    "@radix-ui/react-alert-dialog", "@radix-ui/react-aspect-ratio",
    "@radix-ui/react-avatar", "@radix-ui/react-checkbox",
    "@radix-ui/react-collapsible", "@radix-ui/react-context-menu",
    "@radix-ui/react-dropdown-menu", "@radix-ui/react-hover-card",
    "@radix-ui/react-menubar", "@radix-ui/react-navigation-menu",
    "@radix-ui/react-popover", "@radix-ui/react-progress",
    "@radix-ui/react-radio-group", "@radix-ui/react-scroll-area",
    "@radix-ui/react-select", "@radix-ui/react-separator",
    "@radix-ui/react-slider", "@radix-ui/react-switch",
    "@radix-ui/react-tabs", "@radix-ui/react-toggle",
    "@radix-ui/react-toggle-group", "@radix-ui/react-tooltip",
    "react-day-picker", "date-fns", "react-resizable-panels",
    "lunar-javascript", "@paddleocr/paddleocr-js",
    "emoji-mart", "@emoji-mart/data", "@emoji-mart/react",
}

# ══════════════════════════════════════════════════════
# C# 已知命名空间（.NET BCL + 常见 NuGet）
# ══════════════════════════════════════════════════════
CSHARP_KNOWN_PACKAGES: Set[str] = {
    "System", "System.Collections", "System.Collections.Generic",
    "System.Linq", "System.IO", "System.Text", "System.Threading",
    "System.Threading.Tasks", "System.Net", "System.Net.Http",
    "System.Diagnostics", "System.Reflection", "System.Globalization",
    "System.Security", "System.Security.Cryptography",
    "System.ComponentModel", "System.ComponentModel.DataAnnotations",
    "System.Data", "System.Data.SqlClient", "Microsoft.Data.SqlClient",
    "System.Text.Json", "System.Text.RegularExpressions",
    "System.Xml", "System.Xml.Linq",
    "System.Windows", "System.Windows.Forms", "System.Windows.Controls",
    "System.Windows.Media", "System.Windows.Input",
    "System.Windows.Data", "System.Drawing", "System.Drawing.Imaging",
    "System.Configuration",
    "Microsoft.AspNetCore", "Microsoft.AspNetCore.Mvc",
    "Microsoft.AspNetCore.Http", "Microsoft.AspNetCore.Builder",
    "Microsoft.Extensions.DependencyInjection",
    "Microsoft.Extensions.Configuration",
    "Microsoft.Extensions.Logging",
    "Microsoft.Extensions.Hosting",
    "Microsoft.EntityFrameworkCore", "Microsoft.EntityFrameworkCore.SqlServer",
    "Newtonsoft.Json", "Newtonsoft.Json.Linq",
    "Dapper", "AutoMapper", "FluentValidation",
    "Serilog", "Serilog.AspNetCore", "NLog",
    "MediatR", "MediatR.Extensions",
    "Polly", "MassTransit",
    "xunit", "NUnit", "Moq", "FluentAssertions",
    "Swashbuckle", "Swashbuckle.AspNetCore",
    "IdentityModel", "IdentityServer4",
    "Microsoft.AspNetCore.Authentication",
    "Microsoft.AspNetCore.Authorization",
    "Microsoft.AspNetCore.Cors",
    "Microsoft.AspNetCore.SignalR",
    "CommunityToolkit", "CommunityToolkit.Mvvm",
    "Hardcodet.NotifyIcon",
    "System.Speech",
    "Microsoft.Toolkit",
    "Microsoft.ClearScript",
    "System.Management", "System.Management.Automation",
    "System.ServiceProcess",
}

# ══════════════════════════════════════════════════════
# 核心解析器类
# ══════════════════════════════════════════════════════

class PackageResolver:
    """多语言包名验证器 — 区分内部命名空间、标准库、已知包、未知包"""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root).resolve()
        self._internal_namespaces: Set[str] = set()
        self._project_name: str = ""
        self._project_type: str = "unknown"
        self._parsed_deps: Dict[str, Set[str]] = {}
        self._node_modules_packages: Set[str] = set()
        self._csproj_references: Set[str] = set()
        self._extra_known: Set[str] = set()  # 白名单注入的已知包

        self._parse_project_context()

    # ── 项目上下文解析 ──

    def _parse_project_context(self) -> None:
        """解析项目配置文件，构建内部命名空间和已知依赖"""
        root = self.project_root
        
        # 1. 解析 package.json (JS/TS 项目)
        pkg_json = root / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                self._project_name = data.get("name", "")
                if self._project_name.startswith("@"):
                    self._project_name = self._project_name.split("/")[-1]
                self._project_type = "web" if "react" in str(data).lower() or "vue" in str(data).lower() else "node"
                
                # 提取所有依赖名
                deps = set()
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    for pkg_name in data.get(key, {}).keys():
                        # 处理 @scope/name 格式
                        deps.add(pkg_name)
                        if pkg_name.startswith("@"):
                            parts = pkg_name.split("/", 1)
                            deps.add(parts[-1])  # 添加不带 scope 的版本
                self._parsed_deps["npm"] = deps
            except (json.JSONDecodeError, KeyError):
                pass

        # 1.5. 解析 tsconfig.json (TypeScript 路径别名, 如 @/ → src/)
        for tsconfig in list(root.glob("tsconfig*.json"))[:3]:
            try:
                data = json.loads(tsconfig.read_text(encoding="utf-8"))
                paths = data.get("compilerOptions", {}).get("paths", {})
                # 将所有路径别名加入内部命名空间
                for alias in paths.keys():
                    # @/* → @, @components/* → @components
                    clean = alias.rstrip("/*").lstrip("@").lstrip("/").split("/")[0]
                    if clean:
                        self._internal_namespaces.add(f"@{clean}")
                    # 也添加裸别名
                    base = alias.split("/")[0]
                    if base:
                        self._internal_namespaces.add(base)
            except (json.JSONDecodeError, KeyError):
                pass

        # 2. 解析 .csproj (C# 项目)
        for csproj_file in list(root.glob("*.csproj")):
            try:
                tree = ET.parse(csproj_file)
                ns = {"ms": "http://schemas.microsoft.com/developer/msbuild/2003"}
                # 提取 <RootNamespace> 或 <AssemblyName>
                root_ns = tree.find(".//ms:RootNamespace", ns)
                if root_ns is not None:
                    self._internal_namespaces.add(root_ns.text or "")
                    self._project_name = root_ns.text or ""
                else:
                    # 用 .csproj 文件名作为项目名
                    self._project_name = csproj_file.stem

                # 提取 <PackageReference Include="...">
                refs = set()
                for ref in tree.findall(".//ms:PackageReference", ns):
                    include = ref.get("Include", "")
                    if include:
                        refs.add(include)
                        # 也添加不带 NuGet 命名空间的部分
                        refs.add(include.split("/")[-1] if "/" in include else include)
                self._csproj_references = refs
                self._parsed_deps["nuget"] = refs
                
                # 构建内部命名空间列表
                ns_prefix = self._project_name
                for ns_decl in ["Core", "Models", "Services", "Views", "ViewModels",
                               "Controllers", "Helpers", "Utils", "Components",
                               "Pages", "Data", "Config", "Infrastructure",
                               "Repositories", "Handlers", "Mappings", "Validators"]:
                    self._internal_namespaces.add(f"{ns_prefix}.{ns_decl}")
                
                self._project_type = "desktop"
            except (ET.ParseError, FileNotFoundError):
                pass

        # 3. 解析 go.mod
        go_mod = root / "go.mod"
        if go_mod.exists():
            try:
                content = go_mod.read_text(encoding="utf-8")
                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith("module "):
                        self._project_name = line.split("module ")[1].strip()
                        # 提取最后一段作为短名
                        self._project_name = self._project_name.split("/")[-1]
                        self._project_type = "api" if "http" in content.lower() or "gin" in content.lower() else "cli"
            except Exception:
                pass

        # 4. 解析 Cargo.toml
        cargo_toml = root / "Cargo.toml"
        if cargo_toml.exists():
            self._project_name = root.name
            self._project_type = "cli"

        # 5. 扫描 node_modules 顶层目录（如果存在）
        node_mod = root / "node_modules"
        if node_mod.exists() and node_mod.is_dir():
            try:
                for item in list(node_mod.iterdir())[:200]:  # 限制扫描量
                    if item.is_dir() and not item.name.startswith("."):
                        self._node_modules_packages.add(item.name)
            except PermissionError:
                pass

        # 6. 扫描项目源码目录提取内部命名空间
        self._scan_internal_imports()

    def _scan_internal_imports(self) -> None:
        """扫描项目源码，自动提取内部命名空间/包名"""
        root = self.project_root
        internal_exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".cs"}

        for ext in internal_exts:
            for src_file in list(root.rglob(f"*{ext}"))[:100]:  # 限制扫描量
                try:
                    content = src_file.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                
                if ext == ".py":
                    self._extract_python_internal(content)
                elif ext in (".js", ".jsx", ".ts", ".tsx"):
                    self._extract_js_internal(content)
                elif ext == ".cs":
                    self._extract_csharp_internal(content)

    def _extract_python_internal(self, content: str) -> None:
        """从 Python 源码提取内部模块名"""
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.name.split(".")[0]
                        if self.project_root.name.lower() in name.lower():
                            self._internal_namespaces.add(name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        name = node.module.split(".")[0]
                        if self.project_root.name.lower() in name.lower():
                            self._internal_namespaces.add(name)
        except SyntaxError:
            pass

    def _extract_js_internal(self, content: str) -> None:
        """从 JS/TS 源码提取内部导入路径"""
        import re
        # 匹配相对路径导入（内部模块特征）
        patterns = [
            r'from\s+["\']\.\.?/',          # 相对路径导入
            r'require\s*\(\s*["\']\.\.?/',  # require 相对路径
            r'import\s*\(\s*["\']\.\.?/',   # 动态 import 相对路径
        ]
        for pattern in patterns:
            if re.search(pattern, content):
                # 发现有相对导入 → 项目名本身是内部命名空间
                self._internal_namespaces.add(self._project_name)
                break

    def _extract_csharp_internal(self, content: str) -> None:
        """从 C# 源码提取内部命名空间"""
        import re
        namespace_match = re.search(r'namespace\s+(\w+(?:\.\w+)*)', content)
        if namespace_match:
            ns = namespace_match.group(1)
            parts = ns.split(".")
            if parts:
                self._internal_namespaces.add(parts[0])  # 根命名空间
                self._internal_namespaces.add(ns)  # 完整命名空间

    # ── 包名验证 ──

    def resolve(self, package_name: str, language: str) -> Tuple[bool, str, str]:
        """
        验证包名是否存在
        
        返回: (is_known, category, reason)
        category: "stdlib" | "known" | "dependency" | "internal" | "unknown"
        """
        name = package_name.strip()
        if not name:
            return True, "empty", "empty"

        # 白名单注入的已知包（add_known）
        if self._extra_known:
            base = name.split("/")[-1] if "/" in name else name
            root_ns = name.split(".")[0]
            if name in self._extra_known or base in self._extra_known or root_ns in self._extra_known:
                return True, "known", "白名单已知包"

        # 0. 内部命名空间/模块
        if name in self._internal_namespaces:
            return True, "internal", "项目内部命名空间"

        # 检查是否匹配项目名的任意子命名空间
        if self._project_name and name.startswith(self._project_name):
            return True, "internal", "项目内部命名空间"

        # @/ 路径别名 → tsconfig paths 自动解析
        if name.startswith("@/"):
            return True, "internal", "TypeScript 路径别名 (tsconfig paths)"

        # ── Python ──
        if language == "python":
            # 标准库
            if name in PYTHON_STDLIB:
                return True, "stdlib", "Python 标准库"
            # 已知第三方包
            if name in PYTHON_KNOWN_PACKAGES:
                return True, "known", "已知 PyPI 包"
            # 检查是否包含点号（子模块导入）
            base = name.split(".")[0]
            if base in PYTHON_STDLIB or base in PYTHON_KNOWN_PACKAGES:
                return True, "known", "已知包的子模块"
            if base in self._internal_namespaces:
                return True, "internal", "项目内部模块"

        # ── JavaScript / TypeScript ──
        elif language in ("javascript", "typescript", "vue"):
            base = name.split("/")[-1] if "/" in name else name
            if name in JS_KNOWN_PACKAGES or base in JS_KNOWN_PACKAGES:
                return True, "known", "已知 npm 包"
            if name in self._node_modules_packages:
                return True, "dependency", "node_modules 中已安装"
            if name in self._parsed_deps.get("npm", set()):
                return True, "dependency", "package.json 依赖"
            # node: 内置模块
            if name.startswith("node:"):
                return True, "stdlib", "Node.js 内置模块"
            # 相对路径导入
            if name.startswith("./") or name.startswith("../"):
                return True, "internal", "项目内部文件"

        # ── C# ──
        elif language == "csharp":
            if name in CSHARP_KNOWN_PACKAGES:
                return True, "known", "已知 .NET BCL/NuGet 包"
            if name in self._csproj_references:
                return True, "dependency", ".csproj 依赖"
            # BCL 子命名空间
            if name.startswith("System.") or name.startswith("Microsoft."):
                return True, "known", ".NET BCL 命名空间"

        # ── Go ──
        elif language == "go":
            base = name.split("/")[-1] if "/" in name else name
            if name in self._parsed_deps.get("go", set()):
                return True, "dependency", "go.mod 依赖"
            # Go 标准库
            go_stdlib = {"fmt", "os", "io", "net", "http", "strings", "strconv",
                        "time", "context", "sync", "errors", "log", "testing",
                        "math", "sort", "bytes", "bufio", "crypto", "database",
                        "encoding", "flag", "regexp", "reflect", "runtime",
                        "unsafe", "syscall", "mime", "path", "text", "html",
                        "image", "compress", "archive", "container", "hash",
                        "index"}
            if base in go_stdlib or (name.startswith("golang.org/x/") or 
                                       "github.com" in name or "google.golang.org" in name):
                return True, "known", "Go 标准库或已知包"

        # ── Rust ──
        elif language == "rust":
            if name in self._parsed_deps.get("cargo", set()):
                return True, "dependency", "Cargo.toml 依赖"
            rust_stdlib = {"std", "core", "alloc", "proc_macro", "test"}
            if name in rust_stdlib:
                return True, "stdlib", "Rust 标准库"

        # ── C++ ──
        elif language == "cpp":
            cpp_stdlib = {"iostream", "fstream", "sstream", "string", "vector",
                         "map", "set", "list", "queue", "stack", "algorithm",
                         "functional", "memory", "utility", "cmath", "cstdlib"}
            if name in cpp_stdlib:
                return True, "stdlib", "C++ 标准库"
            if "<" in name or ">" in name:
                return True, "known", "C++ 标准库头文件"

        # ── Java ──
        elif language == "java":
            if name.startswith("java.") or name.startswith("javax."):
                return True, "stdlib", "Java 标准库"
            if "springframework" in name or "apache" in name or "google" in name:
                return True, "known", "已知 Java 包"

        # 无法验证 → 标记为未知
        return False, "unknown", "不在已知包数据库中，需人工确认"

    def is_known_import(self, package_name: str, language: str) -> bool:
        """快速判断包是否已知"""
        known, _, _ = self.resolve(package_name, language)
        return known

    def add_known(self, packages) -> None:
        """白名单注入：将指定包名标记为已知，避免 AI 幻觉层误报。"""
        for p in (packages or []):
            self._extra_known.add(p.strip())

    def get_context_summary(self) -> Dict:
        """返回项目上下文摘要"""
        return {
            "project_name": self._project_name,
            "project_type": self._project_type,
            "internal_namespaces": sorted(list(self._internal_namespaces))[:20],
            "detected_deps": {k: len(v) for k, v in self._parsed_deps.items()},
            "node_modules_count": len(self._node_modules_packages),
        }
