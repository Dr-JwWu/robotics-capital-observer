"""发布闸门：公开导出包 + 渲染站点载荷（fail closed，任一失败即拒绝发布）。

三类闸门
--------

``check_export_bundle``
    对 backend 导出的**公开数据包**（``export public`` 的输出目录）做一次独立复核：
    ``is_demo=false`` / ``data_mode=public`` / 包级与逐条 ``dataset_kind=real``、
    ``bundle.json`` 摘要与清单一致（若存在 ``sha256sum.txt``）、缺失语义自洽、理由语法封闭、
    不许出现禁用键与 private-preview/synthetic 声明。**不接受"标了 pass 就算过"**。
``check_site_payload``
    对**渲染后的站点载荷**做发布前闸门：必需文件、可解析、无密钥形态内容、无私有路径、
    无私有预览/合成声明、发布清单与状态文件一致、URL 指向已确认 origin/base、
    载荷不含本地运行数据根路径。
``check_release_provenance``
    对发布清单的**来源字段**做闸门：``build_id``/``release_version``/``payload_sha256``
    必须齐备且互相自洽；缺少来源（provenance）的产物直接拒绝 —— "没有 build_id 就上线"
    在部署后核验阶段无法分辨"部署成功"与"部署了一份陌生产物"。

依赖策略
--------

本模块**只用标准库**。若运行环境里有 finance 子项目的契约代码（``researcher_finance.contracts``），
则优先复用它（``security`` / ``permissions`` / ``reasons``）以保证与产品判定一致；否则退回本模块内置的
保守规则。两条路径都会把**命中项**记录进报告，但**永不记录命中内容本身**（不打印疑似密钥/路径原值）。
"""

from __future__ import annotations

import glob as globlib
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator, Sequence

from .manifest import MANIFEST_FILENAME, STATUS_FILENAME, read_json_object

__all__ = [
    "GateReport",
    "check_export_bundle",
    "check_site_payload",
    "check_release_provenance",
    "REQUIRED_SITE_FILES",
    "FORBIDDEN_PAYLOAD_FILE_SUFFIXES",
]

#: 站点载荷必须存在的文件（``index.html`` 是入口，两个 JSON 是发布身份）。
REQUIRED_SITE_FILES = ("index.html", MANIFEST_FILENAME, STATUS_FILENAME)

#: 公开载荷**允许的扩展名白名单**（静态站点 + 其数据）。
#:
#: 为什么需要白名单：只靠"禁止名单"意味着**任何**未预料到的文件类型都会默认合法 ——
#: 实测把 `docs-evidence-raw.md`（含"原文摘录/未授权候选包"字样）放进载荷可以通过旧闸门。
#: 白名单是 fail closed：没登记的类型一律拒绝，需要新类型时必须显式加进这里并写清用途。
ALLOWED_PAYLOAD_SUFFIXES = (
    ".html",
    ".htm",
    ".css",
    ".js",
    ".mjs",
    ".json",
    ".map",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".ico",
    ".avif",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".txt",
    ".xml",
    ".webmanifest",
    ".pdf",
    ".csv",
    ".wasm",
    ".pf_fragment",
    ".pf_index",
    ".pf_meta",
    # Pagefind 运行时会输出少量固定名字的二进制索引文件（data/search/*.pagefind 等）
    ".pagefind",
    ".unknown",
)

#: 无扩展名但允许出现在站点根的固定文件。
ALLOWED_PAYLOAD_BARE_NAMES = (
    "robots.txt",
    "sitemap.xml",
    "CNAME",
    ".nojekyll",
    "PUBLISH_MANIFEST.json",
    "status.json",
    "_redirects",
    "_headers",
)

#: 站点构建里**合法**出现的词表（说明文案/枚举值），不构成泄露证据。
#: 实测 frontend r2 产物：`_astro/*.js` 与 `about/index.html` 里有
#: "不含私有路径、原文摘录、密钥"（数据边界说明）与 `confidential: 保密`（missing_status 枚举），
#: 它们**不是**私有内容。把这些词一律当违规只会逼人削弱闸门，因此显式排除。
BENIGN_SITE_MARKERS = (
    # 构建模式/契约字段名（前端在代码里引用它们，不等于泄露内容）
    "未审核",
    "preview_excluded",
    "build-private",
    "private-preview",
    "原文摘录",
    "仅限内部使用",
    "candidate packet",
    "候选包",
    "confidential",
    "本页面的数据边界",
    "缺失状态",
)

#: 任何文本文件里出现即视为"私有/候选内容"的标记（F5）：这些字符串足够特异，
#: 只会出现在真的导出了内部素材的情况下。
UNAMBIGUOUS_CONTENT_MARKERS = (
    "internal only",
    "do not distribute",
    "not for distribution",
    "未授权发布",
    "未授权公开",
    "禁止外传",
    "内部候选包",
    "candidate packet export",
    # 注意：`未审核` 是前端 UI 的状态词（复核上下文已确认），**不算**私有内容标记；
    # `未授权` 在真实公开产物里 0 命中，出现即说明带了未授权素材。
    "未授权",
)

#: 只在**数据文件**（非 HTML/JS/CSS/JSON…即真正的数据载荷）里检查的词汇：
#: 站点文案是渲染后的界面，不能用这些普通词判定。
DATA_ONLY_CONTENT_MARKERS = (
    "原文摘录",
    "原文全文",
    "仅限内部使用",
    "candidate packet",
    "候选包",
)

#: 视为"数据文件"的扩展名（用于上面那一档检查）。
_DATA_LIKE_SUFFIXES = (".csv", ".tsv", ".yaml", ".yml", ".md", ".txt", ".ndjson", ".jsonl")

#: 非 JSON 文本里出现即视为"禁用键赋值"的片段（与契约的禁用键语义一致）。
FORBIDDEN_PAYLOAD_TEXT_KEYS = (
    "private_path",
    "local_path",
    "db_path",
    "raw_file_path",
    "excerpt_text",
    "api_key",
    "apikey",
    "access_token",
    "client_secret",
    "password",
)

#: 明确**禁止**进入公开发布包的载荷文件（构建中间态、私有导出、取证副本、备份、日志）。
#: 这些是真实踩过的旁路：backend 导出目录里的 ``preview.json``/``preview.md`` 会绕过白名单，
#: 发布包若打包"整个工作目录"就会把受限内容带出去。
FORBIDDEN_PAYLOAD_FILE_SUFFIXES = (
    ".sqlite",
    ".sqlite3",
    ".sqlite3-wal",
    ".sqlite3-shm",
    ".db",
    ".log",
    ".env",
    ".pem",
    ".key",
    ".p12",
)
FORBIDDEN_PAYLOAD_FILE_NAMES = (
    "preview.json",
    "preview.md",
    "receipts.json",
    "evidence.jsonl",
)
FORBIDDEN_PAYLOAD_PATH_PARTS = (
    "build-private",
    "private-preview",
    "raw",
    "backups",
    "evidence",
    "review-packets",
    "staging",
)

#: 私有预览/合成数据的**声明**文本（出现在载荷里就说明打包错了对象）。
_PREVIEW_MARKERS = (
    "本地私有预览数据",
    "仅限本机查看",
    "禁止公开部署",
)
_SYNTHETIC_MARKERS = (
    "合成演示数据",
    "不得作为事实引用",
    "demo-build-",
)

#: **高置信度**密钥形态规则：对任何文本文件都适用（不会命中压缩后的 JS 标识符）。
HIGH_CONFIDENCE_SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{16,}")),
    ("aws_access_key", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{12,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("slack_token", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}")),
    ("env_assignment", re.compile(r"(?m)^[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)=\S{8,}\s*$")),
)

#: **低信号**的 ``key=value`` 规则：只在**结构化数据文件**（.json/.ndjson/.csv/.txt）上启用。
#:
#: 为什么分档：产品契约的 ``scan_for_secret_values`` 用 ``(token|secret|...)`` + 宽松的
#: ``\s*[:=]\s*\S+``，在**压缩后的 JS** 里会命中 ECharts 的 ``_placeToken=function(...)``
#: 这类标识符（实测 false positive）。对站点载荷整目录套用这条规则会让"有打包 JS"必然失败，
#: 于是闸门只能被削弱或忽略 —— 两者都不可接受。因此：
#:   * 结构化数据文件用**严格+宽松**两层（数据里出现 token=... 就是真问题）；
#:   * 其它文件只用高置信度规则（真实密钥前缀/私钥块/Bearer）。
#: 这里额外加 ``(?<![A-Za-z0-9_])`` 词边界，避免再命中标识符内部。
_DATA_ASSIGNMENT_SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "key_value_assignment",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_])(api[_-]?key|token|secret|password)\s*[:=]\s*[\"']?[^\s\"',]{8,}"
        ),
    ),
)

#: 视为"结构化数据"的扩展名（低信号规则只在这里生效）。
_DATA_FILE_SUFFIXES = (".json", ".ndjson", ".jsonl", ".csv", ".tsv", ".txt", ".yaml", ".yml")
_FALLBACK_PRIVATE_PATH = re.compile(r"(?:^|[\"'\s(=])(/(?:home|root|var/lib|etc|Users|opt)/[^\s\"'(),;]*)")

_BINARY_SNIFF_BYTES = 4096
_SCAN_CHUNK = 1 << 20


def _load_contract_hooks() -> dict:
    """尝试复用产品契约；失败则返回空字典（退回内置兜底规则）。

    本工具包在**公开发布仓库的 runner**上运行时没有 ``src/``，因此必须能在没有契约的情况下
    独立工作；在本地 ``finance/`` 里运行时则把 ``src/`` 加进 ``sys.path`` 以复用同一套判定。
    """

    try:  # pragma: no cover - 取决于运行环境是否带 src/
        from researcher_finance.contracts.permissions import (
            DEFAULT_FORBIDDEN_KEY_PATTERNS,
            find_forbidden_keys,
            scan_for_secret_values,
        )
        from researcher_finance.contracts.reasons import is_valid_reason, partition_reasons
        from researcher_finance.contracts.security import find_private_path_leaks

        return {
            "forbidden_key_patterns": DEFAULT_FORBIDDEN_KEY_PATTERNS,
            "find_forbidden_keys": find_forbidden_keys,
            "scan_for_secret_values": scan_for_secret_values,
            "find_private_path_leaks": find_private_path_leaks,
            "is_valid_reason": is_valid_reason,
            "partition_reasons": partition_reasons,
        }
    except Exception:  # noqa: BLE001 - 任何导入/属性问题都退回兜底规则
        return {}


def _bootstrap_repo_src() -> bool:
    """把 finance 子项目的 ``src/`` 加入 ``sys.path``（存在时）；返回是否已可导入契约。"""

    try:  # pragma: no cover - 取决于运行环境
        import researcher_finance.contracts  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        pass
    import sys

    candidate = Path(__file__).resolve()
    for parent in candidate.parents:
        src = parent / "src" / "researcher_finance" / "contracts"
        if src.is_dir():
            sys.path.insert(0, str(parent / "src"))
            break
    try:  # pragma: no cover - 取决于运行环境
        import researcher_finance.contracts  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


_BOOTSTRAPPED = _bootstrap_repo_src()
_HOOKS = _load_contract_hooks()


@dataclass
class GateReport:
    """闸门结果。``ok`` 为真才允许继续；``problems`` 是**可操作**的失败原因。"""

    name: str
    ok: bool
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    facts: dict = field(default_factory=dict)

    def fail(self, message: str) -> None:
        self.problems.append(message)
        self.ok = False

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def merge(self, other: "GateReport") -> None:
        self.problems.extend(other.problems)
        self.warnings.extend(other.warnings)
        self.facts[other.name] = {"ok": other.ok, "problems": other.problems}
        if not other.ok:
            self.ok = False

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "ok": self.ok,
            "problems": list(self.problems),
            "warnings": list(self.warnings),
            "facts": self.facts,
        }


# --------------------------------------------------------------------------------------
# 文本扫描（只报告规则名/位置，不报告命中内容）
# --------------------------------------------------------------------------------------


def _looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def _iter_files(root: Path) -> Iterator[tuple[str, Path]]:
    """按文件名排序产出 ``(相对路径, 绝对路径)``；跳过符号链接。"""

    for current, _dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in sorted(filenames):
            candidate = current_path / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            yield candidate.relative_to(root).as_posix(), candidate


def _scan_secret_rules(text: str, relative: str) -> list[dict]:
    """按文件类型选择密钥规则集（见 ``_DATA_ASSIGNMENT_SECRET_RULES`` 的说明）。"""

    hits: list[dict] = []
    for rule, pattern in HIGH_CONFIDENCE_SECRET_RULES:
        if pattern.search(text):
            hits.append({"file": relative, "rule": rule, "count": 1, "confidence": "high"})
    if relative.lower().endswith(_DATA_FILE_SUFFIXES):
        for rule, pattern in _DATA_ASSIGNMENT_SECRET_RULES:
            found = pattern.findall(text)
            if found:
                hits.append(
                    {
                        "file": relative,
                        "rule": rule,
                        "count": len(found),
                        "confidence": "data-file",
                    }
                )
    return hits


def scan_payload_text(root: Path) -> dict:
    """扫描载荷内所有文本文件的疑似密钥值/私有路径。

    返回 ``{"secret_hits": [...], "path_hits": [...], "scanned_files": n, "skipped_binary": n}``；
    命中项只含 ``file``/``rule``/``line``，**不含命中内容**。
    """

    secret_hits: list[dict] = []
    path_hits: list[dict] = []
    scanned = 0
    skipped_binary = 0
    contract_paths = _HOOKS.get("find_private_path_leaks")

    for relative, absolute in _iter_files(root):
        with absolute.open("rb") as handle:
            sample = handle.read(_BINARY_SNIFF_BYTES)
        if _looks_binary(sample):
            skipped_binary += 1
            continue
        scanned += 1
        line_no = 0
        with absolute.open("rb") as handle:
            pending = b""
            while True:
                chunk = handle.read(_SCAN_CHUNK)
                if not chunk:
                    break
                data = pending + chunk
                pending = b""
                # 只对完整行做行号归属；切分处不完整的尾部留到下一块开头。
                if not data.endswith(b"\n"):
                    cut = data.rfind(b"\n")
                    if cut == -1:
                        pending = data
                        continue
                    pending = data[cut + 1 :]
                    data = data[: cut + 1]
                text = data.decode("utf-8", errors="ignore")
                chunk_lines = text.count("\n")
                for hit in _scan_secret_rules(text, relative):
                    secret_hits.append({**hit, "line": line_no + 1})
                if contract_paths is not None:
                    leaks = contract_paths(text)
                else:
                    leaks = [match.group(1) for match in _FALLBACK_PRIVATE_PATH.finditer(text)]
                for leak in leaks:
                    if leak:
                        path_hits.append(
                            {"file": relative, "matched_prefix": leak[:24], "line": line_no + 1}
                        )
                line_no += chunk_lines
            if pending:
                text = pending.decode("utf-8", errors="ignore")
                for hit in _scan_secret_rules(text, relative):
                    secret_hits.append({**hit, "line": line_no + 1})
                if contract_paths is not None:
                    leaks = contract_paths(text)
                else:
                    leaks = [match.group(1) for match in _FALLBACK_PRIVATE_PATH.finditer(text)]
                for leak in leaks:
                    if leak:
                        path_hits.append({"file": relative, "matched_prefix": leak[:24], "line": line_no + 1})

    return {
        "secret_hits": secret_hits,
        "path_hits": path_hits,
        "scanned_files": scanned,
        "skipped_binary": skipped_binary,
    }


def _iter_csv_patterns(patterns: Iterable[str]) -> list[str]:
    return [item for item in patterns]


_FALLBACK_PRIVATE_PATH_VALUE = re.compile(r"(?<![A-Za-z0-9])(?:/home/|/root/|/var/lib/|/etc/)[^\s\"']*")


def _fallback_string_values(payload, _path: str = "") -> Iterator[tuple[str, str]]:
    """内置的 ``(路径, 字符串值)`` 递归展开（对齐产品 ``iter_string_values`` 语义）。"""

    if isinstance(payload, dict):
        for key, value in payload.items():
            yield from _fallback_string_values(value, f"{_path}.{key}")
    elif isinstance(payload, (list, tuple)):
        for index, value in enumerate(payload):
            yield from _fallback_string_values(value, f"{_path}[{index}]")
    elif isinstance(payload, str):
        yield _path, payload


def find_private_paths_in_payload(payload) -> list[str]:
    """按**值**找出疑似本机私有路径（优先用产品契约，退回内置等价规则）。

    只报告命中的路径片段前缀，调用方**不得**把整条值写进日志。
    """

    contract = _HOOKS.get("find_private_path_leaks")
    if contract is not None:
        return list(contract(payload))
    leaks: list[str] = []
    for _, value in _fallback_string_values(payload):
        for match in _FALLBACK_PRIVATE_PATH_VALUE.finditer(value):
            leaks.append(match.group(0))
    return sorted(set(leaks))


# --------------------------------------------------------------------------------------
# 导出包闸门
# --------------------------------------------------------------------------------------


def _digest_matches_manifest(directory: Path, problems: list[str]) -> None:
    manifest = directory / "sha256sum.txt"
    if not manifest.is_file():
        return
    import hashlib

    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        target = directory / name.lstrip("./")
        if not target.is_file():
            problems.append(f"哈希清单指向的文件不存在：{name}")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if not digest.startswith(actual):
            problems.append(f"哈希不一致：{name}")


def check_export_bundle(directory: Path) -> GateReport:
    """复核 backend 的公开导出目录（``export public`` 的输出）。"""

    report = GateReport(name="export_bundle", ok=True)
    directory = Path(directory)
    report.facts["directory"] = str(directory)
    if not directory.is_dir():
        report.fail(f"公开导出目录不存在：{directory}")
        return report
    bundle_path = directory / "bundle.json"
    if not bundle_path.is_file():
        report.fail(f"缺少 bundle.json：{bundle_path}")
        return report
    try:
        bundle = read_json_object(bundle_path, where="公开导出 bundle.json")
    except Exception as exc:  # noqa: BLE001 - ArchiveError 或解析错误
        report.fail(str(exc))
        return report

    if bundle.get("is_demo") is not False:
        report.fail(f"is_demo 必须为 false（实际 {bundle.get('is_demo')!r}）")
    if bundle.get("data_mode") != "public":
        report.fail(f"data_mode 必须是 public（实际 {bundle.get('data_mode')!r}）")
    if bundle.get("dataset_kind") != "real":
        report.fail(f"包级 dataset_kind 必须是 real（实际 {bundle.get('dataset_kind')!r}）")

    manifest = bundle.get("manifest")
    if not isinstance(manifest, dict):
        report.fail("导出包缺少 manifest（发布清单来源），无法核验快照/契约版本")
        manifest = {}
    for key in ("snapshot_id", "data_cutoff", "contract_version", "schema_version"):
        if not manifest.get(key):
            report.fail(f"导出包 manifest 缺少 {key}（发布来源不可追溯）")
    report.facts["snapshot_id"] = manifest.get("snapshot_id")
    report.facts["data_cutoff"] = manifest.get("data_cutoff")
    report.facts["contract_version"] = manifest.get("contract_version")
    report.facts["schema_version"] = manifest.get("schema_version")
    report.facts["publication_policy_version"] = manifest.get("publication_policy_version")

    datasets = bundle.get("datasets")
    if not isinstance(datasets, dict):
        report.fail("导出包 datasets 必须是对象")
        datasets = {}
    counts = {name: len(rows) for name, rows in datasets.items() if isinstance(rows, list)}
    report.facts["counts"] = counts
    for name, rows in datasets.items():
        if not isinstance(rows, list):
            report.fail(f"datasets.{name} 必须是数组")
            continue
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                report.fail(f"datasets.{name}[{index}] 不是对象")
                continue
            if row.get("dataset_kind") == "synthetic":
                report.fail(f"datasets.{name}[{index}] 是 synthetic 记录")
            if name == "observation":
                status = row.get("missing_status")
                value = row.get("value")
                if status is None:
                    report.fail(f"datasets.observation[{index}] 缺 missing_status")
                elif status != "present" and value is not None:
                    report.fail(f"datasets.observation[{index}] 缺失态带数值（{status}）")
                elif status == "present" and value is None:
                    report.fail(f"datasets.observation[{index}] present 但无值")

    # 禁用键 / 私有路径 / 密钥（复用产品契约；命中项只报告位置）
    forbidden = _HOOKS.get("find_forbidden_keys")
    patterns = _iter_csv_patterns(_HOOKS.get("forbidden_key_patterns") or ())
    if forbidden is not None and patterns:
        for hit in forbidden(bundle, patterns):
            report.fail(f"禁用键命中：{hit}")
    else:
        for hit in _builtin_forbidden_keys(bundle):
            report.fail(f"禁用键命中（内置规则）：{hit}")

    # 按值扫描私有路径（用产品的"容忍 URL 主机名"语义；只报告路径前缀）
    leaks = find_private_paths_in_payload(bundle)
    if leaks:
        report.fail(f"导出包出现私有路径（{len(leaks)} 处）：{sorted(leaks)[:3]}")

    scan = scan_payload_text(directory)
    report.facts["scan"] = {k: v for k, v in scan.items() if k not in {"secret_hits", "path_hits"}}
    for hit in scan["secret_hits"]:
        report.fail(f"导出包疑似密钥值：{hit['file']}:{hit['line']}（规则 {hit['rule']}）")
    for hit in scan["path_hits"]:
        report.fail(
            f"导出包出现私有路径：{hit['file']}:{hit['line']}（前缀 {hit['matched_prefix']!r}）"
        )

    # 理由封闭语法（有契约时用产品判定，无契约时至少校验结构）
    is_valid_reason = _HOOKS.get("is_valid_reason")
    partition = _HOOKS.get("partition_reasons")
    for group in ("publication_decisions", "denied"):
        for index, record in enumerate(bundle.get(group) or []):
            if not isinstance(record, dict):
                report.fail(f"{group}[{index}] 不是对象")
                continue
            reasons = record.get("reasons") or []
            if not isinstance(reasons, list):
                report.fail(f"{group}[{index}].reasons 必须是数组")
                continue
            if is_valid_reason is not None:
                for reason in reasons:
                    if not is_valid_reason(reason):
                        report.fail(f"{group}[{index}].reasons 非封闭代码：{reason!r}")
                note = record.get("attribution_note")
                if note is not None and not is_valid_reason(note):
                    report.fail(f"{group}[{index}].attribution_note 非封闭代码")
            decision = record.get("decision")
            if partition is not None:
                try:
                    parts = partition(reasons)
                except ValueError as exc:
                    report.fail(f"{group}[{index}].reasons 分类失败：{exc}")
                    continue
                if decision in {"deny", "hold"} and not parts.blocking:
                    report.fail(f"{group}[{index}] decision={decision} 却无阻断原因")
                if decision in {"allow", "allow_with_attribution"} and parts.blocking:
                    report.fail(f"{group}[{index}] decision={decision} 却含阻断原因")
            else:
                if decision in {"deny", "hold"} and not reasons:
                    report.fail(f"{group}[{index}] decision={decision} 却无理由")
                if decision in {"allow", "allow_with_attribution"} and reasons:
                    blocking = [r for r in reasons if isinstance(r, str) and r.split(";")[0] in _BLOCKING_CODES]
                    if blocking:
                        report.fail(f"{group}[{index}] decision={decision} 却含阻断原因")

    _digest_matches_manifest(directory, report.problems)
    if report.problems:
        report.ok = False
    return report


#: 无契约时的最小阻断代码集合（只用于"结构自洽"兜底判断，不替代产品判定）。
_BLOCKING_CODES = {
    "permission_not_registered",
    "permission_unknown",
    "review_basis_missing",
    "condition_unsatisfied",
    "scope_condition_unsatisfied",
    "scope_unknown",
    "synthetic_record",
    "superseded_version_not_published",
    "hold_pending_review",
}


def _builtin_forbidden_keys(payload, path: str = "") -> list[str]:
    """内置禁用键检查（与产品契约的 glob 语义对齐：``*`` 通配任意长度 ``[]`` 字符）。"""

    patterns = (
        "private_path",
        "*_private_path",
        "private_*",
        "*_secret*",
        "*_token*",
        "*api_key*",
        "*password*",
        "excerpt_text",
        "db_path",
        "local_path",
        "raw_file_path",
    )
    hits: list[str] = []

    def walk(node, prefix: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                key_text = str(key)
                for pattern in patterns:
                    if globlib.fnmatchcase(key_text.lower(), pattern.lower()):
                        hits.append(f"{prefix}.{key_text}")
                        break
                walk(value, f"{prefix}.{key_text}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{prefix}[{index}]")

    walk(payload, path)
    return hits


# --------------------------------------------------------------------------------------
# 站点载荷闸门
# --------------------------------------------------------------------------------------


#: 站点构建**实际产出**的目录（只有这些前缀下的文件才允许发布）。
#: 路径白名单比扩展名白名单更强：仅靠扩展名会放过"任意路径下的 .md/.txt/.html 杂项文档"。
ALLOWED_PAYLOAD_PATH_ROOTS = (
    "_astro/",
    "data/",
    "_pagefind/",
)

#: 站点根允许的固定文件（构建/发布身份产物；其余根级文件一律拒绝）。
ALLOWED_ROOT_FILES = (
    "index.html",
    "404.html",
    "robots.txt",
    "sitemap.xml",
    "favicon.svg",
    "favicon.ico",
    "manifest.webmanifest",
    "site.webmanifest",
    "_redirects",
    "_headers",
    "CNAME",
    ".nojekyll",
    "PUBLISH_MANIFEST.json",
    "status.json",
)

#: 允许出现在**路由目录**（如 `event/<id>/`、`about/`）里的文件类型。
#: 路由名无法在工具侧独立推导（由 web 构建决定），因此这一档是**已知弱点**：
#: 它只保证"路由目录里不会出现数据/文档类文件"（.md/.json/.csv/.txt…），
#: 见 README「已知限制」。路径与扩展名的**双白名单**已覆盖根目录与资源目录。
ALLOWED_ROUTE_FILE_SUFFIXES = (
    # 页面与前端资源（路由目录里只会出现这些）
    ".html",
    ".htm",
    ".js",
    ".mjs",
    ".css",
    ".map",
    ".json",
    # 图片与字体（构建会把它们放在路由/资源目录下）
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".ico",
    ".avif",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    # 站点元数据
    ".xml",
    ".txt",
    ".webmanifest",
)


def _classify_payload_path(relative: str) -> tuple[str, str]:
    """把载荷相对路径分类成 ``(类别, 原因)``；类别为 ``allowed`` / ``root`` / ``route`` / ``denied``。"""

    path = PurePosixPath(relative)
    parts = path.parts
    name = parts[-1]
    suffix = PurePosixPath(name).suffix.lower()
    lowered = relative.lower()

    if any(part in FORBIDDEN_PAYLOAD_PATH_PARTS for part in parts[:-1]):
        return "denied", f"载荷出现禁止的目录（私有数据/中间态）：{relative}"
    if name in FORBIDDEN_PAYLOAD_FILE_NAMES:
        return "denied", f"载荷出现禁止的文件名：{relative}"
    if lowered.endswith(FORBIDDEN_PAYLOAD_FILE_SUFFIXES):
        return "denied", f"载荷出现禁止的文件类型：{relative}"
    if name.startswith(".env"):
        return "denied", f"载荷出现环境文件：{relative}"

    if len(parts) == 1:
        if name in ALLOWED_ROOT_FILES:
            if suffix and suffix not in ALLOWED_PAYLOAD_SUFFIXES:
                return "denied", f"根级文件扩展名未登记：{relative}"
            return "root", ""
        return "denied", (
            f"站点根出现未登记的构建产物：{relative}"
            "（根目录只允许 index.html/404.html/robots.txt/sitemap.xml/favicon.*/_redirects/_headers/"
            "CNAME/.nojekyll/PUBLISH_MANIFEST.json/status.json）"
        )

    top = parts[0] + "/"
    if top in ALLOWED_PAYLOAD_PATH_ROOTS:
        if suffix not in ALLOWED_PAYLOAD_SUFFIXES and not any(
            lowered.endswith(item) for item in (".pf_fragment", ".pf_index", ".pf_meta", ".pagefind", ".unknown")
        ):
            return "denied", f"资源目录内扩展名未登记（{suffix or '<无>'}）：{relative}"
        return "allowed", ""

    # 其余一律视为**路由目录**：只允许构建产出的页面/资源类型
    if suffix in ALLOWED_ROUTE_FILE_SUFFIXES:
        return "route", ""
    return "denied", (
        f"路由目录内出现非构建产物类型：{relative}"
        f"（扩展名 {suffix or '<无>'}；路由目录只允许 "
        f"{', '.join(ALLOWED_ROUTE_FILE_SUFFIXES)}）"
    )


def _check_payload_file_names(directory: Path, report: GateReport) -> None:
    """路径 + 扩展名**双白名单**（fail closed）：只允许站点构建真正产出的文件。"""

    counts = {"allowed": 0, "root": 0, "route": 0, "denied": 0}
    for relative, _absolute in _iter_files(directory):
        kind, reason = _classify_payload_path(relative)
        counts[kind] += 1
        if kind == "denied":
            report.fail(reason)
    report.facts["payload_paths"] = counts
    report.facts["allowed_payload_files"] = counts["allowed"] + counts["root"] + counts["route"]


def _is_benign(relative: str, text: str, marker: str) -> bool:
    """判断命中是否属于"站点自带的说明/枚举文案"（不算违规）。"""

    if relative.endswith((".html", ".htm", ".js", ".mjs", ".css", ".map")):
        # 渲染后的界面与打包脚本里出现这些词，通常是在**说明数据边界**或列出枚举值；
        # 判据是"同一文件里还出现了边界说明/枚举上下文"，且**没有**真正的导出行。
        context = (
            "本页面的数据边界",
            "missing_status",
            "not_disclosed",
            "不含私有路径",
            "口径",
            "preview_excluded",
            "private-preview",
        )
        if any(item in text for item in context):
            return True
    return False


def _check_non_json_text_markers(directory: Path, report: GateReport) -> None:
    """非 JSON 文本的"私有/候选内容"检查（F5），区分**真泄露**与**站点文案**。

    * ``UNAMBIGUOUS_CONTENT_MARKERS``：任何文本文件命中即失败（这些词只可能来自内部素材）；
    * ``DATA_ONLY_CONTENT_MARKERS``：只在数据类文件（md/csv/yaml/txt/jsonl…）里检查 ——
      真实站点文案（HTML/JS）里的"原文摘录"是字段说明，不是内容；
    * ``BENIGN_SITE_MARKERS`` + ``_is_benign``：显式排除实测确认合法的界面文案。
    """

    for relative, absolute in _iter_files(directory):
        if absolute.name.endswith(".json"):
            continue
        try:
            if absolute.stat().st_size > 8 * 1024 * 1024:
                continue
            text = absolute.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lowered = text.lower()
        for marker in UNAMBIGUOUS_CONTENT_MARKERS:
            if marker.lower() in lowered:
                report.fail(f"载荷文本含私有内容标记（{marker}）：{relative}")
                break
        else:
            if relative.lower().endswith(_DATA_LIKE_SUFFIXES):
                for marker in DATA_ONLY_CONTENT_MARKERS:
                    if marker.lower() in lowered and not _is_benign(relative, text, marker):
                        report.fail(f"数据文件含原文摘录/候选内容标记（{marker}）：{relative}")
                        break
        for key in FORBIDDEN_PAYLOAD_TEXT_KEYS:
            if relative.lower().endswith((".js", ".mjs")):
                # 程序词汇不是数据字段：URL.password 属性、拒绝词表里的 'password' 都合法。
                # 不改编译产物去隐藏词；真正的字段/变量赋予非空字面值仍拒绝，且所有文件
                # 的密钥值和宿主路径扫描在 _scan_dir_for_private_data 中保持不变。
                found = re.search(
                    rf"(?<![A-Za-z0-9_$])(?:[\"']{re.escape(key)}[\"']|{re.escape(key)})"
                    rf"\s*(?::|=(?!=))\s*([\"'])([^\"'\r\n]+)\1",
                    text,
                    re.IGNORECASE,
                )
            else:
                found = re.search(rf"[\"'>\s(]{{0,1}}{re.escape(key)}[\"':=\s>)]", lowered)
            if found:
                report.fail(f"载荷文本含禁用键形态（{key}）：{relative}")
                break


def _find_data_files(directory: Path, name: str, *, max_depth: int = 4) -> list[Path]:
    """找出载荷里的数据文件（``data/**`` 与站点根），跳过 node_modules 之类的意外目录。"""

    found: list[Path] = []
    for current, dirnames, filenames in os.walk(directory, followlinks=False):
        current_path = Path(current)
        relative = current_path.relative_to(directory)
        if len(relative.parts) >= max_depth:
            dirnames[:] = []
        if "node_modules" in dirnames:
            dirnames.remove("node_modules")
        if name in filenames:
            found.append(current_path / name)
    return sorted(found)


def _check_site_data_facts(directory: Path, report: GateReport) -> None:
    """核对站点实际数据文件：公开、非演示、非私有预览、无 synthetic 记录。"""

    bundles = _find_data_files(directory, "bundle.json")
    indexes = _find_data_files(directory, "index.json")
    report.facts["data_files"] = {
        "bundle_json": [str(path.relative_to(directory)) for path in bundles],
        "index_json": [str(path.relative_to(directory)) for path in indexes],
    }
    if not bundles and not indexes:
        report.warn("载荷内未找到 bundle.json / index.json：无法核验站点数据的公开性与非演示性")
    for path in bundles:
        relative = path.relative_to(directory)
        try:
            bundle = read_json_object(path, where=f"站点数据 {relative}")
        except Exception as exc:  # noqa: BLE001
            report.fail(str(exc))
            continue
        if bundle.get("is_demo") is not False:
            report.fail(f"{relative} 的 is_demo 必须为 false（实际 {bundle.get('is_demo')!r}）")
        if bundle.get("data_mode") != "public":
            report.fail(f"{relative} 的 data_mode 必须是 public（实际 {bundle.get('data_mode')!r}）")
        kind = bundle.get("dataset_kind")
        if kind is not None and kind != "real":
            report.fail(f"{relative} 的 dataset_kind 必须是 real（实际 {kind!r}）")
        if bundle.get("preview_excluded"):
            report.fail(f"{relative} 是私有预览产物（含 preview_excluded）")
        for name, rows in (bundle.get("datasets") or {}).items():
            if not isinstance(rows, list):
                continue
            for index, row in enumerate(rows):
                if isinstance(row, dict) and row.get("dataset_kind") == "synthetic":
                    report.fail(f"{relative} 的 datasets.{name}[{index}] 是 synthetic 记录")
                    break
    for path in indexes:
        relative = path.relative_to(directory)
        try:
            index = read_json_object(path, where=f"站点索引 {relative}")
        except Exception as exc:  # noqa: BLE001
            report.fail(str(exc))
            continue
        if index.get("is_demo"):
            report.fail(f"{relative} 的 is_demo 为真（演示数据不得进入公开产物）")
        if index.get("data_mode") not in {None, "public"}:
            report.fail(f"{relative} 的 data_mode 必须是 public（实际 {index.get('data_mode')!r}）")
        if "synthetic" in (index.get("dataset_kinds") or []):
            report.fail(f"{relative} 的 dataset_kinds 含 synthetic")
        if index.get("preview_excluded"):
            report.fail(f"{relative} 是私有预览产物（含 preview_excluded）")
        disclaimer = str(index.get("disclaimer") or "").replace("：", ":")
        for marker in _PREVIEW_MARKERS + _SYNTHETIC_MARKERS:
            if marker.replace("：", ":") in disclaimer:
                report.fail(f"{relative} 的 disclaimer 声明了非公开数据（{marker}）")
        source = index.get("source")
        if isinstance(source, str) and source.strip():
            for leak in _FALLBACK_PRIVATE_PATH_VALUE.findall(source):
                report.fail(f"{relative} 的 source 字段含本机绝对路径（前缀 {leak[:24]!r}）")


def read_indexing_metadata(directory: Path) -> dict:
    """读取站点的"是否允许被搜索引擎收录"声明（robots.txt + `<meta name="robots">`）。

    返回 ``{"robots": "index"|"noindex"|"absent", "meta": ..., "effective": ..., "evidence": {...}}``。
    ``effective`` 是两者的一致结论；不一致时为 ``"conflict"``（调用方按闸门失败处理）。

    注意语义：**noindex ≠ 内容不安全**。首发试运行保留 noindex 是合法选择，
    这里只负责"如实登记 + 一致性校验"。
    """

    directory = Path(directory)
    robots_choice = "absent"
    robots_file = directory / "robots.txt"
    if robots_file.is_file():
        text = robots_file.read_text(encoding="utf-8", errors="ignore")
        disallow_all = False
        allow_all = False
        for match in re.finditer(r"(?im)^\s*(Disallow|Allow)\s*:\s*(\S*)\s*$", text):
            value = match.group(2)
            if match.group(1).lower() == "disallow" and value in {"", "/", "*"}:
                disallow_all = True
            if match.group(1).lower() == "allow" and value in {"/", "*"}:
                allow_all = True
        if disallow_all and allow_all:
            robots_choice = "conflict"
        elif disallow_all:
            robots_choice = "noindex"
        elif allow_all:
            robots_choice = "index"

    meta_choice = "absent"
    meta_value = None
    index_html = directory / "index.html"
    if index_html.is_file():
        html = index_html.read_text(encoding="utf-8", errors="ignore")
        match = re.search(
            r'<meta\s+[^>]*name=["\']robots["\'][^>]*content=["\']([^"\']*)["\']',
            html,
            re.IGNORECASE,
        )
        if match is None:
            match = re.search(
                r'<meta\s+[^>]*content=["\']([^"\']*)["\'][^>]*name=["\']robots["\']',
                html,
                re.IGNORECASE,
            )
        if match is not None:
            meta_value = match.group(1).strip()
            lowered = meta_value.lower()
            has_noindex = "noindex" in lowered
            has_index = bool(re.search(r"(?<![a-z])index(?![a-z])", lowered))
            if has_noindex and has_index:
                meta_choice = "conflict"
            elif has_noindex:
                meta_choice = "noindex"
            elif has_index:
                meta_choice = "index"

    present = [value for value in (robots_choice, meta_choice) if value != "absent"]
    if not present:
        effective = "absent"
    elif len(set(present)) == 1:
        effective = present[0]
    else:
        effective = "conflict"
    return {
        "robots": robots_choice,
        "meta": meta_choice,
        "effective": effective,
        "evidence": {
            "robots_txt": robots_choice,
            "meta_robots_content": meta_value,
            "note": "noindex 表示首发试运行不参与搜索收录；与内容是否公开无关",
        },
    }


#: 同步阶段**允许**被站点构建改写的 bundle 字段（其余字段必须与审核导出包逐字节一致）。
#:
#: * ``generated_at`` 等是构建时间戳/来源说明，每次构建都会变；
#: * ``export_bundle_sha256`` 是"站点自带的来源摘要"（provenance），它**指向**审核导出包，
#:   因此不能参与"内容与导出包一致"的比较 —— 它会由下面的摘要校验单独核对。
_EXPORT_BINDING_VOLATILE_FIELDS = (
    "generated_at",
    "source",
    "index_version",
    "notes",
    "export_bundle_sha256",
)


def _canonical_bundle_for_binding(payload: dict) -> bytes:
    """去掉同步阶段合法改写的字段后做确定性序列化，用于与审核导出包比对。"""

    pruned = {key: value for key, value in payload.items() if key not in _EXPORT_BINDING_VOLATILE_FIELDS}
    return json.dumps(pruned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _check_export_binding(
    directory: Path,
    report: GateReport,
    *,
    expected_export_bundle: Path | None,
    expected_export_digest: str | None,
) -> None:
    """站点数据必须与**已审核的导出包**绑定：防止"站点 bundle 自洽就通过"式旁路。"""

    site_bundles = _find_data_files(directory, "bundle.json")
    if not site_bundles:
        report.fail("站点载荷内没有 bundle.json：无法证明站点数据来自已审核的导出包")
        return
    expected_payload: dict | None = None
    if expected_export_bundle is not None:
        expected_path = Path(expected_export_bundle)
        if not expected_path.is_file():
            report.fail(f"用于绑定的审核导出包不存在：{expected_path}")
            return
        try:
            expected_payload = read_json_object(expected_path, where="审核导出 bundle.json")
        except Exception as exc:  # noqa: BLE001
            report.fail(str(exc))
            return
        expected_digest = hashlib.sha256(expected_path.read_bytes()).hexdigest()
        if expected_export_digest is not None and expected_export_digest != expected_digest:
            report.fail(
                "审核导出包的字节摘要与期望不一致："
                f"{expected_digest} != {expected_export_digest}（导出包可能已被改动）"
            )
    else:
        expected_digest = expected_export_digest

    for path in site_bundles:
        relative = path.relative_to(directory)
        try:
            site_bundle = read_json_object(path, where=f"站点数据 {relative}")
        except Exception as exc:  # noqa: BLE001
            report.fail(str(exc))
            continue
        if expected_payload is not None:
            if _canonical_bundle_for_binding(site_bundle) != _canonical_bundle_for_binding(expected_payload):
                report.fail(
                    f"{relative} 的数据集内容与审核导出包不一致："
                    "站点数据必须来自 --export 指向的已审核导出（不允许站点自带一份数据）"
                )
            else:
                report.facts.setdefault("export_binding", {})[str(relative)] = {
                    "bound_to": str(expected_export_bundle),
                    "match": True,
                }
        recorded = site_bundle.get("export_bundle_sha256") or (
            (site_bundle.get("manifest") or {}).get("export_bundle_sha256")
            if isinstance(site_bundle.get("manifest"), dict)
            else None
        )
        if expected_digest is not None:
            if recorded is None:
                report.warn(
                    f"{relative} 未记录 export_bundle_sha256：本次按内容比对通过，"
                    "建议由 web/ 侧在数据里带上导出包摘要以便事后核对"
                )
            elif recorded != expected_digest:
                report.fail(
                    f"{relative} 记录的 export_bundle_sha256 与实际审核导出包不一致："
                    f"{recorded} != {expected_digest}"
                )


def check_site_payload(
    directory: Path,
    *,
    expected_build_id: str | None = None,
    expected_release_version: str | None = None,
    expected_payload_sha256: str | None = None,
    expected_site_url: str | None = None,
    expected_base_path: str | None = None,
    data_root: Path | None = None,
    require_manifest: bool = True,
    manifest_name: str | None = MANIFEST_FILENAME,
    status_name: str | None = STATUS_FILENAME,
    expected_indexing: str | None = None,
    expected_export_bundle: Path | None = None,
    expected_export_digest: str | None = None,
) -> GateReport:
    """渲染站点载荷的发布前闸门（真实站点目录，不是"label 成 pass"）。

    ``manifest_name``/``status_name`` 传 ``None`` 时跳过这两个文件的检查与对齐 —— 只用于
    "发布身份尚未写入"的 preflight 阶段；任何真正的发布判定都必须保留默认值（fail closed）。
    """

    report = GateReport(name="site_payload", ok=True)
    directory = Path(directory)
    report.facts["directory"] = str(directory)
    if not directory.is_dir():
        report.fail(f"站点载荷目录不存在：{directory}")
        return report

    required_files = [
        "index.html",
        *([manifest_name] if manifest_name else []),
        *([status_name] if status_name else []),
    ]
    for required in required_files:
        if not (directory / required).is_file():
            report.fail(f"站点载荷缺少必需文件：{required}")

    # 1) 私有/合成声明
    scan = scan_payload_text(directory)
    report.facts["scan"] = {k: v for k, v in scan.items() if k not in {"secret_hits", "path_hits"}}
    for hit in scan["secret_hits"]:
        report.fail(f"站点载荷疑似密钥值：{hit['file']}:{hit['line']}（规则 {hit['rule']}）")
    for hit in scan["path_hits"]:
        report.fail(
            f"站点载荷出现私有路径：{hit['file']}:{hit['line']}（前缀 {hit['matched_prefix']!r}）"
        )

    # 1a) 站点数据必须来自**已审核的导出包**：不能"站点自己的 bundle 自洽就通过"。
    #     判据：站点 `data/<mode>/bundle.json` 的**数据集内容**（去掉同步阶段合法改写的
    #     generated_at/source 等字段）必须与 `--export` 的 bundle.json 逐字节一致，
    #     并且站点 bundle 记录的 export 摘要（若存在）必须等于实际 export 摘要。
    if expected_export_bundle is not None or expected_export_digest is not None:
        _check_export_binding(
            directory,
            report,
            expected_export_bundle=expected_export_bundle,
            expected_export_digest=expected_export_digest,
        )

    # 1b) 数据事实闸门：**只看数据文件**，不看打包进去的提示文案。
    #
    #     站点 bundle 里本来就有"合成演示数据/本地私有预览数据"的横幅文案（UI 条件渲染），
    #     按字符串搜会把正常公开构建判成失败 —— 那只会逼人削弱闸门。真正的判据是**数据本身**：
    #     is_demo / dataset_kind / dataset_kinds / disclaimer / preview_excluded。
    _check_site_data_facts(directory, report)

    if data_root is not None:
        root_text = str(Path(data_root).expanduser().resolve())
        for relative, absolute in _iter_files(directory):
            if absolute.stat().st_size > 8 * 1024 * 1024:
                continue
            try:
                text = absolute.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if root_text and root_text in text:
                report.fail(f"载荷内出现本地运行数据根路径：{relative}")

    # 2) 文件名/类型（白名单）+ 非 JSON 文本的私有/候选标记
    _check_payload_file_names(directory, report)
    _check_non_json_text_markers(directory, report)

    # 3) 发布清单与状态文件一致性（**发布身份的硬闸门**）
    manifest_path = directory / manifest_name if manifest_name else None
    status_path = directory / status_name if status_name else None
    manifest: dict = {}
    status: dict = {}
    if manifest_path is not None and manifest_path.is_file():
        try:
            manifest = read_json_object(manifest_path, where=f"站点 {MANIFEST_FILENAME}")
        except Exception as exc:  # noqa: BLE001
            report.fail(str(exc))
        else:
            problems: list[str] = []
            check_release_provenance(manifest, problems)
            report.problems.extend(problems)
            report.facts["manifest"] = {
                "release_version": manifest.get("release_version"),
                "build_id": manifest.get("build_id"),
                "payload_sha256": (manifest.get("payload") or {}).get("sha256"),
            }
    elif require_manifest and manifest_name:
        report.fail(f"站点载荷缺少 {manifest_name}（没有发布清单就不能发布）")

    if status_path is not None and status_path.is_file():
        try:
            status = read_json_object(status_path, where=f"站点 {STATUS_FILENAME}")
        except Exception as exc:  # noqa: BLE001
            report.fail(str(exc))
        else:
            for key in ("release_version", "build_id", "payload_sha256"):
                if not status.get(key):
                    report.fail(f"{status_name} 缺少 {key}（部署后核验无法判定线上产物）")
            if manifest and status.get("build_id") != manifest.get("build_id"):
                report.fail(
                    f"{status_name} 与 {manifest_name} 的 build_id 不一致："
                    f"{status.get('build_id')!r} vs {manifest.get('build_id')!r}"
                )
            if manifest and status.get("payload_sha256") != (manifest.get("payload") or {}).get("sha256"):
                report.fail(f"{status_name} 与 {manifest_name} 的载荷摘要不一致")
            report.facts["status"] = {
                "release_version": status.get("release_version"),
                "build_id": status.get("build_id"),
            }

    # 4) 与外部期望值对齐（调用方给出的版本/摘要/站点地址）
    if expected_build_id is not None:
        actual = (status or manifest).get("build_id")
        if actual != expected_build_id:
            report.fail(f"build_id 与期望不一致：{actual!r} != {expected_build_id!r}")
    if expected_release_version is not None:
        actual = (status or manifest).get("release_version")
        if actual != expected_release_version:
            report.fail(f"release_version 与期望不一致：{actual!r} != {expected_release_version!r}")
    if expected_payload_sha256 is not None:
        # payload.sha256 是**站点自身内容**摘要（`status.json` 里的 payload_sha256 也是它）；
        # `payload.packaged_sha256` 是"内容 + 清单 + 状态文件"的摘要，另一回事，不能混用。
        candidates = []
        if manifest:
            candidates.append(("manifest.payload.sha256", (manifest.get("payload") or {}).get("sha256")))
        if status:
            candidates.append(("status.payload_sha256", status.get("payload_sha256")))
        mismatched = [(label, value) for label, value in candidates if value != expected_payload_sha256]
        if mismatched:
            detail = ", ".join(f"{label}={value!r}" for label, value in mismatched)
            report.fail(
                f"站点内容摘要与期望不一致：{detail} != {expected_payload_sha256!r}"
            )
    if expected_site_url is not None and manifest:
        actual = (manifest.get("site") or {}).get("url")
        if actual != expected_site_url:
            report.fail(f"清单 site.url 与期望不一致：{actual!r} != {expected_site_url!r}")
    if expected_base_path is not None and manifest:
        actual = (manifest.get("site") or {}).get("base_path")
        if actual != expected_base_path:
            report.fail(f"清单 site.base_path 与期望不一致：{actual!r} != {expected_base_path!r}")

    # 4b) 部署就绪：`<base>` 必须与项目站点 base path 一致，且不得自带"禁止收录"
    #     （实测：默认构建把 `<base href="/">` + `robots.txt: Disallow: /` + canonical 指向
    #      localhost 一起带出来；如果只检查"有 index.html"，这些会一路带到线上才发现）
    index_path = directory / "index.html"
    if index_path.is_file():
        html_probe = index_path.read_text(encoding="utf-8", errors="ignore")
        base_match = re.search(r"<base\s+[^>]*href=[\"']([^\"']*)[\"']", html_probe, re.IGNORECASE)
        if base_match is None:
            report.warn("index.html 未声明 <base>：子路径项目站点可能出现资源 404（请人工确认）")
        else:
            declared_base = base_match.group(1)
            if expected_base_path is not None and expected_base_path != "/":
                wanted = expected_base_path.rstrip("/") + "/"
                if declared_base != wanted:
                    report.fail(
                        f"index.html 的 <base href> 与项目站点 base 不一致："
                        f"{declared_base!r} != {wanted!r}（站点会按根路径解析资源，线上会 404）"
                    )
        # 索引元数据（**不是内容安全项**）：robots.txt 与 <meta name="robots"> 都是"是否允许搜索
        # 引擎收录"的声明。首发试运行**保留**默认 noindex 是合法且常见的做法，因此这里只做
        # **声明一致性与登记**，不把 noindex 当成内容不安全：
        #   * robots.txt 与 meta 必须一致（一边 noindex、一边 allow 视为配置矛盾 → 拒绝）；
        #   * 期望的 indexing 选择（若调用方给出）必须与实际一致；
        #   * 选择会写进发布清单/status.json，便于事后核对"这一版到底允不允许被收录"。
        indexing = read_indexing_metadata(directory)
        report.facts["indexing"] = indexing
        if indexing["robots"] == "conflict" or indexing["meta"] == "conflict":
            report.fail(
                "robots.txt 与 <meta name=\"robots\"> 的收录声明互相矛盾（robots=%s, meta=%s）"
                % (indexing["robots"], indexing["meta"])
            )
        if indexing["effective"] == "conflict":
            report.fail("robots.txt 与 meta robots 的收录声明不一致：无法确定本版是否允许被收录")
        if expected_indexing is not None:
            if expected_indexing not in {"index", "noindex"}:
                report.fail(f"expected_indexing 取值非法：{expected_indexing!r}")
            elif indexing["effective"] != expected_indexing:
                report.fail(
                    f"收录声明与期望不一致：实际 {indexing['effective']} != 期望 {expected_indexing}"
                    "（若确实要改收录策略，请显式传 --indexing 并在发布记录里留痕）"
                )

    # 5) 站点入口必须可解析（避免"空白页也算成功"）
    index = directory / "index.html"
    if index.is_file():
        html = index.read_text(encoding="utf-8", errors="ignore")
        if len(html.strip()) < 200:
            report.fail("index.html 过短（疑似空壳页面）")
        if "<html" not in html.lower():
            report.fail("index.html 不是 HTML 文档")
        if expected_base_path is not None and expected_base_path != "/":
            base = expected_base_path.rstrip("/")
            if f'href="{base}/' not in html and f'src="{base}/' not in html and f'"{base}/' not in html:
                report.fail(f"index.html 内未见项目站点 base（{base}/）：站点可能构建成了根路径版本")

    if report.problems:
        report.ok = False
    return report


# --------------------------------------------------------------------------------------
# 发布来源（provenance）闸门
# --------------------------------------------------------------------------------------


def check_release_provenance(manifest: dict, problems: list[str]) -> None:
    """核对发布清单的来源字段；缺来源或自相矛盾即记录问题（fail closed）。"""

    if not isinstance(manifest, dict):
        problems.append("发布清单不是对象")
        return
    for key in ("release_version", "build_id", "payload", "package", "provenance", "target", "site"):
        if key not in manifest:
            problems.append(f"发布清单缺少 {key}")
    release_version = manifest.get("release_version")
    if not isinstance(release_version, str) or not release_version:
        problems.append("发布清单 release_version 缺失")
    build_id = manifest.get("build_id")
    if not isinstance(build_id, str) or not build_id.startswith("rf-build-"):
        problems.append(f"发布清单 build_id 缺失或形式不合法：{build_id!r}")
    payload = manifest.get("payload") or {}
    digest = payload.get("sha256")
    if not isinstance(digest, str) or not re.match(r"^[0-9a-f]{64}$", digest):
        problems.append(f"发布清单 payload.sha256 缺失或非法：{digest!r}")
    package = manifest.get("package") or {}
    package_sha = package.get("sha256")
    if isinstance(package_sha, str) and re.match(r"^[0-9a-f]{64}$", package_sha):
        pass
    elif manifest.get("package_sha256_source") == "external":
        # 包内清单**无法自指**包含它自己的包的摘要：这种情况必须显式声明
        # package_sha256_source=external，且真实摘要由发布资产 SHA256SUMS + 工作流输入共同锚定。
        pass
    else:
        problems.append(
            "发布清单 package.sha256 缺失或非法（包内清单请显式声明 package_sha256_source=external）"
        )
    if not package.get("name"):
        problems.append("发布清单 package.name 缺失")
    provenance = manifest.get("provenance") or {}
    if not provenance.get("snapshot_id"):
        problems.append("发布清单 provenance.snapshot_id 缺失（来源不可追溯）")
    if not provenance.get("data_cutoff"):
        problems.append("发布清单 provenance.data_cutoff 缺失")
    target = manifest.get("target") or {}
    if not target.get("owner") or not target.get("repo"):
        problems.append("发布清单 target.owner/target.repo 缺失")
    if target.get("slug") and target.get("owner") and target.get("repo"):
        if target["slug"] != f"{target['owner']}/{target['repo']}":
            problems.append("发布清单 target.slug 与 owner/repo 不一致")
    site = manifest.get("site") or {}
    if not str(site.get("url", "")).startswith("https://"):
        problems.append("发布清单 site.url 缺失或不是 https")
    if not str(site.get("base_path", "")).startswith("/"):
        problems.append("发布清单 site.base_path 缺失或不是 / 开头")


def check_expected_target(
    manifest: dict, *, expected_owner: str, expected_repo: str
) -> list[str]:
    """把清单里的发布目标与"用户已确认的目标"逐字比对。"""

    problems: list[str] = []
    target = manifest.get("target") or {}
    if target.get("owner") != expected_owner or target.get("repo") != expected_repo:
        problems.append(
            "发布目标与已确认目标不一致："
            f"清单 {target.get('owner')!r}/{target.get('repo')!r}"
            f" != 已确认 {expected_owner!r}/{expected_repo!r}"
        )
    return problems


def iter_site_files(directory: Path) -> Iterator[tuple[str, Path]]:
    """按排序产出站点载荷里的文件（供打包前后对比使用）。"""

    return _iter_files(Path(directory))
