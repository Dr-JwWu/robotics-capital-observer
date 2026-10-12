"""发布清单、站点状态文件与确定性发布标识（release identity）。

术语（**三个标识必须区分清楚**，示例工作流原先把它们混成一个 ``VERSION``）
--------------------------------------------------------------------------

``release_version``
    人可读、不可变的**发布版本号**（默认 ``YYYY-MM-DDTHH-MMZ``）。它同时是 GitHub Release 的
    **tag**，因此必须是受约束的安全字符串（只允许 ``[A-Za-z0-9._+-]``、不允许 ``..``/``/``）。
``build_id``
    **构建标识**，由 ``code_version`` + 载荷内容摘要派生（``rf-build-<16 位摘要>``）。
    它回答"线上跑的是不是这一份产物"，与人类版本号**不同**：同一版本号若被误重打成不同内容，
    ``build_id`` 一定不同，从而在部署后核验阶段暴露。
``payload_sha256`` / ``package_sha256``
    载荷目录内容摘要 / 发布包（``tar.gz``）字节摘要。工作流校验的是 ``package_sha256``，
    解包后再对比 ``payload_sha256``，两者都进清单。

清单与状态文件都是**确定性 JSON**（``sort_keys=True``、两空格缩进、末尾换行），
因此同一份载荷 + 同一批输入得到同一份清单字节。
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .safe_archive import ArchiveError

__all__ = [
    "MANIFEST_FILENAME",
    "STATUS_FILENAME",
    "GitHubTarget",
    "ReleaseInputs",
    "validate_release_version",
    "canonical_json",
    "compute_build_id",
    "compute_code_version",
    "build_manifest",
    "build_site_status",
    "manifest_bytes",
    "status_bytes",
    "utc_stamp",
    "read_json_object",
    "assert_public_safe_manifest",
    "assert_no_private_inventory",
    "compact_gate_summary",
]

#: 随站点一起发布的清单/状态文件名（放在站点根目录，公开可见，因此**不得**含私有信息）。
MANIFEST_FILENAME = "PUBLISH_MANIFEST.json"
STATUS_FILENAME = "status.json"

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def utc_stamp(moment: datetime | None = None) -> str:
    """``YYYY-MM-DDTHH-MMZ`` 形式的人可读版本号（可直接用作 git tag / Release tag）。"""

    moment = moment or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H-%MZ")


def utc_now() -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` 形式的确定性可比较时间戳。"""

    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(payload: object) -> bytes:
    """确定性 JSON 字节（排序键 + 两空格缩进 + 末尾换行）。"""

    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def read_json_object(path: Path, *, where: str) -> dict:
    """读取一个 JSON 对象；不存在/不可解析/非对象一律报错（fail closed）。"""

    path = Path(path)
    if not path.is_file():
        raise ArchiveError(f"{where} 不存在：{path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ArchiveError(f"{where} 不是合法 JSON：{path}（{exc}）") from exc
    if not isinstance(payload, dict):
        raise ArchiveError(f"{where} 必须是 JSON 对象：{path}")
    return payload


def validate_owner(owner: str) -> str:
    if not isinstance(owner, str) or not _OWNER_RE.match(owner):
        raise ArchiveError(f"GitHub owner 不合法：{owner!r}（只允许字母/数字/中划线，1-39 字符）")
    return owner


def validate_repo_name(name: str) -> str:
    if not isinstance(name, str) or not _REPO_RE.match(name) or ".." in name:
        raise ArchiveError(f"GitHub 仓库名不合法：{name!r}")
    return name


def validate_release_version(version: str) -> str:
    """发布版本号必须是安全的不可变字符串（会进入 GitHub tag 与本地目录名）。"""

    if not isinstance(version, str) or not _VERSION_RE.match(version):
        raise ArchiveError(
            f"发布版本不合法：{version!r}（只允许 [A-Za-z0-9._+-]，最长 64，首字符为字母或数字）"
        )
    if ".." in version or version in {".", ".."}:
        raise ArchiveError(f"发布版本不合法（不允许 ..）：{version!r}")
    return version


@dataclass(frozen=True)
class GitHubTarget:
    """已确认的发布目标。**绝不**从本地 git remote 推断，必须显式给出。"""

    owner: str
    repo: str

    def __post_init__(self) -> None:
        validate_owner(self.owner)
        validate_repo_name(self.repo)

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def pages_url(self) -> str:
        return f"https://{self.owner.lower()}.github.io/{self.repo}/"

    @property
    def pages_origin(self) -> str:
        return f"https://{self.owner.lower()}.github.io"

    def as_dict(self) -> dict:
        return {
            "owner": self.owner,
            "repo": self.repo,
            "slug": self.slug,
            "pages_url": self.pages_url,
            "pages_origin": self.pages_origin,
            "base_path": f"/{self.repo}/",
        }

    @classmethod
    def parse(cls, slug: str) -> "GitHubTarget":
        if not isinstance(slug, str) or slug.count("/") != 1:
            raise ArchiveError(f"目标仓库必须写成 owner/repo：{slug!r}")
        owner, repo = slug.split("/", 1)
        return cls(owner=owner, repo=repo)


@dataclass(frozen=True)
class ReleaseInputs:
    """构造一次发布所需的全部输入（都由 ``prepare`` 显式传入并写进清单）。"""

    version: str
    target: GitHubTarget
    site_origin: str
    base_path: str
    source_export_dir: str
    snapshot_id: str | None = None
    data_cutoff: str | None = None
    contract_version: str | None = None
    schema_version: str | None = None
    publication_policy_version: str | None = None
    git_commit: str | None = None
    git_dirty: bool = False
    lockfile_sha256: str | None = None
    previous_version: str | None = None
    indexing: str = "noindex"
    source_digest: dict | None = None
    export_bundle_sha256: str | None = None
    generated_by: str = "researcher_finance_deploy"

    def __post_init__(self) -> None:
        validate_release_version(self.version)
        if not isinstance(self.site_origin, str) or not self.site_origin.startswith("https://"):
            raise ArchiveError(f"站点 origin 必须是 https:// 开头：{self.site_origin!r}")
        if not isinstance(self.base_path, str) or not self.base_path.startswith("/"):
            raise ArchiveError(f"base_path 必须是 / 开头（项目站点形如 /repo/）：{self.base_path!r}")
        if not self.base_path.endswith("/"):
            raise ArchiveError(f"base_path 必须以 / 结尾：{self.base_path!r}")
        if ".." in self.base_path:
            raise ArchiveError(f"base_path 不合法：{self.base_path!r}")
        if self.previous_version is not None:
            validate_release_version(self.previous_version)
        if self.lockfile_sha256 is not None and not re.match(r"^sha256:[0-9a-f]{64}$", self.lockfile_sha256):
            raise ArchiveError(f"lockfile_sha256 形式不合法（应为 sha256:<64 hex>）：{self.lockfile_sha256!r}")
        if self.indexing not in {"index", "noindex"}:
            raise ArchiveError(f"indexing 只能是 index/noindex，实际 {self.indexing!r}")
        if self.export_bundle_sha256 is not None and not _SHA256_RE.match(self.export_bundle_sha256):
            raise ArchiveError(f"export_bundle_sha256 必须是 64 位十六进制：{self.export_bundle_sha256!r}")
        if self.source_digest is not None:
            digest = self.source_digest.get("sha256")
            if not _SHA256_RE.match(str(digest)):
                raise ArchiveError(f"source_digest.sha256 缺失或非法：{digest!r}")


def compute_code_version(*, commit: str | None, dirty: bool) -> str:
    """代码版本：``git-<短提交>`` 或 ``git-<短提交>-dirty`` / ``git-unknown``。

    **脏工作区不阻止本地 prepare**（真实情况往往是"先本地跑通再提交"），但会如实写进清单，
    并且 ``publish`` 会拒绝脏工作区（发布必须对应一个确定的提交）。
    """

    short = (commit or "")[:12] or "unknown"
    return f"git-{short}" + ("-dirty" if dirty else "")


def compute_build_id(*, version: str, code_version: str, payload_sha256: str) -> str:
    """构建标识 = 版本 + 代码版本 + 载荷摘要的短哈希；**与人类版本号不同**。"""

    if not re.match(r"^[0-9a-f]{64}$", payload_sha256 or ""):
        raise ArchiveError(f"payload_sha256 必须是 64 位十六进制：{payload_sha256!r}")
    material = "\n".join([version, code_version, payload_sha256]).encode("utf-8")
    return "rf-build-" + hashlib.sha256(material).hexdigest()[:16]


#: 清单里**不得**出现的本机路径形态（公开清单会被打包进站点，人人可读）。
_LOCAL_PATH_PROBE = re.compile(r"(?:^|[\s\"'=(\[])/(?:home|root|var/lib|etc|Users|opt|tmp)/")
_ABS_PATH_PROBE = re.compile(r"(?:^|[\s\"'=(\[])/(?!researcher-finance(?:/|$))[A-Za-z0-9._-]+/")


#: 公开清单里**禁止出现**的键（会泄露私有源码结构/逐文件指纹/git 事实）。
_FORBIDDEN_MANIFEST_KEYS = (
    "file_digests",
    "inventory",
    "includes",
    "excludes",
    "required_anchors",
    "commit",
    "dirty",
)


def assert_no_private_inventory(manifest: dict) -> None:
    """公开清单只允许聚合摘要：出现逐文件清单/git 事实即拒绝（F6）。"""

    def walk(node, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key) in _FORBIDDEN_MANIFEST_KEYS:
                    raise ArchiveError(
                        f"公开发布清单出现不允许的字段 {path}.{key}（逐文件清单/git 事实必须留在仓库外）"
                    )
                walk(value, f"{path}.{key}")
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    walk(manifest, "manifest")
    source = manifest.get("release_source")
    if isinstance(source, dict) and len(source) > 8:
        raise ArchiveError("公开发布清单的 release_source 字段过多（疑似把逐文件明细写进了公开清单）")


def assert_public_safe_manifest(manifest: dict) -> None:
    """发布清单会随站点公开：出现本机绝对路径即拒绝（fail closed）。

    这是"公开产物不得含私有路径"（AGENTS.md 规则 6）在发布身份文件上的落地检查；
    典型踩坑是 provenance 里直接写导出目录，例如 ``/home/<user>/.local/share/...``。
    """

    def walk(node, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}")
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")
        elif isinstance(node, str):
            if _LOCAL_PATH_PROBE.search(node):
                raise ArchiveError(f"发布清单 {path} 含本机绝对路径，拒绝写进公开发布物")
            if node.startswith("/") and not node.startswith("/researcher-finance"):
                raise ArchiveError(f"发布清单 {path} 以绝对路径开头，拒绝写进公开发布物")

    walk(manifest, "manifest")


def compact_gate_summary(reports: "list | tuple") -> dict:
    """把闸门结果压成**可公开**的小结（只保留结论与计数，不保留可能含路径的说明文本）。"""

    summary: dict = {}
    for report in reports:
        entry = getattr(report, "as_dict", None)
        data = entry() if callable(entry) else dict(report)
        summary[data["name"]] = {
            "ok": bool(data.get("ok")),
            "problems": len(data.get("problems") or []),
            "warnings": len(data.get("warnings") or []),
        }
    return summary


def build_manifest(
    *,
    inputs: ReleaseInputs,
    payload_digest: dict,
    package: dict,
    created_at: str,
    gates: dict,
    extra: dict | None = None,
) -> dict:
    """构造发布清单（确定性字段顺序由 ``canonical_json`` 保证）。"""

    if not _SHA256_RE.match(payload_digest.get("sha256", "")):
        raise ArchiveError("载荷摘要缺失或非法，拒绝生成清单")
    code_version = compute_code_version(commit=inputs.git_commit, dirty=inputs.git_dirty)
    build_id = compute_build_id(
        version=inputs.version, code_version=code_version, payload_sha256=payload_digest["sha256"]
    )
    manifest = {
        "manifest_version": 1,
        "release_version": inputs.version,
        "build_id": build_id,
        "code_version": code_version,
        "created_at": created_at,
        "target": inputs.target.as_dict(),
        "site": {
            "origin": inputs.site_origin,
            "base_path": inputs.base_path,
            "url": inputs.site_origin.rstrip("/") + inputs.base_path,
        },
        "dependencies": {"lockfile_sha256": inputs.lockfile_sha256},
        # 发布来源指纹：**只放聚合值**（sha256 / 文件数 / 是否完整）。
        #
        # 为什么不能放逐文件明细（F6）：清单会随站点公开，逐文件 path+sha256 等于把私有仓库的
        # 源码结构与逐文件指纹公布出去；而"外层 repo 的 commit"又不包含 finance/（untracked），
        # 拿它当代码身份属于**误导性**陈述。因此：
        #   * 公开清单：只有聚合摘要 + 明确说明这不是 git 提交身份；
        #   * 逐文件清单与 git 事实：写进**仓库外**发布库的 verification.json / sidecar。
        "release_source": {
            "identity": "content-digest",
            "digest_sha256": (inputs.source_digest or {}).get("sha256"),
            "files": (inputs.source_digest or {}).get("files"),
            "bytes": (inputs.source_digest or {}).get("bytes"),
            "complete": bool((inputs.source_digest or {}).get("complete")),
            "note": (
                "发布来源身份 = 参与构建的源码/配置的**聚合内容摘要**（不含逐文件清单，"
                "逐文件清单留在仓库外发布库）。**本字段不是 git 提交**：外层仓库的 HEAD "
                "不包含 finance/（untracked），因此不把它写成代码身份"
            ),
        },
        # 收录声明：首发试运行默认 noindex（不参与搜索收录）属于**正常选择**，
        # 与内容是否公开无关；这里如实登记，便于事后核对与显式变更。
        "indexing": {
            "choice": inputs.indexing,
            "meaning": (
                "noindex = 首发试运行不参与搜索引擎收录（默认）；index = 显式允许收录。"
                "两者都不代表内容公开与否，也不代表内容安全判定"
            ),
        },
        "data_binding": {
            "export_bundle_sha256": inputs.export_bundle_sha256,
            "note": "站点数据必须与该导出包一致（内容比对 + 摘要登记），禁止站点自带数据",
        },
        "payload": {
            "files": payload_digest["files"],
            "total_bytes": payload_digest["total_bytes"],
            "sha256": payload_digest["sha256"],
        },
        "package": {
            "name": package["name"],
            "bytes": package["bytes"],
            "sha256": package["sha256"],
        },
        "package_sha256_source": (
            "self" if re.match(r"^[0-9a-f]{64}$", str(package.get("sha256") or "")) else "external"
        ),
        "provenance": {
            "source_export": inputs.source_export_dir,
            "snapshot_id": inputs.snapshot_id,
            "data_cutoff": inputs.data_cutoff,
            "contract_version": inputs.contract_version,
            "schema_version": inputs.schema_version,
            "publication_policy_version": inputs.publication_policy_version,
        },
        "gates": gates,
        "rollback": {"previous_version": inputs.previous_version},
        "generated_by": inputs.generated_by,
    }
    if extra:
        manifest.update(extra)
    return manifest


def build_site_status(*, manifest: dict, generated_at: str) -> dict:
    """站点根 ``status.json`` 的内容（部署后线上核验读它）。

    **刻意只放公开、无路径的信息**：版本、build_id、载荷/包摘要、快照与数据截止、
    契约版本、站点 URL、收录声明、数据来源摘要。不放本地目录、不放日志、不放任何私有标识。
    """

    provenance = manifest.get("provenance") or {}
    site = manifest.get("site") or {}
    indexing = manifest.get("indexing") or {}
    binding = manifest.get("data_binding") or {}
    release_source = manifest.get("release_source") or {}
    return {
        "status_version": 1,
        "indexing": indexing.get("choice"),
        "export_bundle_sha256": binding.get("export_bundle_sha256"),
        "release_source_sha256": (release_source.get("digest") or {}).get("sha256"),
        "release_version": manifest["release_version"],
        "build_id": manifest["build_id"],
        "code_version": manifest["code_version"],
        "payload_sha256": (manifest.get("payload") or {}).get("sha256"),
        "packaged_sha256": (manifest.get("payload") or {}).get("packaged_sha256"),
        "package_sha256": (manifest.get("package") or {}).get("sha256"),
        "package_sha256_source": manifest.get("package_sha256_source", "external"),
        "snapshot_id": provenance.get("snapshot_id"),
        "data_cutoff": provenance.get("data_cutoff"),
        "contract_version": provenance.get("contract_version"),
        "schema_version": provenance.get("schema_version"),
        "publication_policy_version": provenance.get("publication_policy_version"),
        "site_url": site.get("url"),
        "generated_at": generated_at,
        "generated_by": manifest.get("generated_by"),
    }


def manifest_bytes(manifest: dict) -> bytes:
    return canonical_json(manifest)


def status_bytes(status: dict) -> bytes:
    return canonical_json(status)
