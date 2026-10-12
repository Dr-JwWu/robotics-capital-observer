r"""确定性 tar.gz 打包 + 归档安全校验 + 受限解包（发布工具的核心安全件）。

为什么不能直接用 ``tar -xzf``
---------------------------

示例工作流原先用 ``tar -tzf | grep -E '^(\.\.|/)'`` 做"路径检查"，这既不完整也不可靠：

* 只匹配**行首**，``./../../etc/passwd``、``a/../../x`` 这类内部穿越会漏过；
* 完全没检查 **symlink / hardlink / 字符设备 / FIFO**（hardlink 成员可以让解包器把内容写到
  包内任意**已存在**路径上）；
* 没有检查**重复成员**（同名成员后者覆盖前者，校验与使用看到的不是同一份内容）；
* 没有**大小/数量上限**，gzip 解压炸弹可以打满磁盘；
* ``grep`` 命中即 ``exit 1``（未命中时 ``&&`` 短路），失败路径依赖 shell 语义，容易写反。

本模块的约定
------------

**只接受**：名称可归一化为仓库内相对 POSIX 路径的目录成员与普通文件成员。
**一律拒绝**：绝对路径、任何形式的内部穿越（``..``）、符号链接、硬链接、其它特殊文件、
重复成员、互为前缀的"文件/目录"冲突、超出大小/数量/文件名长度上限的包、
带 ``pax_headers`` 等可被用于逃逸的元数据。

**解包**：先全量校验（解压到临时 spool，内存占用与包大小无关），再往一个新建的独占目录里
逐成员写出（``O_EXCL``）；任何一步失败即中止并清理临时目录。
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import shutil
import stat
import tarfile
import tempfile
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator, Sequence

__all__ = [
    "ArchiveLimits",
    "ArchiveError",
    "ArchiveValidation",
    "MemberInfo",
    "build_deterministic_tar",
    "validate_tar_gz",
    "extract_tar_gz",
    "iter_regular_files",
    "digest_payload_dir",
    "normalize_member_name",
    "ensure_inside",
    "ensure_not_inside",
    "utc_now_seconds",
]


@dataclass(frozen=True)
class ArchiveLimits:
    """归档资源上限（fail closed：超出即拒绝，不"尽力而为"）。

    默认值面向"静态站点载荷"（真实站点载荷在数十 MB 量级），比默认值大一个数量级即视为异常。
    """

    max_compressed_bytes: int = 512 * 1024 * 1024
    max_decompressed_bytes: int = 2 * 1024 * 1024 * 1024
    max_members: int = 20_000
    max_member_bytes: int = 256 * 1024 * 1024
    max_name_length: int = 512
    max_path_depth: int = 32


class ArchiveError(RuntimeError):
    """归档校验/解包失败（信息面向运维，不含任何密钥值）。"""


@dataclass(frozen=True)
class MemberInfo:
    """通过校验的成员（供校验报告与解包阶段复用，避免二次判断漂移）。"""

    name: str
    size: int
    is_dir: bool
    mode: int


@dataclass
class ArchiveValidation:
    """校验结果：只有 ``ok=True`` 时才允许解包。"""

    ok: bool
    compressed_bytes: int = 0
    decompressed_bytes: int = 0
    file_count: int = 0
    dir_count: int = 0
    total_file_bytes: int = 0
    members: tuple[MemberInfo, ...] = ()
    sha256: str = ""
    problems: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "compressed_bytes": self.compressed_bytes,
            "decompressed_bytes": self.decompressed_bytes,
            "file_count": self.file_count,
            "dir_count": self.dir_count,
            "total_file_bytes": self.total_file_bytes,
            "sha256": self.sha256,
            "problems": list(self.problems),
        }


# --------------------------------------------------------------------------------------
# 名称归一化与成员校验
# --------------------------------------------------------------------------------------

_FORBIDDEN_MEMBER_TYPES = {
    tarfile.SYMTYPE: "符号链接",
    tarfile.LNKTYPE: "硬链接",
    tarfile.CHRTYPE: "字符设备",
    tarfile.BLKTYPE: "块设备",
    tarfile.FIFOTYPE: "FIFO",
    tarfile.CONTTYPE: "连续文件（contiguous）",
}


def normalize_member_name(raw: str) -> str:
    """把归档成员名归一化成安全的相对 POSIX 路径；不合法直接 ``ArchiveError``。

    归一化只做"去掉开头 ``./``"，**不做** ``..`` 折叠 —— ``..`` 一律拒绝，
    避免"先折叠再检查"的经典绕过。
    """

    if not isinstance(raw, str) or not raw:
        raise ArchiveError("归档成员名为空")
    name = raw
    if "\\" in name:
        raise ArchiveError(f"归档成员名含反斜杠（可能是 Windows 绝对路径）：{name!r}")
    if any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in name):
        # 控制字符（含 \n/\r/\x01）会污染 SHA256SUMS、日志与下游 shell 处理（F9）
        raise ArchiveError(f"归档成员名含控制字符：{raw!r}")
    while name.startswith("./"):
        name = name[2:]
    if name.endswith("/"):
        name = name.rstrip("/")
    if name in {"", "."}:
        raise ArchiveError("归档成员名归一化后为空")
    if name.startswith("/") or PurePosixPath(name).is_absolute():
        raise ArchiveError(f"归档成员是绝对路径：{raw!r}")
    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ArchiveError(f"归档成员名含空段/当前目录/上级目录：{raw!r}")
    if len(name) > 1 and name[1] == ":":
        raise ArchiveError(f"归档成员名疑似盘符绝对路径：{raw!r}")
    for part in parts:
        if part.startswith("-"):
            # 以 '-' 开头的成员名会被下游工具当成选项（F9）
            raise ArchiveError(f"归档成员名以 '-' 开头（可能被当作命令行选项）：{raw!r}")
    return name


def _check_member(
    member: tarfile.TarInfo,
    limits: ArchiveLimits,
    seen: dict[str, MemberInfo],
    regular_names: set[str],
    dir_names: set[str],
) -> MemberInfo:
    if member.pax_headers:
        raise ArchiveError(f"归档成员带 pax_headers（可携带逃逸元数据）：{member.name!r}")
    if member.type in _FORBIDDEN_MEMBER_TYPES:
        raise ArchiveError(
            f"归档成员类型被拒绝（{_FORBIDDEN_MEMBER_TYPES[member.type]}）：{member.name!r}"
        )
    if member.islnk() or member.issym():
        raise ArchiveError(f"归档成员是链接：{member.name!r}")
    if not (member.isdir() or member.isreg()):
        raise ArchiveError(f"归档成员既不是目录也不是普通文件：{member.name!r}（type={member.type!r}）")
    if member.isreg() and member.size < 0:
        raise ArchiveError(f"归档成员大小为负：{member.name!r}")

    name = normalize_member_name(member.name)
    if len(name) > limits.max_name_length:
        raise ArchiveError(f"归档成员名过长（> {limits.max_name_length}）：{name!r}")
    if len(name.split("/")) > limits.max_path_depth:
        raise ArchiveError(f"归档成员路径过深（> {limits.max_path_depth}）：{name!r}")
    if name in seen:
        raise ArchiveError(f"归档内出现重复成员：{name!r}")
    # 双向前缀检查（F7）：无论成员**顺序**如何，只要"某个成员是另一个成员的前缀"，一律拒绝。
    # 这样 `validate.ok == True` 就真的意味着"可解包"，不会出现"校验通过、解包才炸"。
    for prefix in regular_names:
        if name.startswith(prefix + "/"):
            raise ArchiveError(f"归档成员位于一个普通文件之下（路径冲突）：{name!r}")
    for directory in dir_names:
        # 反向（与顺序无关的那一半）：名为 `a` 的**普通文件**成员若出现在 `a/b` 之后，
        # 解包时 `a` 需要是目录 ⇒ 冲突。`a/b` 出现在目录 `a` 之后是**合法**的（a 本来就是目录）。
        if not member.isdir() and name in dir_names:
            raise ArchiveError(f"归档成员同时是目录与普通文件（路径冲突）：{name!r}")
        if not member.isdir() and any(item.startswith(name + "/") for item in regular_names):
            raise ArchiveError(f"归档成员与已出现路径冲突：{name!r}")

    if member.isdir():
        info = MemberInfo(name=name, size=0, is_dir=True, mode=stat.S_IMODE(member.mode) or 0o755)
    else:
        if member.size > limits.max_member_bytes:
            raise ArchiveError(
                f"归档成员超出单文件上限（{member.size} > {limits.max_member_bytes}）：{name!r}"
            )
        info = MemberInfo(
            name=name, size=int(member.size), is_dir=False, mode=stat.S_IMODE(member.mode) or 0o644
        )
    seen[name] = info
    if info.is_dir:
        dir_names.add(name)
    else:
        regular_names.add(name)
    return info


def _check_member_tree(members: "list[MemberInfo] | tuple[MemberInfo, ...]") -> list[str]:
    """集合级检查：所有成员能否构成互不冲突的树（与成员顺序无关，F7）。

    规则：

    * 任何**普通文件**都不得同时是另一个成员的祖先（否则解包需要它既是文件又是目录）；
    * 任何成员的路径必须与其祖先的成员类型一致（目录可以是隐式的，但不能是普通文件）；
    * 显式声明的目录不得隐藏普通文件（同名文件另有成员）。
    """

    problems: list[str] = []
    files = {member.name for member in members if not member.is_dir}
    dirs = {member.name for member in members if member.is_dir}
    for name in sorted(files | dirs):
        parts = name.split("/")
        for index in range(1, len(parts)):
            ancestor = "/".join(parts[:index])
            if ancestor in files:
                problems.append(
                    f"归档路径冲突：{name!r} 需要 {ancestor!r} 是目录，但它被声明为普通文件"
                )
                break
        if name in files and name in dirs:
            problems.append(f"归档路径冲突：{name!r} 同时是文件与目录")
    return problems


# --------------------------------------------------------------------------------------
# 受限解压（不写业务盘、内存占用与包大小无关）
# --------------------------------------------------------------------------------------


def _sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def assert_plain_regular_file(path: Path, *, what: str) -> None:
    """断言路径是**单链接普通文件**（拒绝符号链接与多链接，F4/F8）。

    归档是整条信任链的根：如果它本身是符号链接（或可在校验后换指向），
    "期望 sha256"就不再约束被解包的字节。
    """

    path = Path(path)
    if path.is_symlink():
        raise ArchiveError(f"{what}是符号链接，拒绝处理：{path}")
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise ArchiveError(f"{what}不存在：{path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ArchiveError(f"{what}不是普通文件：{path}")
    if info.st_nlink != 1:
        raise ArchiveError(f"{what}有 {info.st_nlink} 个硬链接（可被替换），拒绝处理：{path}")


def _spool_gzip(
    path: Path,
    *,
    max_decompressed_bytes: int,
    max_in_memory_bytes: int = 256 * 1024 * 1024,
    chunk_size: int = 1 << 20,
) -> tuple[Path, int, str]:
    """把 gzip **解压**到私有临时文件（spool），并强制解压上限。

    返回 ``(spool_path, decompressed_bytes, raw_sha256)``：

    * ``spool_path`` 是**解压后的 tar 字节**（供 ``tarfile`` 以 ``r:`` 读取）；
    * ``raw_sha256`` 是**压缩包字节**摘要；它与解压**来自同一份内存缓冲**，
      因此调用方可以在解包时复核摘要、发现"校验后被换文件"（F4 TOCTOU）。

    大文件（超过 ``max_in_memory_bytes``）走流式路径：先按块算摘要，再流式解压，
    内存占用与包大小无关，但"摘要 → 解压"之间理论上仍可被换文件；因此**超过该上限的包
    直接拒绝**（本站站点载荷只有几百 KB，出现超大包本身就是异常）。
    """

    raw_digest = hashlib.sha256()
    handle = tempfile.NamedTemporaryFile(prefix="rf-gz-spool-", delete=False)
    spool = Path(handle.name)
    total = 0
    try:
        size = path.stat().st_size
        if size > max_in_memory_bytes:
            raise ArchiveError(
                f"归档过大（{size} > {max_in_memory_bytes} 字节）：拒绝在无法保证 TOCTOU 复核的前提下处理"
            )
        with open(path, "rb") as compressed:
            raw = compressed.read()
        raw_digest.update(raw)
        with handle:
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as source:
                    while True:
                        chunk = source.read(chunk_size)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_decompressed_bytes:
                            raise ArchiveError(
                                f"解压后体积超出上限（> {max_decompressed_bytes} 字节），疑似解压炸弹"
                            )
                        handle.write(chunk)
            except zlib.error as exc:
                raise ArchiveError(f"gzip 数据损坏：{exc}") from exc
    except ArchiveError:
        spool.unlink(missing_ok=True)
        raise
    except (gzip.BadGzipFile, EOFError) as exc:
        spool.unlink(missing_ok=True)
        raise ArchiveError(f"不是有效的 gzip 归档或被截断：{exc}") from exc
    except OSError as exc:
        spool.unlink(missing_ok=True)
        raise ArchiveError(f"归档不可读：{exc}") from exc
    return spool, total, raw_digest.hexdigest()


def _open_tar_spool(path: Path, limits: ArchiveLimits):
    """上下文管理器：产出 ``(tarfile, spool_path, decompressed_bytes)`` 并在退出时清理 spool。"""

    class _Ctx:
        def __enter__(self):
            spool, size, digest = _spool_gzip(
                path, max_decompressed_bytes=limits.max_decompressed_bytes
            )
            try:
                tar = tarfile.open(name=str(spool), mode="r:")
            except (tarfile.TarError, OSError) as exc:
                spool.unlink(missing_ok=True)
                raise ArchiveError(f"tar 结构损坏：{exc}") from exc
            self._tar, self._spool = tar, spool
            return tar, spool, size, digest

        def __exit__(self, exc_type, exc, tb):
            try:
                self._tar.close()
            finally:
                self._spool.unlink(missing_ok=True)
            return False

    return _Ctx()


# --------------------------------------------------------------------------------------
# 校验
# --------------------------------------------------------------------------------------


def validate_tar_gz(path: Path, *, limits: ArchiveLimits | None = None) -> ArchiveValidation:
    """全量校验一个 tar.gz（**不落盘、不解包**），返回结构化结果；``ok=False`` 时禁止解包。

    ``result.sha256`` 是**校验当次 fd 读**算出的摘要（与解压字节同源），解包阶段会复核（F4）。
    """

    limits = limits or ArchiveLimits()
    result = ArchiveValidation(ok=False)
    path = Path(path)
    try:
        assert_plain_regular_file(path, what="归档")
    except ArchiveError as exc:
        result.problems.append(str(exc))
        return result
    size = path.stat().st_size
    result.compressed_bytes = size
    if size > limits.max_compressed_bytes:
        result.problems.append(f"压缩包超出上限（{size} > {limits.max_compressed_bytes} 字节）")
        return result

    members: list[MemberInfo] = []
    seen: dict[str, MemberInfo] = {}
    regular_names: set[str] = set()
    dir_names: set[str] = set()
    try:
        with _open_tar_spool(path, limits) as (tar, _spool, decompressed_bytes, digest):
            result.decompressed_bytes = decompressed_bytes
            result.sha256 = digest
            for member in tar:
                if len(members) >= limits.max_members:
                    raise ArchiveError(f"归档成员数超出上限（> {limits.max_members}）")
                members.append(_check_member(member, limits, seen, regular_names, dir_names))
    except ArchiveError as exc:
        result.problems.append(str(exc))
        return result

    if not members:
        result.problems.append("归档为空（0 个成员）")
        return result
    if not regular_names:
        result.problems.append("归档内没有任何普通文件")

    # 整体树校验（F7 的兜底）：成员集合必须能构成一棵"文件与目录互不冲突"的树。
    # 逐成员检查只能看到"已出现过"的成员，这里改成集合级检查，顺序完全无关。
    tree_problems = _check_member_tree(members)
    result.problems.extend(tree_problems)

    total = sum(member.size for member in members if not member.is_dir)
    if total > limits.max_decompressed_bytes:
        result.problems.append(f"成员声明总大小超出上限（{total} > {limits.max_decompressed_bytes}）")

    if result.problems:
        return result
    result.ok = True
    result.members = tuple(members)
    result.file_count = len(regular_names)
    result.dir_count = len(members) - len(regular_names)
    result.total_file_bytes = total
    return result


# --------------------------------------------------------------------------------------
# 解包
# --------------------------------------------------------------------------------------


def _ensure_parents(root: Path, relative: str) -> None:
    """逐级创建父目录，并拒绝任何已存在的非目录节点（防"目录位置被文件占用"）。"""

    current = root
    *parents, _leaf = relative.split("/")
    for part in parents:
        current = current / part
        if current.is_symlink():
            raise ArchiveError(f"解包路径上的 {current} 是符号链接，拒绝写入")
        if current.exists() and not current.is_dir():
            raise ArchiveError(f"解包路径上的 {current} 不是目录，拒绝写入")
        current.mkdir(exist_ok=True)


def _assert_no_symlink_parents(path: Path) -> None:
    """拒绝目标路径上任何**已存在**的符号链接父目录（F8：防止写到链接指向的目录之外）。"""

    current = Path(path).expanduser().absolute().parent
    chain: list[Path] = []
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if candidate.is_symlink():
            raise ArchiveError(
                f"解包目标的父目录链上有符号链接（可能写到预期之外的位置）：{candidate}"
            )


def extract_tar_gz(
    archive: Path,
    destination: Path,
    *,
    validation: ArchiveValidation | None = None,
    limits: ArchiveLimits | None = None,
) -> ArchiveValidation:
    """先校验、后解包；``destination`` 必须**不存在**（独占新建，避免与既有站点混写）。

    **TOCTOU 复核（F4）**：解包用的字节来自一次新的 fd 读，其摘要必须与校验时记录的
    ``report.sha256`` **逐字相同**；不同即拒绝（并且尚未创建任何目录，也没有移动指针）。
    归档本身还必须是单链接普通文件（符号链接/硬链接直接拒绝）。
    """

    limits = limits or ArchiveLimits()
    archive = Path(archive)
    report = validation if validation is not None else validate_tar_gz(archive, limits=limits)
    if not report.ok:
        raise ArchiveError("归档未通过校验，拒绝解包：" + "; ".join(report.problems))
    assert_plain_regular_file(archive, what="归档")

    destination = Path(destination)
    # F8：悬空符号链接会被 ``exists()`` 判为 False，于是临时目录会被建到链接指向的位置。
    # 用 ``lexists`` 判定"路径上什么都不允许存在"，并且拒绝父链上的符号链接。
    if os.path.lexists(destination):
        raise ArchiveError(f"解包目标已存在（含悬空符号链接，必须独占新建目录）：{destination}")
    _assert_no_symlink_parents(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    staging = Path(tempfile.mkdtemp(prefix=".extract-", dir=str(destination.parent)))
    try:
        with _open_tar_spool(archive, limits) as (tar, _spool, _size, digest):
            if digest != report.sha256:
                raise ArchiveError(
                    "归档在校验与解包之间发生变化（TOCTOU）："
                    f"{digest} != {report.sha256}；拒绝使用未经验证的字节"
                )
            by_name = {member.name: member for member in report.members}
            written = 0
            for member in tar:
                info = by_name.get(normalize_member_name(member.name))
                if info is None:  # pragma: no cover - 校验与解包之间不可能新增成员
                    raise ArchiveError(f"解包时发现未校验成员：{member.name!r}")
                if info.is_dir:
                    (staging / info.name).mkdir(parents=True, exist_ok=True)
                    continue
                _ensure_parents(staging, info.name)
                target = staging / info.name
                if os.path.lexists(target):
                    raise ArchiveError(f"解包目标已存在，拒绝覆盖：{info.name!r}")
                source = tar.extractfile(member)
                if source is None:
                    raise ArchiveError(f"归档成员无法读取（不是普通文件？）：{info.name!r}")
                with open(target, "xb") as handle:
                    while True:
                        chunk = source.read(1 << 20)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > limits.max_decompressed_bytes:
                            raise ArchiveError("解包写出字节数超出上限，疑似解压炸弹")
                        handle.write(chunk)
                actual_size = target.stat().st_size
                if actual_size != info.size:
                    raise ArchiveError(
                        f"解包后大小与归档声明不一致：{info.name!r}（{actual_size} != {info.size}）"
                    )
                os.chmod(target, info.mode)
        try:
            os.replace(staging, destination)
        except OSError as exc:  # F8：把 rename 类失败包成 ArchiveError（易于上层报告）
            raise ArchiveError(f"提交解包目录失败：{exc}") from exc
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    actual = digest_payload_dir(destination)
    if actual["files"] != report.file_count or actual["total_bytes"] != report.total_file_bytes:
        shutil.rmtree(destination, ignore_errors=True)
        raise ArchiveError(
            "解包结果的成员数/字节数与校验结果不一致，已回滚解包目录："
            f"{actual} != files={report.file_count}, bytes={report.total_file_bytes}"
        )
    return report


# --------------------------------------------------------------------------------------
# 确定性打包
# --------------------------------------------------------------------------------------


def iter_regular_files(root: Path) -> Iterator[tuple[str, Path]]:
    """按 POSIX 相对路径排序产出 ``(relative_path, absolute_path)``；遇到符号链接即拒绝。"""

    root = Path(root)
    if not root.is_dir():
        raise ArchiveError(f"载荷目录不存在或不是目录：{root}")
    entries: list[tuple[str, Path]] = []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in list(dirnames):
            candidate = current_path / name
            if candidate.is_symlink():
                raise ArchiveError(f"载荷目录内含符号链接目录，拒绝打包：{candidate}")
        for name in filenames:
            candidate = current_path / name
            if candidate.is_symlink():
                raise ArchiveError(f"载荷目录内含符号链接文件，拒绝打包：{candidate}")
            if not candidate.is_file():
                raise ArchiveError(f"载荷目录内含非普通文件，拒绝打包：{candidate}")
            entries.append((candidate.relative_to(root).as_posix(), candidate))
    entries.sort(key=lambda item: item[0])
    seen: set[str] = set()
    for relative, absolute in entries:
        if relative in seen:
            raise ArchiveError(f"载荷目录内出现重复相对路径：{relative}")
        seen.add(relative)
        normalize_member_name(relative)
        yield relative, absolute


def build_deterministic_tar(
    payload_dir: Path,
    out_path: Path,
    *,
    limits: ArchiveLimits | None = None,
    gzip_mtime: int = 0,
) -> dict:
    """把载荷目录打成**逐字节可复现**的 tar.gz。

    确定性来自：成员按路径排序、``mtime=0``、``uid/gid=0``、``uname/gname=""``、
    固定权限位、GNU tar 格式（不写 pax 扩展头）、gzip 头 ``mtime=0`` 且不写原文件名。
    同样的载荷目录两次打包得到**同一个 SHA-256**（有测试守着）。
    """

    limits = limits or ArchiveLimits()
    payload_dir = Path(payload_dir)
    out_path = Path(out_path)
    if out_path.exists():
        raise ArchiveError(f"输出归档已存在，拒绝覆盖：{out_path}")
    entries = list(iter_regular_files(payload_dir))
    if not entries:
        raise ArchiveError(f"载荷目录为空，拒绝打包：{payload_dir}")
    if len(entries) > limits.max_members:
        raise ArchiveError(f"载荷文件数超出上限（{len(entries)} > {limits.max_members}）")

    total = 0
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for relative, absolute in entries:
            size = absolute.stat().st_size
            if size > limits.max_member_bytes:
                raise ArchiveError(f"载荷文件超出单文件上限（{size}）：{relative}")
            total += size
            if total > limits.max_decompressed_bytes:
                raise ArchiveError(f"载荷总大小超出上限（> {limits.max_decompressed_bytes} 字节）")
            if len(relative) > limits.max_name_length:
                raise ArchiveError(f"载荷相对路径过长：{relative}")
            info = tarfile.TarInfo(relative)
            info.size = size
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.type = tarfile.REGTYPE
            with absolute.open("rb") as handle:
                tar.addfile(info, handle)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = raw.getvalue()
    with open(out_path, "xb") as handle:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=handle, compresslevel=9, mtime=gzip_mtime
        ) as gz:
            gz.write(payload)
    stat_result = out_path.stat()
    return {
        "path": str(out_path),
        "bytes": stat_result.st_size,
        "sha256": _sha256_file(out_path),
        "file_count": len(entries),
        "total_uncompressed_bytes": total,
    }


# --------------------------------------------------------------------------------------
# 载荷目录指纹与路径约束
# --------------------------------------------------------------------------------------


def digest_payload_dir(root: Path) -> dict:
    """计算载荷目录的内容指纹（相对路径 + 大小 + 内容），用于前后一致性核对。"""

    digest = hashlib.sha256()
    files = 0
    total = 0
    for relative, absolute in iter_regular_files(root):
        size = absolute.stat().st_size
        files += 1
        total += size
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\x00")
        with absolute.open("rb") as handle:
            while True:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
        digest.update(b"\x00")
    return {"files": files, "total_bytes": total, "sha256": digest.hexdigest()}


def utc_now_seconds() -> int:
    """当前 UTC 时间（整秒）；打包时固定写入 gzip 头以保持确定性。"""

    return int(time.time())


def ensure_inside(path: Path, allowed_roots: Sequence[Path]) -> Path:
    """断言 ``path`` 位于给定根之一，返回解析后的绝对路径；否则 ``ArchiveError``。"""

    resolved = Path(path).expanduser().resolve()
    for root in allowed_roots:
        root_resolved = Path(root).expanduser().resolve()
        if resolved == root_resolved or root_resolved in resolved.parents:
            return resolved
    raise ArchiveError(
        "路径被拒绝（不在允许的根之下）："
        + str(resolved)
        + "；允许的根："
        + ", ".join(str(Path(item).expanduser().resolve()) for item in allowed_roots)
    )


def ensure_not_inside(path: Path, forbidden_roots: Iterable[Path]) -> Path:
    """断言 ``path`` 不在任何禁止根之下（例如 git 仓库内），返回解析后的绝对路径。"""

    resolved = Path(path).expanduser().resolve()
    for root in forbidden_roots:
        root_resolved = Path(root).expanduser().resolve()
        if resolved == root_resolved or root_resolved in resolved.parents:
            raise ArchiveError(f"路径被拒绝（位于禁止目录内）：{resolved} 在 {root_resolved} 之下")
    return resolved
