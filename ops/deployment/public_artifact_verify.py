#!/usr/bin/env python3
"""公开发布包校验 + 安全解包（**独立运行**；发布仓库的 runner 直接调用它）。

用法（发布工作流里，不需要 checkout 私有仓库）::

    python3 ops/deployment/public_artifact_verify.py \
        --archive ./incoming/researcher-finance-site-<version>.tar.gz \
        --out ./site \
        --expected-sha256 "$INPUT_SHA256" \
        --expected-version "$INPUT_VERSION" \
        --expected-build-id "$INPUT_BUILD_ID" \
        --report ./verify-report.json

退出码：``0`` 全部通过；非零 = **拒绝发布**（fail closed）。所有失败原因都会打印到 stderr，
并（可选）写进 ``--report`` 的 JSON。

它做四件事，缺一不可：

1. **字节校验**：``--expected-sha256`` 与实际包摘要一致（工作流另有 ``sha256sum -c`` 双保险）；
2. **归档安全校验**：拒绝绝对路径、内部穿越、符号链接/硬链接/特殊文件、重复成员、
   超限大小/数量（见 ``researcher_finance_deploy.safe_archive``）；
3. **受限解包**：只在校验通过后解包到**独占新建**目录（``--out`` 必须不存在）；
4. **载荷闸门**：站点必需文件、密钥形态内容、私有路径、私有预览/合成声明、
   ``PUBLISH_MANIFEST.json`` 与 ``status.json`` 的 ``build_id``/载荷摘要一致，
   以及与工作流输入（version/build_id）逐字一致。

**只读、离线、零依赖**：只用 Python 标准库，不联网、不写包外任何文件（除 ``--out`` 与 ``--report``）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from researcher_finance_deploy.gates import check_release_provenance, check_site_payload  # noqa: E402
from researcher_finance_deploy.manifest import (  # noqa: E402
    MANIFEST_FILENAME,
    STATUS_FILENAME,
    read_json_object,
)
from researcher_finance_deploy.safe_archive import (  # noqa: E402
    ArchiveError,
    ArchiveLimits,
    digest_payload_dir,
    extract_tar_gz,
    validate_tar_gz,
)

EXIT_OK = 0
EXIT_FAIL = 1


def _sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify(
    archive: Path,
    out_dir: Path,
    *,
    expected_sha256: str | None,
    expected_version: str | None,
    expected_build_id: str | None,
    limits: ArchiveLimits,
) -> dict:
    """执行全部校验；返回结构化报告（``ok=False`` 时调用方必须非零退出）。"""

    problems: list[str] = []
    warnings: list[str] = []
    report: dict = {"archive": str(archive), "out_dir": str(out_dir)}

    archive = Path(archive)
    if not archive.is_file():
        return {
            "ok": False,
            "problems": [f"发布包不存在：{archive}"],
            "warnings": [],
        }

    # —— 读链闭合（F4 勘误）——
    # 这里原先有**三次独立读**：
    #   读1 `_sha256_file(archive)` → actual_sha256（与 expected 比）
    #   读2 `validate_tar_gz(archive)` → validation.sha256
    #   读3 `extract_tar_gz(archive, ...)` → 复核 validation.sha256
    # 读2 与读3 之间是闭合的，但**读1 与读2 之间没有比较**：在"读1 → 读2"窗口里把归档换成
    # 另一个**结构合法**的包 B（例如成员同名同大小），就会带着"expected = A 的摘要"进入 B，
    # 而 B 内部自带自洽的 `status.json`/`PUBLISH_MANIFEST.json`（build_id 可与其内容一致），
    # 于是可能出现"校验通过但解包的并不是 expected 所指的字节"。
    # 现在：先读一次拿 actual_sha256，与 expected 比；再校验拿到 validation.sha256；
    # **逐字比较两者**，不等即在任何 out 目录/解包动作之前失败（fail closed）。
    actual_sha256 = _sha256_file(archive)
    report["package_sha256"] = actual_sha256
    report["package_bytes"] = archive.stat().st_size
    expected = expected_sha256.strip().lower() if expected_sha256 else None
    if expected and actual_sha256 != expected:
        problems.append(f"包摘要与工作流输入不一致：{actual_sha256} != {expected}")

    validation = validate_tar_gz(archive, limits=limits)
    report["archive_validation"] = validation.as_dict()
    if not validation.ok:
        problems.extend(f"归档校验失败：{item}" for item in validation.problems)
        return {"ok": False, "problems": problems, "warnings": warnings, **report}

    if validation.sha256 != actual_sha256:
        # 读1 与读2 看到的不是同一份字节 ⇒ 归档在校验过程中被替换/改动，拒绝继续（不创建 out）
        problems.append(
            "归档在校验过程中发生变化（读链不闭合）："
            f"读取摘要 {actual_sha256} != 校验摘要 {validation.sha256}"
        )
        return {"ok": False, "problems": problems, "warnings": warnings, **report}
    if expected and validation.sha256 != expected:
        problems.append(
            f"校验摘要与工作流输入不一致：{validation.sha256} != {expected}"
        )
        return {"ok": False, "problems": problems, "warnings": warnings, **report}
    if problems:
        # 例如 expected 为空但 actual 已异常：此时也必须先于任何写盘动作返回
        return {"ok": False, "problems": problems, "warnings": warnings, **report}

    target = Path(out_dir)
    if os.path.lexists(target):
        problems.append(f"解包目标已存在（含悬空符号链接，必须独占新建目录）：{target}")
        return {"ok": False, "problems": problems, "warnings": warnings, **report}

    try:
        # extract 内部会用**同一次 fd 读**再算一次摘要并与 validation.sha256 比较（读3 == 读2）
        extract_tar_gz(archive, target, validation=validation, limits=limits)
    except ArchiveError as exc:
        problems.append(str(exc))
        return {"ok": False, "problems": problems, "warnings": warnings, **report}

    digest = digest_payload_dir(target)
    report["payload"] = digest

    manifest_path = target / MANIFEST_FILENAME
    status_path = target / STATUS_FILENAME
    manifest: dict = {}
    status: dict = {}
    if not manifest_path.is_file():
        problems.append(f"载荷缺少 {MANIFEST_FILENAME}")
    else:
        manifest = read_json_object(manifest_path, where=f"载荷 {MANIFEST_FILENAME}")
        provenance_problems: list[str] = []
        check_release_provenance(manifest, provenance_problems)
        problems.extend(provenance_problems)
    if not status_path.is_file():
        problems.append(f"载荷缺少 {STATUS_FILENAME}（部署后无法核验线上产物）")
    else:
        status = read_json_object(status_path, where=f"载荷 {STATUS_FILENAME}")

    # 摘要语义（**必须分清**，"包内清单"无法自指包含它自己的包）：
    #   * ``payload.sha256``          = 站点自身内容摘要（不含清单/状态文件）；
    #   * ``payload.packaged_sha256`` = "站点内容 + 清单 + 状态文件"摘要 = 解包目录的摘要。
    # 解包目录必然包含这两个身份文件，因此只能与 ``packaged_sha256`` 比较；
    # 只有站点内容摘要时（正常情况：包内清单就是如此）**不能**拿来比，否则必然误报。
    payload_meta = (manifest.get("payload") or {}) if isinstance(manifest, dict) else {}
    site_digest = payload_meta.get("sha256")
    packaged_digest = payload_meta.get("packaged_sha256")
    if not site_digest or not re.match(r"^[0-9a-f]{64}$", str(site_digest)):
        problems.append(f"清单 payload.sha256（站点内容摘要）缺失或非法：{site_digest!r}")
    if manifest and status:
        if status.get("build_id") != manifest.get("build_id"):
            problems.append("status.json 与 PUBLISH_MANIFEST.json 的 build_id 不一致")
        if status.get("release_version") != manifest.get("release_version"):
            problems.append("status.json 与 PUBLISH_MANIFEST.json 的 release_version 不一致")
        if status.get("payload_sha256") != site_digest:
            problems.append(
                "status.json 的 payload_sha256 与清单 payload.sha256 不一致："
                f"{status.get('payload_sha256')!r} != {site_digest!r}"
            )
        if packaged_digest:
            if packaged_digest != digest["sha256"]:
                problems.append(
                    f"清单 packaged_sha256 与解包结果不一致：{packaged_digest} != {digest['sha256']}"
                )
            declared_files = payload_meta.get("packaged_files")
            if declared_files and declared_files != digest["files"]:
                problems.append(
                    f"清单 packaged_files 与解包结果不一致：{declared_files} != {digest['files']}"
                )
        else:
            warnings.append(
                "清单未记录 packaged_sha256（包内清单无法自指自身包摘要）："
                "本次只能校验站点内容摘要与身份字段；完整包级复验请用 "
                "`prepare_release.py verify-release` 或对照发布资产的 SHA256SUMS"
            )

    gate = check_site_payload(
        target,
        expected_build_id=expected_build_id,
        expected_release_version=expected_version,
        expected_payload_sha256=None,
        require_manifest=True,
    )
    report["site_gate"] = gate.as_dict()
    problems.extend(gate.problems)
    warnings.extend(gate.warnings)

    if expected_version and status and status.get("release_version") != expected_version:
        problems.append(
            f"载荷 release_version 与工作流输入不一致：{status.get('release_version')!r} != {expected_version!r}"
        )
    if expected_build_id and status and status.get("build_id") != expected_build_id:
        problems.append(
            f"载荷 build_id 与工作流输入不一致：{status.get('build_id')!r} != {expected_build_id!r}"
        )

    return {
        "ok": not problems,
        "problems": problems,
        "warnings": warnings,
        "release_version": (status or manifest).get("release_version"),
        "build_id": (status or manifest).get("build_id"),
        **report,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="公开发布包校验 + 安全解包（离线、零依赖）")
    parser.add_argument("--archive", required=True, help="待校验的 tar.gz 发布包")
    parser.add_argument("--out", required=True, help="解包目标目录（必须不存在）")
    parser.add_argument("--expected-sha256", default=None)
    parser.add_argument("--expected-version", default=None)
    parser.add_argument("--expected-build-id", default=None)
    parser.add_argument("--report", default=None, help="把结构化报告写到该文件")
    parser.add_argument("--max-members", type=int, default=ArchiveLimits().max_members)
    parser.add_argument(
        "--max-decompressed-bytes", type=int, default=ArchiveLimits().max_decompressed_bytes
    )
    args = parser.parse_args(argv)

    limits = ArchiveLimits(
        max_members=args.max_members, max_decompressed_bytes=args.max_decompressed_bytes
    )
    try:
        report = verify(
            Path(args.archive),
            Path(args.out),
            expected_sha256=args.expected_sha256,
            expected_version=args.expected_version,
            expected_build_id=args.expected_build_id,
            limits=limits,
        )
    except ArchiveError as exc:
        report = {"ok": False, "problems": [str(exc)], "warnings": []}

    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(f"[artifact-verify] 包：{args.archive}")
    if report.get("package_sha256"):
        print(f"[artifact-verify] 包摘要：{report['package_sha256']}")
    if report.get("build_id"):
        print(f"[artifact-verify] build_id：{report['build_id']}")
    print(f"[artifact-verify] 判定：{'PASS' if report.get('ok') else 'FAIL'}")
    for warning in report.get("warnings") or []:
        print(f"[artifact-verify][warn] {warning}")
    for problem in report.get("problems") or []:
        print(f"[artifact-verify][FAIL] {problem}", file=sys.stderr)
    return EXIT_OK if report.get("ok") else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
