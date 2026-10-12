"""ResearcherFinance 发布工具包（architect 维护；**零第三方依赖、零全局安装**）。

设计边界
--------

* **只依赖 Python 标准库**（3.11+），可以直接在公开发布仓库的 GitHub runner 上以
  ``python3 - <file>`` 方式运行，不需要 checkout 私有仓库、不需要安装包；
* **不读密钥**：只处理已构建好的**公开产物目录**，从不打开 ``.env``/凭据文件；
* **默认不联网、不写发布状态**：``prepare`` 默认 dry-run，``publish`` 是独立命令且必须显式
  ``--yes`` 才会执行网络动作；
* 产物**不得**包含私有路径、密钥形态内容、私有预览/合成数据；任一闸门失败即 fail closed。

模块：

``gates``
    公开产物（导出包）与渲染站点载荷的发布前闸门。
``safe_archive``
    确定性 tar.gz 打包 + 归档安全校验 + 受限解包（拒绝绝对路径/内部穿越/符号链接/
    硬链接/特殊文件/重复成员/超限压缩）。
``manifest``
    发布清单、站点状态文件与确定性 build_id。
``store``
    本地不可变发布库（版本目录 + current/previous + 回滚记录）。
``cli``
    ``prepare`` / ``verify-release`` / ``rollback`` / ``publish`` 命令行。
"""

from __future__ import annotations

__all__ = ["__version__"]

#: 发布工具包自身的版本（与产物契约版本无关，便于追溯工具行为）。
__version__ = "1.0.0"
