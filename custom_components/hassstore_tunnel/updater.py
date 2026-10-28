"""hs-frpc 客户端二进制自动更新：跟随站点发布清单，下载 → 校验 → 原子替换 → 重启。

三条不可动摇的纪律
------------------
1. **只运行校验过的二进制**：SHA256 必须与站点发布清单逐位相符（与配置时预填
   ``binary_sha256`` 同一份数据），且先落临时文件、冒烟测试通过才替换。
2. **"替换"不需要先停子进程**：Linux 的 ``rename(2)`` 不打开目标文件写入，
   因此不触发 ETXTBSY（实测运行中的 ELF 被 ``os.replace`` 覆盖后
   ``/proc/<pid>/exe`` 显示 ``(deleted)``，进程照常运行）。所以
   "下载 → 校验 → 替换"全程**不中断隧道**；只有随后的重启才会瞬断。
   冒烟测试也因此能在旧进程还在跑的时候执行，坏包提前挡掉。
3. **pin 必须走在替换之前**：``async_prepare_binary`` 启动时要求磁盘二进制
   与 ``options.binary_sha256`` 相符，不符就重新下载，而镜像给的是**新版** →
   校验必败 → ``ConfigEntryNotReady`` → SETUP_RETRY 死循环。所以"先替换后回写
   pin"的顺序在取消/崩溃落在两步之间时（executor 任务已完成、await 还没返回的
   窗口，``Task.cancel`` 照样会注入）会留下"磁盘新、pin 旧"这个死锁态。
   反过来"pin 新、磁盘旧"是**自愈**的：下次启动校验失败 → 重下载 → 与 pin
   相符 → 正常跑。因此本类先落 pin 再下载替换；**确定性**失败（校验失败、
   OSError——此时替换必然没发生，磁盘可断定仍是旧值）把 pin 退回原值；
   超时则**不退**——executor 作业取消不掉、``os.replace`` 可能在超时返回后
   才由后台线程落盘，退 pin 反而会制造出死锁方向（见 ``_async_update_locked``
   的 TimeoutError 分支）。

⚠️ 同步 pin 必经 ``hass.config_entries.async_update_entry``，而它**会触发**
``entry.update_listeners``（HA 源码 ``config_entries.py`` 的
``_async_save_and_notify``，已核实）。本集成的 listener 是"重载集成"，
更新过程中重载会把刚拉起的隧道重新拆掉，且站点一抖就让 setup 变成
``ConfigEntryNotReady``。因此 ``__init__._async_options_updated`` 对
"binary_sha256 变化且新值==updater 写入值"豁免重载——仓库原注释说
"async_update_entry 不触发 reload"是错的；而"用户手动改 sha"不在豁免之列
（本类把写入值记到 ``last_persisted_sha`` 供 listener 区分两者）。
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import HassStoreClient
from .const import (
    CONF_AUTO_UPDATE_CLIENT,
    CONF_BINARY_MIRROR,
    CONF_BINARY_SHA256,
    DEFAULT_AUTO_UPDATE_CLIENT,
    DEFAULT_BINARY_MIRROR,
    DOMAIN,
    HEALTHZ_TIMEOUT_SECONDS,
    UPDATE_CHECK_SECONDS,
    UPDATE_RESTART_GRACE_SECONDS,
    UPDATE_STARTUP_DELAY_SECONDS,
    UPDATE_TIMEOUT_SECONDS,
)
from .local_process import (
    BinaryIntegrityError,
    TunnelProcess,
    async_prepare_binary,
    detect_arch,
    sha256_file_sync,
)

_LOGGER = logging.getLogger(__name__)

# 回滚备份与二进制同目录，避免跨文件系统 rename 失败。
BACKUP_SUFFIX = ".prev"

# 新版本起不来且已回滚时建的 Repairs issue ID。
ISSUE_CLIENT_UPDATE_FAILED = "client_update_failed"
# 更糟的一档：新版本起不来且**没有备份可回滚**——隧道停在一个起不来的版本上，
# 需要用户手工处置（填回 sha 或改 app 模式），文案与"已回滚、隧道应已恢复"分开。
ISSUE_CLIENT_UPDATE_NO_ROLLBACK = "client_update_no_rollback"

# 版本号形如 v0.71.0-hs.4（frp 上游版本 + HassStore 定制号，见 Makefile HS_VERSION）。
_HS_VERSION_RE = re.compile(r"^v?(?P<frp>\d+(?:\.\d+)*)(?:-hs\.(?P<hs>\d+))?$", re.IGNORECASE)
# 清单里 sha256 必须是 64 位十六进制，否则宁可不更新也不用一个来路不明的值。
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def parse_hs_version(value: str | None) -> tuple[int, ...] | None:
    """把 ``v0.71.0-hs.4`` 解析成可比较的元组 ``(0, 71, 0, 4)``。

    必须**分段**比较而不是字符串比较：字典序下 ``"hs.10" < "hs.4"``，
    第 10 个定制版会被判成比第 4 个旧——正是"永远不更新"的那种 bug。
    解析不了返回 None；调用方按"未知"处理，绝不能当成最新版。
    """
    if not value:
        return None
    match = _HS_VERSION_RE.match(str(value).strip())
    if match is None:
        return None
    parts = [int(p) for p in match.group("frp").split(".")]
    # 没有 -hs.N 时补 0，保证元组等长、可直接比较。
    parts.append(int(match.group("hs")) if match.group("hs") is not None else 0)
    return tuple(parts)


def version_is_newer(candidate: str | None, current: str | None) -> bool:
    """``candidate`` 是否严格新于 ``current``。

    候选不合法 → False；当前版本未知 → True（只能认为要更新）。
    """
    new = parse_hs_version(candidate)
    if new is None:
        return False
    old = parse_hs_version(current)
    if old is None:
        return True
    return new > old


def manifest_binary(manifest: dict[str, Any] | None, arch: str) -> dict[str, str] | None:
    """从发布清单取本架构的 ``{version, sha256}``；缺项/格式不对返回 None。

    刻意**不**返回清单里的 ``url``：下载地址由集成选项里的镜像决定
    （用户可能配了国内加速镜像），用清单的 URL 会绕过用户的选择。
    """
    if not isinstance(manifest, dict):
        return None
    binaries = manifest.get("binaries")
    if not isinstance(binaries, dict):
        return None
    info = binaries.get(arch)
    if not isinstance(info, dict):
        return None
    version = str(manifest.get("version") or "").strip()
    sha256 = str(info.get("sha256") or "").strip().lower()
    if not version or not _SHA256_RE.match(sha256):
        return None
    return {"version": version, "sha256": sha256}


async def async_fetch_healthz(hass: HomeAssistant, addr: str | None) -> dict[str, Any] | None:
    """读 hs-frpc 的 ``/healthz``；**任何 HTTP 状态码都解析 body**。

    503 也带完整 JSON（``ok`` / ``connected`` / ``version`` …），把它当"不可达"
    会丢掉唯一的版本真相来源——那正是"故障时 HA 显示一个假的客户端版本"的成因。
    只有连接错误 / 超时 / 非 JSON 才算不可达（返回 None）。
    """
    if not addr:
        return None
    session = async_get_clientsession(hass)
    try:
        async with asyncio.timeout(HEALTHZ_TIMEOUT_SECONDS):
            response = await session.get(
                f"http://{addr}/healthz",
                # 本机回环必须绕过 HA 共享 session 可能带上的代理设置。
                proxy=None,
                headers={"Accept": "application/json"},
            )
            data = await response.json(content_type=None)
    except (TimeoutError, asyncio.TimeoutError):
        _LOGGER.debug("healthz 超时（%s）", addr)
        return None
    except (aiohttp.ClientError, ValueError) as err:
        _LOGGER.debug("healthz 不可用（%s）：%s", addr, err)
        return None
    return data if isinstance(data, dict) else None


def _sha256_or_empty(path: Path) -> str:
    """文件哈希；不存在/读不动返回空串（调用方按"未知"处理）。"""
    try:
        if not path.is_file():
            return ""
        return sha256_file_sync(path)
    except OSError as err:
        _LOGGER.debug("计算 %s 哈希失败：%s", path, err)
        return ""


def _is_file(path: Path) -> bool:
    """executor 里调用：``path`` 是否是普通文件（stat 不上事件循环）。"""
    return path.is_file()


def _copy_file(src: Path, dst: Path) -> None:
    """executor 里调用：更新前备份旧二进制。"""
    shutil.copy2(src, dst)


def _restore_backup(backup: Path, binary: Path) -> bool:
    """executor 里调用：有备份则原子换回并返回 True；没有备份返回 False。"""
    if not backup.is_file():
        return False
    os.replace(backup, binary)
    return True


def _remove_quietly(path: Path) -> None:
    """executor 里调用：删备份，不存在也算成功。"""
    path.unlink(missing_ok=True)


class ClientBinaryUpdater:
    """周期比对站点发布清单，发现新版本就下载、校验、原子替换并重启子进程。

    语义：**开启即跟随站点发布版**。``binary_sha256`` 由本类维护（每次装完
    回写），要固定某个构建就关掉选项、自己填 SHA——选项描述里也是这么说的。
    """

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        entry: Any,
        client: HassStoreClient,
        process: TunnelProcess,
        mirror: str,
        arch: str,
        health_addr: str | None,
    ) -> None:
        self._hass = hass
        self._entry = entry
        self._client = client
        self._process = process
        self._mirror = mirror
        self._arch = arch
        self._health_addr = health_addr
        # 串行化：一次只跑一个更新。启动首查与周期任务都可能同时触发，
        # 没有锁就会并发下载/重启。
        self._lock = asyncio.Lock()
        # 上次检查的 loop 单调时钟；None = 从未检查过。
        self._last_check: float | None = None
        # 本类最近一次通过 async_update_entry 写回 options 的 sha256。
        # __init__._async_options_updated 据此区分"自动更新回写"与"用户手动改 sha"：
        # 前者豁免集成重载，后者必须重载（用户钉版本是显式意图，不能静默吞掉）。
        self.last_persisted_sha: str | None = None

    # -- 开关 ---------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        """选项开关（默认关）。"""
        return bool(
            self._entry.options.get(CONF_AUTO_UPDATE_CLIENT, DEFAULT_AUTO_UPDATE_CLIENT)
        )

    # -- 对外入口 -----------------------------------------------------------
    async def async_maybe_update(self, *, force: bool = False) -> str | None:
        """返回新安装的版本号；无需更新/被跳过/失败都返回 None。

        ``force=True`` 跳过开关与节流判断（供测试用）。任何失败只记日志——
        **绝不影响正在运行的隧道**。
        """
        if self._process is None:
            return None
        if not self.enabled and not force:
            return None
        if self._hass.is_stopping:
            return None
        async with self._lock:
            now = self._hass.loop.time()
            if (
                not force
                and self._last_check is not None
                and now - self._last_check < UPDATE_CHECK_SECONDS
            ):
                return None
            self._last_check = now
            return await self._async_update_locked()

    async def async_run_forever(self) -> None:
        """后台循环：启动后先等 ``UPDATE_STARTUP_DELAY_SECONDS`` 首查，之后按周期检查。

        用 sleep 循环而不是 ``async_track_time_interval``：节奏是**单调时长**，
        且从上一轮检查**开始**时刻算起（见 ``async_maybe_update`` 的节流），
        一次拖长的检查不会让下一轮立刻跟上。
        """
        delay = UPDATE_STARTUP_DELAY_SECONDS
        while True:
            await asyncio.sleep(delay)
            delay = UPDATE_CHECK_SECONDS
            try:
                await self.async_maybe_update()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - 后台任务不能因一次失败就消失
                _LOGGER.exception("hs-frpc 自动更新检查失败")

    # -- 主流程 -------------------------------------------------------------
    async def _async_update_locked(self) -> str | None:
        binary = self._process.binary_path
        backup = binary.with_name(binary.name + BACKUP_SUFFIX)

        if self._process.paused:
            # 服务端 action=stop 已叫我们别跑：此刻 healthz 必然读不到、
            # wait_stable 必然超时。若照走流程，每个周期都会白白下载一份
            # 二进制、然后以"启动失败"为名做一次假的回滚+假的 Repairs issue
            # ——更新在暂停期间永远落不了地，还吓用户。恢复后再更新不迟。
            _LOGGER.debug("隧道处于服务端暂停态（action=stop），跳过本次自动更新")
            return None

        # 1) 当前版本：唯一可信来源是 hs-frpc 自己的 /healthz。
        current = await self._async_current_version()
        if current is None and self._process.is_running:
            # 进程在跑却读不到版本：健康口可能还没就绪。宁可晚一个周期，
            # 也不要在"不知道现在装的是什么"的情况下换二进制。
            _LOGGER.debug("读不到 hs-frpc 版本且进程正在运行，本次跳过自动更新检查")
            return None

        # 2) 发布清单（公开端点，不需要令牌）。
        manifest = await self._client.async_get_release_manifest()
        offer = manifest_binary(manifest, self._arch)
        if offer is None:
            # 拉取失败（站点/网络故障）返回 {}，与"没有本架构条目"分开记——
            # 排障时"读不到清单"和"清单没发布"是两个方向。
            _LOGGER.debug(
                "跳过自动更新：%s",
                "发布清单不可达或为空" if not manifest else f"清单没有本架构（{self._arch}）的条目",
            )
            return None
        if not version_is_newer(offer["version"], current):
            return None

        # 上一轮可能遗留 .prev（中途断电/cancel）：先清掉，否则"无备份"场景会把
        # 一份陈年旧包当成备份，回滚出第三个版本（磁盘与 pin 又不一致）。
        await self._hass.async_add_executor_job(_remove_quietly, backup)
        if await self._hass.async_add_executor_job(_is_file, binary):
            try:
                await self._hass.async_add_executor_job(_copy_file, binary, backup)
            except OSError as err:
                # 备份失败（磁盘满/权限）就放弃本次更新：没有备份的更新等于把
                # "起不来就回滚"这道保险拆掉，不值得为追一个版本冒这个险。
                _LOGGER.warning("备份当前 hs-frpc 失败，放弃本次自动更新：%s", err)
                return None

        _LOGGER.info(
            "发现 hs-frpc 新版本 %s（当前 %s），开始自动更新",
            offer["version"],
            current or "未知",
        )

        # 3) 先落 pin 再下载（docstring 纪律第 3 条）。此刻磁盘还是旧二进制，
        #    pin 已是新值——这个中间态是自愈的；反方向（磁盘新/pin 旧）才会
        #    让下次启动进 SETUP_RETRY 死循环。
        #    回写失败 = 这次更新根本不开始：磁盘与 pin 都还是旧的，一致，无需回滚。
        old_sha = await self._hass.async_add_executor_job(_sha256_or_empty, binary)
        if not self._persist_sha(offer["sha256"]):
            _LOGGER.warning("回写 binary_sha256 失败，放弃本次自动更新（继续使用当前版本）")
            await self._hass.async_add_executor_job(_remove_quietly, backup)
            return None

        try:
            async with asyncio.timeout(UPDATE_TIMEOUT_SECONDS):
                # 下载 + 校验 + 冒烟测试 + 原子替换；替换不中断隧道（docstring 第 2 条）。
                # force_download 用 old_sha 决定：磁盘已是目标 sha（上一轮替换后被
                # 取消留下的中间态）→ 允许复用，校验 + 冒烟测试照跑、省 20MB 下载；
                # 否则强制重下——不能传 False，那会先验证旧二进制再失败，把每次
                # 正常的旧→新过渡都打一条"校验失败，将重新下载"的 WARNING。
                await async_prepare_binary(
                    self._hass,
                    directory=binary.parent,
                    expected_sha256=offer["sha256"],
                    mirror=self._mirror,
                    force_download=old_sha != offer["sha256"],
                )
        except BinaryIntegrityError as err:
            # 校验/冒烟失败：镜像给了坏包或清单与镜像不一致。继续用当前版本。
            _LOGGER.warning("自动更新下载或校验失败（继续使用当前版本）：%s", err)
            await self._hass.async_add_executor_job(_remove_quietly, backup)
            self._persist_sha(old_sha)  # pin 退回原值，磁盘/pin 重新一致
            return None
        except (TimeoutError, asyncio.TimeoutError):
            # ⚠️ 超时后磁盘状态是**不确定**的：asyncio.timeout 只取消协程的
            #    await，executor 里已提交的 _verify_and_replace（sha256 + 最长
            #    ~60s 的冒烟测试 + os.replace）取消不掉、会在后台跑完——
            #    os.replace 可能在本分支返回之后才落盘。此时若把 pin 退回
            #    old_sha，恰好制造出 docstring 第 3 条的"磁盘新/pin 旧"死锁。
            #    所以 pin 一律保持新值：磁盘仍是旧 → 下次启动校验失败→重下载
            #    （自愈方向）；磁盘已被后台换成新 → pin 正好相符。
            landed = await self._hass.async_add_executor_job(_sha256_or_empty, binary)
            if landed == offer["sha256"]:
                # 替换已在后台落盘（超时打在 await 返回之前）：按"已安装"继续走
                # 暂停检查与重启验证，而不是误报成失败。
                _LOGGER.info("自动更新超时，但校验与替换已在后台完成，继续重启验证")
            else:
                _LOGGER.warning(
                    "自动更新超时（%ds；pin 保留新值，磁盘仍是旧版时下次启动会重下载自愈）",
                    UPDATE_TIMEOUT_SECONDS,
                )
                await self._hass.async_add_executor_job(_remove_quietly, backup)
                return None
        except OSError as err:
            # async_prepare_binary 只保证抛 BinaryIntegrityError；落盘/rename 的
            # 裸 OSError 也会冒出来。放在 TimeoutError 之后——3.11+ 起 TimeoutError
            # 是 OSError 的子类，顺序反了会把超时归到这类里。
            _LOGGER.warning("自动更新写入失败（磁盘/权限，继续使用当前版本）：%s", err)
            await self._hass.async_add_executor_job(_remove_quietly, backup)
            self._persist_sha(old_sha)
            return None

        # 3.5) 暂停指令可能在"检查 → 替换"这几秒里到达（服务端批量停用）。
        #      暂停态下 wait_stable 必然超时，"留着新包等恢复"等于把一个**未验证**
        #      的二进制交给 resume 后的 supervisor——坏了也没机会回滚。所以当场
        #      回退（进程还没重启，零中断），恢复后下个周期再走完整的下载→验证。
        if self._process.paused:
            rolled_back = await self._async_rollback_binary(binary, backup)
            _LOGGER.info(
                "hs-frpc 已下载 %s，但隧道刚被服务端暂停（无法验证启动）：%s",
                offer["version"],
                "已回退到原版本，恢复后下个周期再更新"
                if rolled_back
                else "无备份可回退，保留新版本待恢复",
            )
            return None

        # 4) 重启加载新二进制——全程唯一会造成隧道瞬断的一步
        await self._process.async_restart()
        if await self._process.async_wait_stable(UPDATE_RESTART_GRACE_SECONDS):
            await self._hass.async_add_executor_job(_remove_quietly, backup)
            _LOGGER.info("hs-frpc 已自动更新到 %s 并重启", offer["version"])
            # 上一周期可能因失败建过 issue：成功后清理，否则过期告警永远挂着。
            try:
                ir.async_delete_issue(self._hass, DOMAIN, ISSUE_CLIENT_UPDATE_FAILED)
                ir.async_delete_issue(self._hass, DOMAIN, ISSUE_CLIENT_UPDATE_NO_ROLLBACK)
            except Exception as err:  # noqa: BLE001 - 清 issue 失败绝不影响更新结果
                _LOGGER.debug("清理旧的更新失败 issue 失败（忽略）：%s", err)
            self._notify_updated(offer["version"], current)
            return offer["version"]

        # 新二进制起不来 → 回滚到备份，恢复原 pin，再重启一次。
        _LOGGER.error("新版 hs-frpc（%s）启动失败，回滚到上一版本", offer["version"])
        rolled_back = await self._async_rollback_binary(binary, backup)
        if rolled_back:
            await self._process.async_restart()
        else:
            # 备份没做成（磁盘满/权限）时不能默默放着坏二进制不管：issue 照建，
            # 但文案必须是"没法回滚、需要人工处置"，而不是"已回滚、隧道应已恢复"。
            _LOGGER.error("没有可用备份（%s），无法回滚", backup)
        self._create_issue(offer["version"], current, rolled_back=rolled_back)
        return None

    # -- 辅助 ---------------------------------------------------------------
    async def _async_rollback_binary(self, binary: Path, backup: Path) -> bool:
        """把备份换回磁盘并尽量把 pin 改回旧值（**不重启**，由调用方按场景决定）。

        返回 False = 没有可用备份。成功时若读不出 sha 或回写失败只记日志：
        调用方要么已建 issue，要么下次启动的校验路径会兜底，不必再抛。

        "不重启"是有意的：两处调用（替换后遇暂停、新二进制起不来）里前者
        进程还在跑旧 inode，重启只会白白中断隧道；后者回滚后由调用方决定。
        """
        restored_ok = await self._hass.async_add_executor_job(
            _restore_backup, backup, binary
        )
        if not restored_ok:
            return False
        restored = await self._hass.async_add_executor_job(_sha256_or_empty, binary)
        # 尽力恢复 pin；读不出 sha 说明刚回滚的文件都读不动，pin 暂不动，
        # 让下次启动的校验/重下载路径去兜底。
        if not restored:
            _LOGGER.error("回滚后的二进制读不出 sha256，options pin 暂不改动")
        elif not self._persist_sha(restored):
            # 二进制已换回旧版但 pin 还指着新版：又是磁盘/pin 不一致的
            # SETUP_RETRY 坑，记 ERROR 让排障能接上（issue 已如实描述故障）。
            _LOGGER.error(
                "回写回滚后的 binary_sha256 失败：磁盘为旧版而 pin 为新版，"
                "下次启动可能校验失败，请手工核对 options.binary_sha256"
            )
        return True

    async def _async_current_version(self) -> str | None:
        health = await async_fetch_healthz(self._hass, self._health_addr)
        if not health:
            return None
        version = health.get("version")
        return str(version).strip() if version else None

    def _persist_sha(self, sha256: str) -> bool:
        """把校验值写回 ``entry.options``；返回是否落盘成功（见模块 docstring 第 3 条）。

        返回值语义：True = options 里现在就是这个值（已一致或写入成功）；
        False = 写不进去，**调用方必须自己保证磁盘与 pin 一致**（通常是回滚二进制），
        否则下次启动会因校验失败进 SETUP_RETRY 死循环。
        """
        if not sha256:
            return False
        options = dict(self._entry.options)
        if options.get(CONF_BINARY_SHA256) == sha256:
            # 已经一致也登记：这是 updater 维护的目标值，listener 靠它区分
            # "updater 回写"与"用户手动改"。
            self.last_persisted_sha = sha256
            return True
        options[CONF_BINARY_SHA256] = sha256
        try:
            self._hass.config_entries.async_update_entry(self._entry, options=options)
        except Exception as err:  # noqa: BLE001 - 由调用方决定是否回滚，这里只上报
            _LOGGER.warning("回写 binary_sha256 失败：%s", err)
            return False
        self.last_persisted_sha = sha256
        return True

    def _notify_updated(self, new_version: str, old_version: str | None) -> None:
        """更新成功后发一条持久通知（固定 id，重复更新覆盖同一条，不刷屏）。"""
        try:
            from homeassistant.components import persistent_notification

            persistent_notification.async_create(
                self._hass,
                (
                    f"隧道客户端已从 {old_version or '未知版本'} 自动更新到 "
                    f"{new_version}，并已用新二进制重启（期间有数秒中断；"
                    "连接状态请见集成面板的 tunnel_online 实体）。\n\n"
                    "如不希望自动更新，可在集成选项里关闭「自动更新 hs-frpc 客户端」。"
                ),
                title="HassStore 隧道客户端已自动更新",
                notification_id=f"{DOMAIN}_client_updated",
            )
        except Exception as err:  # noqa: BLE001 - 通知失败绝不影响更新结果
            _LOGGER.debug("发送自动更新通知失败（忽略）：%s", err)

    def _create_issue(
        self, new_version: str, old_version: str | None, *, rolled_back: bool
    ) -> None:
        """更新失败建 Repairs issue：已回滚与"没东西可回滚"用不同文案。"""
        issue_id = (
            ISSUE_CLIENT_UPDATE_FAILED if rolled_back else ISSUE_CLIENT_UPDATE_NO_ROLLBACK
        )
        try:
            ir.async_create_issue(
                self._hass,
                DOMAIN,
                issue_id,
                is_fixable=False,
                severity=ir.IssueSeverity.ERROR,
                translation_key=issue_id,
                translation_placeholders={
                    "version": new_version,
                    "previous": old_version or "未知版本",
                    "arch": self._arch,
                },
            )
        except Exception as err:  # noqa: BLE001 - 建 issue 失败只记日志
            _LOGGER.debug("创建自动更新失败 issue 失败（忽略）：%s", err)


def resolve_mirror(entry: Any) -> str:
    """生效的下载镜像。读法必须与 ``__init__._async_start_local_side`` **逐字一致**——
    两边读到不同镜像时，更新器会从一个地方下载、而下次启动又从另一个地方校验。"""
    return str(entry.options.get(CONF_BINARY_MIRROR, DEFAULT_BINARY_MIRROR))


def resolve_arch() -> str | None:
    """本机架构；不支持时返回 None（调用方据此跳过自动更新）。"""
    try:
        return detect_arch()
    except BinaryIntegrityError as err:
        _LOGGER.info("架构不受支持，跳过 hs-frpc 自动更新：%s", err)
        return None
