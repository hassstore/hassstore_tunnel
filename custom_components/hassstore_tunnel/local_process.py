"""集成内置模式的二进制管理 + 子进程托管（仅 Container / Core 或无 Supervisor 的场景）。

官方先例（``docs/design/02a-ha-client-delivery.md`` §B.3.4）：
  * ``pycloudflared`` —— "下载 cloudflared 二进制 → ``chmod`` → 拉起"（HA 官方 ``cloud``
    集成的依赖链里就在这么干）；
  * ``ha-ffmpeg`` —— ``asyncio.create_subprocess_exec`` + ``close()/kill()`` 生命周期。

硬约束（02 §9.3 / §17.3、02a §B.3.3）：
  1. **事件循环内禁止阻塞 IO**：下载、SHA256、mkdir、chmod、可执行探测全部走
     ``hass.async_add_executor_job``。
  2. **SHA256 白名单缺省拒绝运行**（``TUNNEL_HSFRPC_SHA256_*`` 为空即拒绝）——
     第三方 app 仓库在 Supervisor 侧**没有任何签名校验**（``signed`` 恒为 False），
     二进制只能在下载链路上自证完整。
  3. ``async_unload_entry`` **必须**收敛子进程，否则重载会留下孤儿进程继续占用隧道。
  4. 崩溃自愈用 ``await proc.wait()`` + 指数退避，**不要轮询**。
  5. 必须做一次可执行性探测（防 ``noexec`` 挂载点；HAOS 数据分区实测无 noexec，
     但某些 NAS/自定义 Docker 的 ``/config`` 会挂 ``noexec`` —— 02a §B.3.1）。
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import platform
import re
import stat
import subprocess
from collections import deque
from pathlib import Path
from typing import Any, Final

import aiohttp
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    BINARY_NAME,
    BINARY_URL_TEMPLATE,
    CLIENT_TYPE_INTEGRATION,
    DEFAULT_HEALTH_ADDR,
    ENV_API_BASE,
    ENV_CLIENT_TYPE,
    ENV_CONFIG_CACHE,
    ENV_DEVICE_TOKEN,
    ENV_HA_VERSION,
    ENV_HEALTH_ADDR,
    ENV_LOCAL_TARGET,
    ENV_LOG_LEVEL,
    ENV_PROTOCOL,
    RESTART_BACKOFF_INITIAL,
    RESTART_BACKOFF_MAX,
    STABLE_RUN_SECONDS,
    STOP_TIMEOUT_SECONDS,
    ha_version,
)

_LOGGER = logging.getLogger(__name__)

# 我们只发布 amd64 / aarch64（HA 已弃用 32 位，02 §17.3）。
_ARCH_MAP: Final[dict[str, str]] = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
}

_STDERR_TAIL_LINES: Final = 40

# hs-frpc 静态链接二进制实测 ~20MB；上限放宽到 128MB 只是防"镜像配置错误
# 导致无限增长/把磁盘写满"的保险丝，正常构建离它很远。
_MAX_BINARY_BYTES: Final = 128 * 1024 * 1024


class BinaryIntegrityError(Exception):
    """下载/校验/可执行性检查失败——**拒绝运行**，并给用户可操作的提示。"""


def detect_arch() -> str:
    """Return our release arch name (``amd64`` / ``aarch64``)."""
    machine = platform.machine().lower()
    if (arch := _ARCH_MAP.get(machine)) is None:
        raise BinaryIntegrityError(
            f"不支持的架构 {platform.system()}/{platform.machine()}；"
            "本项目只发布 amd64 与 aarch64（HA 已弃用 32 位，2025-05 公告）"
        )
    return arch


def sha256_file_sync(path: Path) -> str:
    """Blocking SHA256 of a file — **call via the executor only**."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_and_prepare_sync(binary: Path, expected_sha256: str) -> None:
    """Blocking: hash check → chmod +x → exec smoke test (catches ``noexec``)."""
    actual = sha256_file_sync(binary)
    if actual.lower() != expected_sha256.strip().lower():
        # 哈希不符 = 要么是供应链攻击，要么是我们自己发版给错了值。两种都必须停。
        raise BinaryIntegrityError(
            f"hs-frpc SHA256 校验失败：期望 {expected_sha256.strip().lower()[:16]}…，"
            f"实际 {actual[:16]}…。已删除该文件，拒绝运行。"
        )
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    if not os.access(binary, os.X_OK):
        raise BinaryIntegrityError(f"{binary} 不可执行（chmod 后仍无 x 位）")
    # 真跑一次：能捕获 noexec、缺动态库、架构不匹配三类问题。
    # 用 subprocess.run 而不是 os.system：不走 shell（无注入面）、
    # 返回码语义明确、能设超时（os.system 返回的是 wait 状态，被信号杀死时会误判）。
    for args in ([str(binary), "--version"], [str(binary), "--help"]):
        try:
            result = subprocess.run(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            _LOGGER.debug("hs-frpc 可执行性探测 %s 失败：%s", args, err)
            continue
        if result.returncode == 0:
            return
    raise BinaryIntegrityError(
        f"{binary} 无法执行。常见原因：/config 挂载了 noexec、"
        "架构不匹配（下载了错误架构的包）、或文件被截断。请检查挂载参数或改用 app 模式。"
    )


async def async_prepare_binary(
    hass: HomeAssistant,
    *,
    directory: Path,
    expected_sha256: str,
    mirror: str,
    force_download: bool = False,
) -> Path:
    """Make sure a verified, executable ``hs-frpc`` exists; return its path.

    ``expected_sha256`` 为空 → **直接拒绝**（02 §17.3 / §13：
    "缺省则拒绝下载，禁止无校验运行"）。
    """
    if not expected_sha256 or not expected_sha256.strip():
        raise BinaryIntegrityError(
            "binary_sha256 未配置：出于安全考虑拒绝下载/运行 hs-frpc。"
            "请到站点「用户中心 → 内网穿透 → 安装向导」查看官方 SHA256，"
            "或浏览器打开 <你的站点>/api/v1/tunnel/release/manifest 自行对照。"
        )

    binary = directory / BINARY_NAME
    arch = detect_arch()

    def _ensure_dir() -> None:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    await hass.async_add_executor_job(_ensure_dir)

    if binary.exists() and not force_download:
        try:
            await hass.async_add_executor_job(_verify_and_prepare_sync, binary, expected_sha256)
        except BinaryIntegrityError:
            _LOGGER.warning("已存在的 hs-frpc 校验失败，将重新下载：%s", binary)
        else:
            _LOGGER.debug("复用已校验的 hs-frpc：%s", binary)
            return binary

    url = BINARY_URL_TEMPLATE.format(mirror=mirror.rstrip("/"), arch=arch)
    _LOGGER.info("下载 hs-frpc（%s，arch=%s）→ %s", url, arch, binary)

    # 用 HA 的共享 session：走 HA 的代理/证书配置，且复用连接池。
    # （自己 new ClientSession 会绕过这两样，并在卸载时泄漏——api.py 的同款要求。）
    session = async_get_clientsession(hass)
    tmp = binary.with_suffix(".tmp")
    total = 0
    try:
        async with asyncio.timeout(300):
            async with session.get(url, allow_redirects=True) as response:
                if response.status != 200:
                    raise BinaryIntegrityError(f"下载失败：HTTP {response.status}（{url}）")
                # 镜像/CDN 常见坑：404/限流/拦截时返回的是 HTML 错误页，
                # 若照单全收就会变成"SHA256 不符"被误判成供应链攻击。
                # 用 Content-Type 先拦截这类响应，错误信息分层
                # （"镜像异常" vs "校验失败"是两种完全不同的处置方向）。
                content_type = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                if content_type in ("text/html", "text/plain", "application/json"):
                    raise BinaryIntegrityError(
                        f"镜像返回了 {content_type}（HTTP 200 但不是二进制），"
                        f"可能是镜像/CDN 错误页或鉴权挑战页：{url}"
                    )
                if (cl := response.headers.get("Content-Length")) and cl.isdigit():
                    if int(cl) > _MAX_BINARY_BYTES:
                        raise BinaryIntegrityError(
                            f"镜像报告的文件大小 {int(cl)} 字节超过上限 {_MAX_BINARY_BYTES}（{url}）"
                        )
                # 流式落盘 + 分块交给 executor 写：
                # * 不把整个二进制驻留内存（hs-frpc ≈20MB，低端机上
                #   `response.read()` 会双倍驻留——bytes + 解码缓冲）；
                # * 写盘走 executor：事件循环里不直接做阻塞 write；
                # * 每块检查 hass.is_stopping：HA 关闭时及时中断下载，
                #   不再把"最后一块"写完才收手（下载中点 X 关 HA 的场景）。
                tmp_handle = await hass.async_add_executor_job(
                    lambda: tmp.open("wb")
                )
                try:
                    async for chunk in response.content.iter_chunked(256 * 1024):
                        if hass.is_stopping:
                            raise BinaryIntegrityError(
                                "下载被中断：Home Assistant 正在停止"
                            )
                        total += len(chunk)
                        if total > _MAX_BINARY_BYTES:
                            raise BinaryIntegrityError(
                                f"下载内容超过上限 {_MAX_BINARY_BYTES} 字节（{url}）"
                            )
                        await hass.async_add_executor_job(tmp_handle.write, chunk)
                finally:
                    await hass.async_add_executor_job(tmp_handle.close)
    except BinaryIntegrityError:
        await hass.async_add_executor_job(lambda: tmp.unlink(missing_ok=True))
        raise
    except (TimeoutError, asyncio.TimeoutError) as err:
        await hass.async_add_executor_job(lambda: tmp.unlink(missing_ok=True))
        raise BinaryIntegrityError(f"下载超时（{url}）") from err
    except aiohttp.ClientError as err:
        await hass.async_add_executor_job(lambda: tmp.unlink(missing_ok=True))
        raise BinaryIntegrityError(f"下载失败（{url}）：{err}") from err

    def _verify_and_replace() -> None:
        # 校验已落盘的临时文件，通过后原子 rename——避免"半截文件"被当成可用二进制。
        tmp.chmod(0o700)
        try:
            _verify_and_prepare_sync(tmp, expected_sha256)
        except BinaryIntegrityError:
            tmp.unlink(missing_ok=True)
            raise
        os.replace(tmp, binary)

    await hass.async_add_executor_job(_verify_and_replace)
    _LOGGER.info("hs-frpc 下载并校验通过（%d 字节）", total)
    return binary


class TunnelProcess:
    """Own the ``hs-frpc`` child process: start, watch, restart with backoff, stop."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        binary: Path,
        server_url: str,
        device_token: str,
        local_target: str,
        protocol: str,
        log_level: str,
        config_cache: Path,
        health_addr: str = DEFAULT_HEALTH_ADDR,
        on_state_change: Any = None,
    ) -> None:
        self.hass = hass
        self._binary = binary
        self._server_url = server_url.rstrip("/")
        self._device_token = device_token
        self._local_target = local_target
        self._protocol = protocol
        self._log_level = log_level
        self._config_cache = config_cache
        self._health_addr = health_addr
        self._on_state_change = on_state_change

        self._proc: asyncio.subprocess.Process | None = None
        self._supervisor_task: asyncio.Task[None] | None = None
        # 服务端下发 action=stop（到期/超额/被停用）时暂停，避免无谓重连刷日志。
        self._resume_event = asyncio.Event()
        self._resume_event.set()
        self._paused = False
        self._log_task: asyncio.Task[None] | None = None
        self._stopping = False
        # —— action=stop/resume 的收敛设计（曾经的竞态坑）——
        # 服务端动作指令的"期望态"：外部（coordinator 的 action_cb）只写
        # ``_desired_paused`` 并唤醒收敛任务，真实 pause/resume 由
        # ``_async_apply_desired_state`` 串行执行。若每次动作各自起一个
        # pause/resume 协程（旧实现：每条动作 create_background_task），
        # pause 的 SIGTERM 等待窗口里 resume 先跑完 → 最终状态与最新指令
        # **相反**（续费后隧道不起来 / 停用后还在重连）。
        self._desired_paused = False
        self._apply_task: asyncio.Task[None] | None = None
        self._stderr_tail: deque[str] = deque(maxlen=_STDERR_TAIL_LINES)
        self._last_error: str | None = None
        self._restarts = 0

    # -- 状态 ---------------------------------------------------------------
    @property
    def is_running(self) -> bool:
        """Whether the child process is alive."""
        return self._proc is not None and self._proc.returncode is None

    @property
    def binary_path(self) -> Path:
        """本进程托管的 ``hs-frpc`` 路径。"""
        return self._binary

    @property
    def health_addr(self) -> str:
        """子进程 ``/healthz`` 的监听地址（回环）。"""
        return self._health_addr

    @property
    def pid(self) -> int | None:
        """Child PID, if running."""
        return self._proc.pid if self._proc else None

    @property
    def restart_count(self) -> int:
        """How many times we restarted the child since setup."""
        return self._restarts

    @property
    def paused(self) -> bool:
        """True while the server told us to stop (expired / over quota / disabled)."""
        return self._paused

    @callback
    def state_snapshot(self) -> dict[str, Any]:
        """Synchronous snapshot used by the coordinator (no IO)."""
        return {
            "running": self.is_running,
            # "online" 是 healthz 不可用时的近似值：进程活着且未被暂停。
            # 精确在线状态仍以 healthz（ok&&connected）为准，这里只作兜底。
            "online": self.is_running and not self._paused,
            "pid": self.pid,
            "restarts": self._restarts,
            # ⚠️ **不报版本号**。曾经放的是 Python 常量 HS_CLIENT_VERSION（集成
            # "打算交付"的版本），于是磁盘上是旧二进制时 HA 照样显示新版本——
            # 2026-10-28 的票据过期事故就是这么被藏住的。版本只认 /healthz。
            "paused": self._paused,
            "last_error": self._last_error,
            "stderr_tail": list(self._stderr_tail)[-5:],
        }

    # -- 环境变量（**唯一**配置来源，与 run.sh 保持逐字一致）----------------
    def _environment(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                ENV_API_BASE: self._server_url,
                ENV_DEVICE_TOKEN: self._device_token,
                ENV_HEALTH_ADDR: self.health_addr,
                ENV_LOCAL_TARGET: self._local_target,
                ENV_PROTOCOL: self._protocol,
                ENV_LOG_LEVEL: self._log_level,
                ENV_CONFIG_CACHE: str(self._config_cache),
                ENV_CLIENT_TYPE: CLIENT_TYPE_INTEGRATION,
                # 上报 HA 版本：后台排查"某个 HA 版本上集体出问题"时靠它。
                # app 形态由 run.sh 传 Supervisor 的 HA_VERSION，这里传 Core 的版本。
                # ⚠️ 不能用 `hass.config.version`：`Config` 从来就没有这个属性
                # （已用真实 HA 2025.1.0 / 2026.10.1 核实：hasattr(Config,"version") 为 False，
                # 也没有 __getattr__），getattr(..., "") 恒得空串 →
                # HS_HA_VERSION 一直是空，后台按 HA 版本聚合时这类用户全归到"未知"。
                # const.py 早已提供 ha_version()，但这里漏改了（const.ha_version 的注释
                # 就写着"Config.version 已移除"）。
                ENV_HA_VERSION: ha_version(),
            }
        )
        return env

    # -- 生命周期 -----------------------------------------------------------
    async def async_start(self) -> None:
        """Start the child + its supervisor task."""
        if self.is_running:
            return
        self._stopping = False
        # 用 HA 的 background task 助手：HA 停止时会随事件循环收敛，不会变成僵尸任务。
        self._supervisor_task = self.hass.async_create_background_task(
            self._async_supervise(), name=f"{self._binary.name}-supervisor"
        )

    @callback
    def set_desired_paused(self, paused: bool) -> None:
        """Record the server-intended paused state; converge asynchronously.

        同步入口（coordinator 在拉取循环里直接调用）：只翻期望位、
        保证**至多一个**收敛任务在跑。收敛任务循环检查到
        ``_paused == _desired_paused`` 才结束，任务运行期间又被更新的
        期望态不会丢（同一任务继续收敛，而不是再起一个并发）。
        """
        self._desired_paused = paused
        if self._paused == self._desired_paused:
            return
        if self._apply_task is not None and not self._apply_task.done():
            # 已在收敛中：任务退出条件是 _paused == _desired_paused，
            # 而期望位刚被更新 → 它会继续跑到新目标，无需再起任务。
            return
        self._apply_task = self.hass.async_create_background_task(
            self._async_apply_desired_state(),
            name=f"{self._binary.name}-apply-desired",
        )

    async def _async_apply_desired_state(self) -> None:
        """Serially converge ``_paused`` toward ``_desired_paused``.

        while 循环是"串行 + 去重"的核心：一次 pause 期间目标又从
        stop→none 反复时，只按**最新**期望值收尾，而不是顺序回放每个动作。
        """
        while self._paused != self._desired_paused and not self._stopping:
            if self._desired_paused:
                await self.async_pause()
            else:
                await self.async_resume()

    async def async_pause(self) -> None:
        """Stop the child and hold off restarts (``action=stop``).

        服务端在 ``GET /tunnel/client/config`` 里下发 ``action:"stop"`` 时，
        权益已到期/超额或设备被停用（02 §7.6 "秒级停用"、§9.4 流程图）。
        此时继续重连只会被 frps 反复拒绝，所以由**客户端主动停下**。
        """
        if self._paused:
            return
        self._paused = True
        self._resume_event.clear()
        _LOGGER.warning("服务端要求停止隧道（action=stop，通常为套餐到期/流量耗尽/设备被停用）")
        await self._async_terminate_child()

    async def async_resume(self) -> None:
        """Resume after a pause (e.g. the user redeemed a new code)."""
        if not self._paused:
            return
        self._paused = False
        self._resume_event.set()
        _LOGGER.info("服务端已恢复权益，重建隧道进程")
        if self._supervisor_task is None or self._supervisor_task.done():
            self._supervisor_task = self.hass.async_create_background_task(
                self._async_supervise(), name=f"{self._binary.name}-supervisor"
            )

    async def async_stop(self) -> None:
        """Stop supervising and kill the child. **必须在 async_unload_entry 里调用。**"""
        self._stopping = True
        apply_task, self._apply_task = self._apply_task, None
        if apply_task is not None and not apply_task.done():
            apply_task.cancel()
        # ⚠️ 先把**所有**取消信号发出去再逐个 await：若 await apply_task 期间
        # 外层取消传进来（_swallowed_outer_cancel → raise），supervisor 的
        # cancel 已经发出——它不会在此期间又拉起一个子进程。
        supervisor_task = self._supervisor_task
        self._supervisor_task = None
        if supervisor_task is not None:
            supervisor_task.cancel()
        # 无条件 await（即使 cancel 后瞬间已 done）：把任务的异常/取消取走，
        # 避免 "Task exception was never retrieved" 警告。
        if apply_task is not None:
            try:
                await apply_task
            except asyncio.CancelledError:
                if _swallowed_outer_cancel():
                    raise
            except Exception:  # noqa: BLE001 - 收敛失败不阻断卸载
                _LOGGER.debug("收敛期望态任务异常（忽略）", exc_info=True)
        if supervisor_task is not None:
            try:
                await supervisor_task
            except asyncio.CancelledError:
                if _swallowed_outer_cancel():
                    raise
        await self._async_terminate_child()
        _LOGGER.debug("hs-frpc 已停止")

    async def async_restart(self) -> None:
        """停掉子进程，再从**磁盘上当前的**二进制重新拉起。

        自动更新换完二进制后必须走这里——旧进程持有的是已被 rename 掉的旧
        inode，不重启就永远加载不到新文件（见 updater 模块 docstring 第 2 条）。

        暂停态跨重启保留：``async_pause`` 清掉的 ``_resume_event`` 不被
        ``async_stop`` 触碰，所以服务端 ``action=stop`` 期间更新二进制不会
        把隧道偷偷拉起来。
        """
        await self.async_stop()
        await self.async_start()

    async def async_wait_stable(self, timeout: float) -> bool:
        """最多等 ``timeout`` 秒让子进程真正起来。

        ``async_start`` 只是起了 supervisor 任务，spawn 发生在任务里，返回时
        并不知道成没成——回滚判定需要这个确定性。

        ⚠️ 只判 ``is_running`` 会被崩溃循环骗过：supervisor 的退避重连让它
        周期性 flap（崩 → 睡 2s → 再拉起 → 再崩……），一次 0.25s 采样正好落在
        "刚拉起"的窗口就会把坏版本判成启动成功，回滚随之失效。因此这里要求
        **同一个 PID 持续存活**：崩溃循环每轮都是新 PID，换 PID 即判失败。

        注意边界：这里验的是"进程活着"而非"隧道连上"。能 spawn、能活着但
        连不上站点（网络/票据问题）的版本会判为稳定——这是知情取舍：此类
        版本本身是合法交付物，连通问题由 supervisor 重连与 coordinator 排障
        信息承接，不属于"二进制坏了"的回滚范畴。
        """
        deadline = self.hass.loop.time() + timeout
        seen_pid: int | None = None
        while True:
            if self.is_running:
                if seen_pid is None:
                    seen_pid = self.pid
                elif self.pid != seen_pid:
                    return False  # 换了 PID = 中间崩过一次
            elif seen_pid is not None:
                return False  # 起来过又没了 = 崩了
            if self.hass.loop.time() >= deadline:
                return seen_pid is not None  # 从未起来 → False
            await asyncio.sleep(0.25)

    async def _async_supervise(self) -> None:
        """Spawn → wait → backoff → respawn，直到 ``async_stop``。"""
        backoff = RESTART_BACKOFF_INITIAL
        while not self._stopping:
            # 上一轮的日志泵可能还在排空管道缓冲：先收敛再 spawn，
            # 否则 self._log_task 被覆盖后旧 task 再也 cancel 不掉（HA 关闭时挂住）。
            await self._cancel_log_task()
            if not self._resume_event.is_set():
                # 暂停中：等 async_resume / async_stop。
                await self._resume_event.wait()
                if self._stopping:
                    return
            try:
                await self._async_spawn()
            except (OSError, ValueError) as err:
                self._last_error = f"启动 hs-frpc 失败：{err}"
                _LOGGER.error("%s；%.0fs 后重试", self._last_error, backoff)
                await self._async_sleep_or_stop(backoff)
                backoff = _next_backoff(backoff)
                continue

            proc = self._proc
            assert proc is not None
            # 第一段稳定运行时间够长就重置退避，避免"偶尔崩一次"累积成 5 分钟空窗。
            started = self.hass.loop.time()
            returncode = await proc.wait()
            # ⚠️ 先让日志泵把管道里剩下的数据排空再取 tail：`proc.wait()` 只保证
            # 进程退出，管道缓冲可能还有未读行——而那正是 fatal 的最后几行，
            # 是 last_error / child_log_tail 最需要的内容。直接 cancel 会丢掉它们。
            await self._drain_log_task(grace=0.5)
            if self._stopping:
                return
            ran_for = self.hass.loop.time() - started
            self._restarts += 1
            tail = "\n".join(self._stderr_tail)
            self._last_error = (
                f"hs-frpc 退出，exit code={returncode}（已运行 {ran_for:.0f}s）"
                + (f"；最后输出：{tail}" if tail else "")
            )
            # 契约：致命错误退出码非 0（ha/README.md）。我们统一退避重试，
            # 因为网络抖动/令牌过期/权益到期都表现为非 0，且 /healthz 会一直 503，
            # Supervisor watchdog（app 模式）或本进程 supervisor 会兜底。
            _LOGGER.warning("%s；%.0fs 后重启", self._last_error, backoff)
            if self._on_state_change is not None:
                self._on_state_change({"type": "tunnel_down", "message": self._last_error})
            # ⚠️ 顺序很重要：先用 ran_for 决定**本次**该睡多久，再睡。
            # 曾经的 bug 是把重置判断写在 sleep 之后 —— 崩溃循环里 ran_for 永远很小，
            # backoff 一路翻倍到 300s 后永远锁死在那里（用户改完配置也要等 5 分钟）。
            if ran_for > STABLE_RUN_SECONDS:
                backoff = RESTART_BACKOFF_INITIAL
            else:
                backoff = _next_backoff(backoff)
            await self._async_sleep_or_stop(backoff)

    async def _async_spawn(self) -> None:
        """Create the child process and start its log pump."""
        _LOGGER.debug("启动 hs-frpc：%s（local_target=%s, protocol=%s）", self._binary, self._local_target, self._protocol)
        self._proc = await asyncio.create_subprocess_exec(
            str(self._binary),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=self._environment(),
        )
        self._stderr_tail.clear()
        proc = self._proc
        self._log_task = self.hass.async_create_background_task(
            self._async_log_pump(proc), name=f"{self._binary.name}-log"
        )
        if self._on_state_change is not None:
            self._on_state_change({"type": "proxy_start", "message": f"pid={proc.pid}"})

    async def _async_log_pump(self, proc: asyncio.subprocess.Process) -> None:
        """Forward child stdout/stderr into the HA log (never blocks the loop).

        ``hs-frpc`` 的日志级别由 ``HS_LOG_LEVEL`` 控制；这里原样透传，加 ``[hs-frpc]``
        前缀，便于用户在 **设置 → 系统 → 日志** 里过滤（02 §9.4 结构化日志）。

        容错纪律：单行异常**不能**让日志泵整体退出。子进程写出一行超过
        StreamReader 的 limit（默认 64KiB、无换行）时 ``async for`` 会抛
        ``ValueError``（LimitOverrunError 的包装）；若把它当成"管道关闭"处理，
        日志泵会永久结束——此后子进程的日志全丢，管道写满还可能**阻塞 hs-frpc**。
        """
        assert proc.stdout is not None
        while True:
            try:
                raw = await proc.stdout.readline()
            except asyncio.CancelledError:
                raise
            except ValueError as err:
                # 超长行：丢弃该行继续泵，而不是结束整个泵
                _LOGGER.debug("hs-frpc 日志行超长，已丢弃该行：%s", err)
                continue
            except OSError as err:  # 管道真的断了
                _LOGGER.debug("hs-frpc 日志泵结束（管道关闭）：%s", err)
                return
            if not raw:  # EOF：子进程退出
                return
            text = raw.decode(errors="replace").rstrip()
            if not text:
                continue
            self._stderr_tail.append(text)
            level = _guess_level(text)
            _LOGGER.log(level, "[hs-frpc] %s", text)

    async def _drain_log_task(self, grace: float = 0.5) -> None:
        """给日志泵一小段排空时间再收敛它。

        子进程退出后管道里可能仍有缓冲行；立刻 cancel 会丢掉它们
        （实测丢掉的就是 fatal 那几行）。超时后仍强制收敛，避免挂住。
        """
        task = self._log_task
        if task is None or task.done():
            return
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=grace)
        except (TimeoutError, asyncio.TimeoutError):
            pass
        except asyncio.CancelledError:
            # shield 只挡"等待侧取消"，**不阻止别人取消这个日志泵自身**：
            # pause 路径的 _async_terminate_child → _cancel_log_task 会并发
            # cancel 同一个任务，此时 CancelledError 属"被等对象自己没了"，
            # 按原语义忽略；只有外层取消才上抛。
            if _swallowed_outer_cancel():
                raise
        except Exception:  # noqa: BLE001 - 泵的异常不该影响重启流程
            _LOGGER.debug("hs-frpc 日志泵排空时异常", exc_info=True)
        await self._cancel_log_task()

    async def _cancel_log_task(self) -> None:
        """收敛当前日志泵任务（幂等）。"""
        task, self._log_task = self._log_task, None
        if task is None:
            return
        if not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            if _swallowed_outer_cancel():
                raise
        except Exception:  # noqa: BLE001 - 日志泵失败不应影响 supervise 循环
            _LOGGER.exception("hs-frpc 日志泵异常退出")

    async def _async_terminate_child(self) -> None:
        """SIGTERM → 等待 → SIGKILL."""
        await self._cancel_log_task()
        proc, self._proc = self._proc, None
        if proc is None or proc.returncode is not None:
            return
        _LOGGER.debug("终止 hs-frpc（pid=%s）", proc.pid)
        try:
            proc.terminate()
        except ProcessLookupError:
            return
        try:
            async with asyncio.timeout(STOP_TIMEOUT_SECONDS):
                await proc.wait()
        except (TimeoutError, asyncio.TimeoutError):
            _LOGGER.warning("hs-frpc 在 %.0fs 内未退出，SIGKILL", STOP_TIMEOUT_SECONDS)
            proc.kill()
            await proc.wait()

    async def _async_sleep_or_stop(self, seconds: float) -> None:
        """Sleep in small slices so ``async_stop`` / ``async_pause`` are honoured promptly."""
        slept = 0.0
        while slept < seconds and not self._stopping and self._resume_event.is_set():
            slice_seconds = min(1.0, seconds - slept)
            await asyncio.sleep(slice_seconds)
            slept += slice_seconds


def _next_backoff(current: float) -> float:
    """Double the backoff, capped (2 → 4 → … → 300)."""
    return min(current * 2, RESTART_BACKOFF_MAX)


def _swallowed_outer_cancel() -> bool:
    """当前协程自己是否也收到了取消（区别于"被 await 的任务自己被 cancel"）。

    ``except asyncio.CancelledError: pass`` 吞掉的可能是**外层**取消——例如
    unload 时 ``_stop_updater`` cancel 了正在 ``async_restart()`` 里的更新
    任务：若不区分，取消在内层被吞，协程会继续跑完 ``async_start``，在
    unload 之后把 hs-frpc 又拉起来一个孤儿进程（本仓库反复修的那类 bug）。
    Python 3.11+ 的 ``Task.cancelling()`` 记录了向本任务发出的取消请求数；
    被等任务自身被 cancel 时它不增长，借此区分两种来源。
    """
    task = asyncio.current_task()
    return task is not None and task.cancelling() > 0


# frp 日志行格式：`2026-10-15 16:13:03.326 [E] [client/control.go:153] ...`
# 级别标记是方括号内的单字母。曾经的实现**只按英文单词子串**猜：
# `connect to server error: EOF`（W 级）会被报成 ERROR —— 4627 次重复的
# "StartWorkConn ... pool is full"（E 级）与单发 EOF 难分轻重。
_FRP_LEVEL_TAG = re.compile(r"\[(?P<tag>[EWIDT])\]")

_FRP_TAG_LEVEL = {
    "E": logging.ERROR,
    "W": logging.WARNING,
    "I": logging.INFO,
    "D": logging.DEBUG,
    "T": logging.DEBUG,  # frp trace → 最近的标准级别
}


def _guess_level(text: str) -> int:
    """Map a child log line onto a Python logging level.

    先认 frp 的 ``[E]/[W]/[I]/[D]/[T]`` 标记（权威），再退化到英文子串
    （兼容老版本/非 frp 输出）。子串兜底必须排在标记之后，否则
    `[W] ... error: EOF` 会越过真实级别被报成 ERROR。
    """
    if m := _FRP_LEVEL_TAG.search(text):
        return _FRP_TAG_LEVEL.get(m.group("tag"), logging.INFO)
    lowered = text.lower()
    if "fatal" in lowered or "panic" in lowered:
        return logging.CRITICAL
    if "error" in lowered or "fail" in lowered:
        return logging.ERROR
    if "warn" in lowered:
        return logging.WARNING
    if "debug" in lowered or "trace" in lowered:
        return logging.DEBUG
    return logging.INFO
