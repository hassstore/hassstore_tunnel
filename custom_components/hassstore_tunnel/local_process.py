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
    HS_CLIENT_VERSION,
    RESTART_BACKOFF_INITIAL,
    RESTART_BACKOFF_MAX,
    STABLE_RUN_SECONDS,
    STOP_TIMEOUT_SECONDS,
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
            "请到 HassStore 官方发布页复制对应架构的 SHA256 填入集成配置。"
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
    try:
        async with asyncio.timeout(300):
            async with session.get(url, allow_redirects=True) as response:
                if response.status != 200:
                    raise BinaryIntegrityError(f"下载失败：HTTP {response.status}（{url}）")
                payload = await response.read()
    except (TimeoutError, asyncio.TimeoutError) as err:
        raise BinaryIntegrityError(f"下载超时（{url}）") from err
    except aiohttp.ClientError as err:
        raise BinaryIntegrityError(f"下载失败（{url}）：{err}") from err

    def _write_and_verify() -> None:
        # 先写临时文件再校验、最后 rename：避免"半截文件"被当成可用二进制。
        tmp = binary.with_suffix(".tmp")
        tmp.write_bytes(payload)
        tmp.chmod(0o700)
        try:
            _verify_and_prepare_sync(tmp, expected_sha256)
        except BinaryIntegrityError:
            tmp.unlink(missing_ok=True)
            raise
        os.replace(tmp, binary)

    await hass.async_add_executor_job(_write_and_verify)
    _LOGGER.info("hs-frpc 下载并校验通过（%d 字节）", len(payload))
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
        self.health_addr = health_addr
        self._on_state_change = on_state_change

        self._proc: asyncio.subprocess.Process | None = None
        self._supervisor_task: asyncio.Task[None] | None = None
        # 服务端下发 action=stop（到期/超额/被停用）时暂停，避免无谓重连刷日志。
        self._resume_event = asyncio.Event()
        self._resume_event.set()
        self._paused = False
        self._log_task: asyncio.Task[None] | None = None
        self._stopping = False
        self._stderr_tail: deque[str] = deque(maxlen=_STDERR_TAIL_LINES)
        self._last_error: str | None = None
        self._restarts = 0

    # -- 状态 ---------------------------------------------------------------
    @property
    def is_running(self) -> bool:
        """Whether the child process is alive."""
        return self._proc is not None and self._proc.returncode is None

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
            "version": HS_CLIENT_VERSION,
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
                ENV_HA_VERSION: str(getattr(self.hass.config, "version", "") or ""),
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
        if self._supervisor_task is not None:
            self._supervisor_task.cancel()
            try:
                await self._supervisor_task
            except asyncio.CancelledError:
                pass
            self._supervisor_task = None
        await self._async_terminate_child()
        _LOGGER.debug("hs-frpc 已停止")

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
            pass
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
            pass
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


def _guess_level(text: str) -> int:
    """Map a child log line onto a Python logging level (best effort)."""
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
