"""DataUpdateCoordinator：定时拉取隧道状态。

数据源（两条，互不阻塞）：
  1. ``GET /api/v1/tunnel/client/config`` —— 权威控制面状态：``device.url`` /
     ``expire_at`` / ``quota`` / ``config_revision``（02 §6.3）。需要设备令牌。
  2. ``http://127.0.0.1:7401/healthz`` —— **本地数据面事实**：``hs-frpc`` 自己的
     自检结果（已拉配置 + 控制连接状态 + 版本）。02 §9.4 / ha/README.md CLI 契约。

为什么两条都要：控制面可达 ≠ 隧道连上（可能刚崩、正在退避重启）；
数据面健康 ≠ 权益有效（可能已到期，服务端正在拒绝）。
实体在两者都有数据时给出最完整的画面，缺一条就只用另一条，绝不因此让实体变
``unavailable`` —— 隧道场景下"短暂拉不到控制面"是**常态**（02 §9.4 离线容忍）。
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import aiohttp
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import HassStoreAuthError, HassStoreClient, HassStoreError
from .const import (
    AUTH_ERROR_THRESHOLD,
    DEFAULT_HEALTH_ADDR,
    DOMAIN,
    UPDATE_INTERVAL_SECONDS,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class TunnelState:
    """Everything the entities / panel need, in one immutable-ish snapshot."""

    # 数据面（local hs-frpc /healthz）
    health_reachable: bool = False
    online: bool = False
    client_version: str | None = None
    config_revision: int | None = None
    health_raw: dict[str, Any] = field(default_factory=dict)
    # 控制面（GET /tunnel/client/config）
    config_reachable: bool = False
    url: str | None = None
    fqdn: str | None = None
    device_name: str | None = None
    device_status: str | None = None
    line_code: str | None = None
    line_addr: str | None = None
    protocol: str | None = None
    expire_at: datetime | None = None
    renew_at: datetime | None = None
    quota_total_bytes: int | None = None
    quota_used_bytes: int | None = None
    # 服务端下发的动作指令：none | reload | stop（02 §6.3、§9.4）
    #   stop = 权益到期/超额/设备被停用 → 客户端应主动停下隧道，避免无谓重连。
    action: str | None = None
    last_error: str | None = None

    @property
    def quota_remaining_bytes(self) -> int | None:
        """Remaining quota, or ``None`` for unlimited plans (``total_bytes == 0``)."""
        if self.quota_total_bytes is None or self.quota_used_bytes is None:
            return None
        if self.quota_total_bytes == 0:  # 0 = 不限量（02 §17.3 ✅Q24）
            return None
        return max(self.quota_total_bytes - self.quota_used_bytes, 0)


class HassStoreTunnelCoordinator(DataUpdateCoordinator[TunnelState]):
    """Poll ``/healthz`` (always) and ``/tunnel/client/config`` (when we have a token)."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: HassStoreClient,
        *,
        device_token: str | None,
        health_addr: str | None = DEFAULT_HEALTH_ADDR,
        process_health_cb: Any = None,
        action_cb: Any = None,
        addon_state_cb: Any = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {entry.title}",
            update_interval=timedelta(seconds=UPDATE_INTERVAL_SECONDS),
            config_entry=entry,
        )
        self.client = client
        self.device_token = device_token
        self.health_addr = health_addr
        # 可注入的本地进程健康回调（集成内置模式下由 TunnelProcess 提供），
        # 让 coordinator 不必 import 进程管理模块（避免循环依赖）。
        self._process_health_cb = process_health_cb
        # action 变化时的回调（02 §9.4 流程图里的 action=stop 分支）：
        # 内置模式用它暂停/恢复子进程；app 模式由服务端直接拒绝连接，无需客户端动作。
        self._action_cb = action_cb
        # addon 模式回调：hs-frpc 在 app 容器网络命名空间里，本机 127.0.0.1:7401
        # 永远访问不到（集成与容器不共享 loopback）。此时 health_addr 传 None，
        # "数据面活着"改由 Supervisor 的 app state（running/not_running/…）近似。
        self._addon_state_cb = addon_state_cb
        self._last_action: str | None = None
        self._auth_failures = 0
        self.last_error: str | None = None

    @property
    def has_token(self) -> bool:
        """Whether a device token is available."""
        return bool(self.device_token)

    @property
    def auth_failures(self) -> int:
        """连续鉴权失败次数（暴露给实体属性，便于用户理解"为什么突然要重新绑定"）。

        计数语义：**只有成功拉到 config 才清零**，网络错误不影响它。
        这曾是 bug：网络错误也清零，于是一次超时就把"连续 3 次 401"洗白，
        reauth 可能永远不触发（用户看到的一直是"控制面不可达"）。
        """
        return self._auth_failures

    async def _async_update_data(self) -> TunnelState:
        state = TunnelState()

        # ---- 1) 本地数据面 healthz / addon 状态 -------------------------
        health = await self._async_read_health()
        if health is not None:
            state.health_reachable = True
            state.health_raw = health
            state.online = bool(health.get("ok")) and bool(health.get("connected"))
            version = health.get("version")
            state.client_version = str(version) if version else None
            revision = health.get("config_revision")
            if isinstance(revision, int):
                state.config_revision = revision
            if not state.online:
                state.last_error = health.get("last_error") or health.get("detail")
        elif self.health_addr is None and self._addon_state_cb is not None:
            # addon 模式：访问不到 hs-frpc 的 healthz（它在 app 容器 netns 里），
            # 用 Supervisor 的 app state 近似"数据面活着"。
            try:
                addon_state = await self._addon_state_cb()
            except Exception:  # noqa: BLE001 - 回调内已吞，双保险
                addon_state = ""
            state.health_raw = {"addon_state": addon_state}
            if addon_state in ("running", "started"):
                state.health_reachable = True
            elif addon_state in ("not_running", "stopped", "error", "not_installed"):
                state.last_error = f"隧道 app 当前状态：{addon_state}"

        # ---- 2) 控制面 config ------------------------------------------
        config_error: str | None = None
        if self.has_token:
            try:
                config = await self.client.async_get_config()
            except HassStoreAuthError as err:
                self._auth_failures += 1
                config_error = f"控制面鉴权失败：{err}"
                if self._auth_failures >= AUTH_ERROR_THRESHOLD:
                    # 只有连续多次失败才让用户重走授权流程（02a §B.4.1 reauth）。
                    raise ConfigEntryAuthFailed(str(err)) from err
            except HassStoreError as err:
                # ⚠️ 网络错误**不能**清零 _auth_failures：曾经的 bug 是这里也清零，
                # 于是一次超时就把"连续 3 次 401"的计数洗白，reauth 可能永远不触发
                # （用户看到的一直是"控制面不可达"，而不是重新绑定引导）。
                config_error = f"控制面不可达：{err}"
            else:
                self._auth_failures = 0
                state.config_reachable = True
                _apply_config(state, config)
        else:
            config_error = "尚未绑定设备令牌（等待 bind_code 或本地 token 文件）"

        # ---- 3) 本地子进程健康（集成内置模式）-------------------------
        if self._process_health_cb is not None:
            try:
                proc_health = self._process_health_cb()
            except Exception:  # noqa: BLE001 - 回调来自我们自己的进程管理器
                _LOGGER.exception("读取本地 hs-frpc 进程状态失败")
            else:
                if state.client_version is None and proc_health.get("version"):
                    state.client_version = str(proc_health["version"])
                if not state.health_reachable and proc_health.get("running"):
                    # 进程还在但 healthz 拉不到：隧道不可用，但算"数据面可达"，
                    # 让实体展示 available 而不是灰掉，用户才能看到排障信息。
                    state.health_reachable = True
                if not state.online:
                    state.online = bool(proc_health.get("online"))
                if not state.last_error:
                    state.last_error = proc_health.get("last_error")

        # ---- 3.5) 处理服务端动作指令 -----------------------------------
        # action=stop 必须给一句人话：hs-frpc 在这个分支只 log.Printf + 置 stopped，
        # **不写 lastErr**，于是实体属性里空空如也，用户看到的现象是
        # "隧道莫名离线，集成里查不到原因"。
        if state.action == "stop" and not state.last_error:
            state.last_error = (
                "服务端已要求停止隧道（套餐到期 / 流量耗尽 / 设备被停用）；"
                "续费或解除停用后会自动恢复"
            )
        if self._action_cb is not None and state.action != self._last_action:
            self._last_action = state.action
            try:
                self._action_cb(state.action)
            except Exception:  # noqa: BLE001 - 回调来自我们自己的进程管理器
                _LOGGER.exception("处理 action=%s 失败", state.action)

        # ---- 3.6) addon 模式下的 online 推导 -----------------------------
        # 本地模式 online 由 hs-frpc healthz 直接给事实；addon 模式没有 healthz，
        # 用"app 在跑 + 控制面可达 + 未被下发 stop + 设备未停用"近似。拿不到
        # 精确控制连接状态没关系——比"实体恒 off"强（曾经的 bug）。
        if (
            self._addon_state_cb is not None
            and not state.online
            and state.health_reachable
            and state.config_reachable
            and state.action != "stop"
            and state.device_status != "disabled"
        ):
            state.online = True

        # ---- 4) 双源都失败才算更新失败 ---------------------------------
        if not state.health_reachable and not state.config_reachable:
            raise UpdateFailed(config_error or "隧道状态未知（控制面与本地面均不可达）")

        # 有一条能用就不用旧错误覆盖：清掉已恢复的错误。
        if state.online and state.config_reachable:
            state.last_error = None
        elif state.last_error is None:
            state.last_error = config_error
        self.last_error = state.last_error
        return state

    async def _async_read_health(self) -> dict[str, Any] | None:
        """Read ``hs-frpc``'s built-in ``/healthz`` (never raises)."""
        if not self.health_addr:
            # addon 模式：hs-frpc 在 app 容器 netns 里，本机 healthz 不存在。
            return None
        session = async_get_clientsession(self.hass)
        try:
            async with asyncio.timeout(5):
                response = await session.get(
                    f"http://{self.health_addr}/healthz",
                    # 本机回环必须绕过任何代理设置（HA 的共享 session 可能带代理）。
                    proxy=None,
                    headers={"Accept": "application/json"},
                )
                if response.status != 200:
                    _LOGGER.debug("healthz 返回 HTTP %s", response.status)
                    return None
                data = await response.json(content_type=None)
        except (TimeoutError, asyncio.TimeoutError):
            _LOGGER.debug("healthz 超时（%s）", self.health_addr)
            return None
        except (aiohttp.ClientError, ValueError) as err:
            _LOGGER.debug("healthz 不可用（%s）：%s", self.health_addr, err)
            return None
        return data if isinstance(data, dict) else None


def _apply_config(state: TunnelState, config: dict[str, Any]) -> None:
    """Map ``GET /tunnel/client/config`` JSON onto :class:`TunnelState` (02 §6.3)."""
    revision = config.get("config_revision")
    if isinstance(revision, int):
        state.config_revision = revision

    device = config.get("device") or {}
    if isinstance(device, dict):
        state.url = device.get("url")
        state.fqdn = device.get("fqdn")
        state.device_name = device.get("name")
        state.device_status = device.get("status")

    line = config.get("line") or {}
    if isinstance(line, dict):
        state.line_code = line.get("code")
        state.line_addr = line.get("addr")
        state.protocol = line.get("protocol_hint")

    quota = config.get("quota") or {}
    if isinstance(quota, dict):
        total = quota.get("total_bytes")
        used = quota.get("used_bytes")
        state.quota_total_bytes = int(total) if isinstance(total, (int, float)) else None
        state.quota_used_bytes = int(used) if isinstance(used, (int, float)) else None

    action = config.get("action")
    state.action = str(action) if action else None

    state.expire_at = _parse_ts(config.get("expire_at"))
    state.renew_at = _parse_ts(config.get("renew_at"))


def _parse_ts(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp from the API; tolerate ``Z`` and junk."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _LOGGER.debug("无法解析时间戳：%r", value)
        return None
