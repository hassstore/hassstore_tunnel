"""Shared entity plumbing for the HassStore Tunnel entities.

实体清单（``docs/design/02-tunnel-service.md`` §9.3 步骤 4）::

    binary_sensor.tunnel_online        隧道是否在线（数据面 + 控制面双源）
    sensor.tunnel_traffic_today        今日用量（GB，10^9 字节口径）
    sensor.tunnel_expire_at            权益到期时间
    sensor.tunnel_url                  公网访问地址
    sensor.tunnel_version              hs-frpc 版本（v0.71.0-hs.N）
    sensor.tunnel_config_revision      服务端配置版本（热更新判据）

所有实体都挂在同一个 ``DataUpdateCoordinator`` 上，``should_poll = False``，
不做任何自己的 IO。
"""

from __future__ import annotations

from typing import Any

from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import AUTH_ERROR_THRESHOLD, DOMAIN, NAME, VERSION
from .coordinator import HassStoreTunnelCoordinator, TunnelState

# 设备信息里的 configuration_url 指向站点（不是隧道地址 —— 隧道地址由
# sensor.tunnel_url 暴露，且每个用户不同）。
CONFIGURATION_URL = "https://hassstore.nextrt.com/user/tunnel"


class HassStoreTunnelEntity(CoordinatorEntity[HassStoreTunnelCoordinator]):
    """Base entity: coordinator-backed, no polling, one shared device."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: HassStoreTunnelCoordinator, key: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.config_entry.entry_id}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.config_entry.entry_id)},
            name=NAME,
            manufacturer="HassStore",
            model="内网穿透客户端",
            sw_version=VERSION,
            entry_type=DeviceEntryType.SERVICE,
            configuration_url=CONFIGURATION_URL,
        )

    @property
    def tunnel_state(self) -> TunnelState:
        """Shortcut to the current coordinator data.

        ⚠️ **绝不能叫 `state`**。MRO 是
        ``[子类, HassStoreTunnelEntity, CoordinatorEntity, SensorEntity, Entity]``，
        本类的 ``state`` 会**遮蔽**平台的 ``SensorEntity.state`` / ``BinarySensorEntity.state``
        （它们返回 ``native_value`` / ``on|off``）。而 HA 写状态机走的是
        ``Entity._stringify_state`` → ``str(self.state)``，于是所有实体状态会变成
        ``"TunnelState(online=True, ...)"`` 这种 dataclass repr：
          - 5 个 sensor 显示 dataclass 字符串，`data_size`+`total_increasing` 的
            数值型实体拿到非数字状态 → 统计/recorder 报错；
          - `binary_sensor.tunnel_online` 永远不是 `on/off` → 依赖它的自动化全废。
        （`@final` 只在类型检查期有效，运行期拦不住遮蔽。）

        另外不要直接返回 ``self.coordinator.data``：reload 时序下 runtime_data 可能
        还是旧的（旧 coordinator 已 shutdown），``data`` 会是 None，
        调用方读 ``.online`` 直接 AttributeError。返回空状态更安全。
        """
        return self.coordinator.data or TunnelState()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose diagnostics that help support without reading logs."""
        state = self.tunnel_state
        runtime = getattr(self.coordinator.config_entry, "runtime_data", None)
        proc_health = getattr(runtime, "process", None)
        snapshot = {}
        if proc_health is not None:
            try:
                snapshot = proc_health.state_snapshot() or {}
            except Exception:  # noqa: BLE001 - 属性展示不能让隧道崩
                snapshot = {}
        attrs: dict[str, Any] = {
            "mode": getattr(runtime, "mode", None),
            "health_reachable": state.health_reachable,
            "config_reachable": state.config_reachable,
            "config_revision": state.config_revision,
            "client_version": state.client_version,
            # auth_failures：让"突然弹出重新绑定表单"有前因（见 coordinator 的阈值判断）
            "auth_failures": f"{self.coordinator.auth_failures}/{AUTH_ERROR_THRESHOLD}",
        }
        if state.line_code:
            attrs["line"] = state.line_code
        if state.line_addr:
            attrs["line_addr"] = state.line_addr
        if state.device_status:
            attrs["device_status"] = state.device_status
        if state.protocol:
            attrs["protocol"] = state.protocol
        if state.action and state.action != "none":
            attrs["server_action"] = state.action
        if state.last_error:
            attrs["last_error"] = state.last_error
        if state.quota_total_bytes is not None:
            attrs["quota_total_bytes"] = state.quota_total_bytes
            attrs["quota_used_bytes"] = state.quota_used_bytes
            attrs["quota_remaining_bytes"] = state.quota_remaining_bytes
        # 内置模式的进程级诊断：最后几行 [hs-frpc] 日志直接挂到实体上，
        # 用户报"隧道离线"时客服第一句话永远是"看日志"——这能省掉 90% 的来回。
        if snapshot:
            if snapshot.get("restarts") is not None:
                attrs["child_restarts"] = snapshot["restarts"]
            if snapshot.get("pid"):
                attrs["child_pid"] = snapshot["pid"]
            if snapshot.get("paused"):
                attrs["child_paused"] = True
            tail = snapshot.get("stderr_tail") or []
            if tail:
                attrs["child_log_tail"] = list(tail)
        return attrs
