"""``binary_sensor.tunnel_online`` —— 隧道是否在线。

判据（两源取"都可用时以数据面为准"）：
  * 数据面：``hs-frpc`` 的 ``/healthz`` → ``ok`` **且** ``connected``（ha/README.md CLI 契约）
  * 控制面：``GET /api/v1/tunnel/client/config`` 可达 + ``device.status == "active"``

为什么控制面状态也要看：隧道进程可能连着但权益已到期/被管理员停用，
服务端会在下一次 ``Ping`` 里拒绝（02 §7.6 "到期/耗尽 → 停用（秒级）"），
此时"进程在跑"≠"服务可用"。任一条件明确为否就报 off。
"""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import BINARY_SENSOR_ONLINE
from .coordinator import HassStoreTunnelCoordinator
from .entity import HassStoreTunnelEntity

# 站点侧设备状态里视为"可用"的取值（02 §5.6 tunnel_devices.status）。
_ACTIVE_DEVICE_STATUSES = {"active"}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the online binary sensor."""
    coordinator: HassStoreTunnelCoordinator = entry.runtime_data.coordinator
    async_add_entities([HassStoreTunnelOnlineSensor(coordinator)])


class HassStoreTunnelOnlineSensor(HassStoreTunnelEntity, BinarySensorEntity):
    """Whether the tunnel is up and the device is allowed to serve traffic."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = BINARY_SENSOR_ONLINE

    def __init__(self, coordinator: HassStoreTunnelCoordinator) -> None:
        super().__init__(coordinator, BINARY_SENSOR_ONLINE)

    @property
    def is_on(self) -> bool:
        """Return True only when data plane AND control plane both say OK."""
        state = self.tunnel_state
        if not state.online:
            return False
        # 控制面拿不到时（离线容忍）不因此判负，只以数据面为准。
        if state.config_reachable and state.device_status:
            return state.device_status in _ACTIVE_DEVICE_STATUSES
        return True
