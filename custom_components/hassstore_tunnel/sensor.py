"""Sensors: traffic today / expire at / tunnel url / versions.

实体与口径（``docs/design/02-tunnel-service.md`` §9.3 步骤 4、§17.3 ✅Q4）::

    sensor.tunnel_traffic_today     今日用量，单位 **GB = 10^9 字节**（不是 GiB！）
    sensor.tunnel_expire_at         权益到期（timestamp 设备类，UTC）
    sensor.tunnel_url               公网访问地址 https://<子域名>.<线路根域名>
    sensor.tunnel_version           hs-frpc 版本（v0.71.0-hs.N，02 §15.7）
    sensor.tunnel_config_revision   服务端 config_revision（热更新是否已生效）

数值全部来自 ``GET /api/v1/tunnel/client/config``（权威控制面）与本地 ``/healthz``
（数据面事实），不做任何本地推算，避免与后台对账口径打架（02 §10.1）。
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory, UnitOfInformation
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    BYTES_PER_GB,
    SENSOR_CONFIG_REVISION,
    SENSOR_EXPIRE_AT,
    SENSOR_TRAFFIC_TODAY,
    SENSOR_URL,
    SENSOR_VERSION,
)
from .coordinator import HassStoreTunnelCoordinator, TunnelState
from .entity import HassStoreTunnelEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up all tunnel sensors."""
    coordinator: HassStoreTunnelCoordinator = entry.runtime_data.coordinator
    async_add_entities(
        [
            HassStoreTunnelTrafficSensor(coordinator),
            HassStoreTunnelExpireSensor(coordinator),
            HassStoreTunnelUrlSensor(coordinator),
            HassStoreTunnelVersionSensor(coordinator),
            HassStoreTunnelConfigRevisionSensor(coordinator),
        ]
    )


class HassStoreTunnelTrafficSensor(HassStoreTunnelEntity, SensorEntity):
    """Traffic used in the **current billing window**, in GB (10^9 bytes).

    ⚠️ 名字叫 ``traffic_today`` 但语义是"本计费周期累计"（后台的 ``quota.used_bytes``），
    不是"今日"——续期时会归零。这里在属性里显式给出 ``window`` 说明，
    并把 ``unlimited`` 标记暴露出来（total=0 表示不限量套餐）。

    ``total_increasing``：累计量在权益续期/新套餐时可能回落到 0，
    HA 能识别这种"累计量重置"而不会记出负增量。
    """

    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_suggested_display_precision = 3
    _attr_translation_key = SENSOR_TRAFFIC_TODAY

    def __init__(self, coordinator: HassStoreTunnelCoordinator) -> None:
        super().__init__(coordinator, SENSOR_TRAFFIC_TODAY)

    @property
    def native_value(self) -> float | None:
        """Used bytes converted to GB (10^9)."""
        used = self.tunnel_state.quota_used_bytes
        if used is None:
            return None
        return round(used / BYTES_PER_GB, 6)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose the raw byte counters for troubleshooting / automations."""
        attrs = super().extra_state_attributes
        state: TunnelState = self.tunnel_state
        attrs["used_bytes"] = state.quota_used_bytes
        attrs["total_bytes"] = state.quota_total_bytes
        attrs["unlimited"] = state.quota_total_bytes == 0
        attrs["window"] = "本计费周期累计（非今日；续期后归零）"
        attrs["renew_at"] = state.renew_at.isoformat() if state.renew_at else None
        return attrs


class HassStoreTunnelExpireSensor(HassStoreTunnelEntity, SensorEntity):
    """When the current entitlement expires (``expire_at``)."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_translation_key = SENSOR_EXPIRE_AT

    def __init__(self, coordinator: HassStoreTunnelCoordinator) -> None:
        super().__init__(coordinator, SENSOR_EXPIRE_AT)

    @property
    def native_value(self):
        """Return the entitlement expiry as an aware datetime."""
        return self.tunnel_state.expire_at


class HassStoreTunnelUrlSensor(HassStoreTunnelEntity, SensorEntity):
    """The public URL of this tunnel (``https://<prefix>.<line root domain>``)."""

    _attr_device_class = SensorDeviceClass.URL
    _attr_translation_key = SENSOR_URL

    def __init__(self, coordinator: HassStoreTunnelCoordinator) -> None:
        super().__init__(coordinator, SENSOR_URL)

    @property
    def native_value(self) -> str | None:
        """Return the tunnel URL reported by the control plane."""
        return self.tunnel_state.url

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose the components separately so dashboards can compose links."""
        attrs = super().extra_state_attributes
        attrs["fqdn"] = self.tunnel_state.fqdn
        attrs["device_name"] = self.tunnel_state.device_name
        return attrs


class HassStoreTunnelVersionSensor(HassStoreTunnelEntity, SensorEntity):
    """Local ``hs-frpc`` version, read from ``/healthz`` (diagnostic)."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_translation_key = SENSOR_VERSION

    def __init__(self, coordinator: HassStoreTunnelCoordinator) -> None:
        super().__init__(coordinator, SENSOR_VERSION)

    @property
    def native_value(self) -> str | None:
        """Return e.g. ``v0.71.0-hs.1``."""
        return self.tunnel_state.client_version


class HassStoreTunnelConfigRevisionSensor(HassStoreTunnelEntity, SensorEntity):
    """Server-side ``config_revision`` — bumped when subdomain/line changes land.

    ⚠️ 不能用 ``TOTAL``：设备被删除重建/管理员重置时 revision 会回落到 1，
    而 ``TOTAL`` 在 HA 里表示"只增不减的计数器"，值倒退会记出负增量并触发修复提示。
    改用 ``MEASUREMENT``（瞬时值语义，与"配置版本号"这件事本身一致）。
    """

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_translation_key = SENSOR_CONFIG_REVISION

    def __init__(self, coordinator: HassStoreTunnelCoordinator) -> None:
        super().__init__(coordinator, SENSOR_CONFIG_REVISION)

    @property
    def native_value(self) -> int | None:
        """Return the revision reported by the control plane / data plane."""
        return self.tunnel_state.config_revision
