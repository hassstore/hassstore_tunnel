"""读取 HA 自身 HTTP 配置（server_port / use_x_forwarded_for）的兼容层。

背景（为什么要单独抽一个模块）
------------------------------
隧道回源地址必须指向 HA 真实监听的端口，而"端口写死 8123"在新版本上已经不成立：

* **2026.x 的 storage 化**：http 配置迁移到 ``HTTPConfigStore``，挂在
  ``hass.data["http"].stable``（``config.py`` 的 ``ConfData`` TypedDict）；
  且 **Supervisor 环境下 Core 的默认 HTTP 端口从 8123 改成了 80**
  （``SUPERVISOR_DEFAULT_PORT = 80``，还可用 ``SETUP_PORT`` 环境变量覆盖）。
  app 形态若继续写死 ``homeassistant:8123`` 会连错端口。
* **2025.x 及更早**：http 组件**不往** ``hass.data`` 写任何配置，
  唯一渠道是已弃用的 ``async_get_last_config``（读 ``.storage/http``）。
* **两代通用**：``hass.http``（``HomeAssistantHTTP``）上的 ``server_port`` 与
  ``trusted_proxies`` 是绑定后的**运行态**值——最贴近"现在生效的配置"。

读取顺序统一为：运行态 → 新版 storage → 旧版 ``async_get_last_config``，
全部失败再回退常量。任何一步读不到都视为"未知"，绝不抛异常——
这里只是**探测**，不该影响集成 setup。
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

# 兜底值：HA 全版本通用的默认 HTTP 端口（homeassistant.const.SERVER_PORT）。
# 不 import 那个常量——selftest 的 stub 里没有它，且它两版都恰好是 8123。
DEFAULT_HA_PORT = 8123


def _int_port(value: Any) -> int | None:
    """Coerce a stored port into ``int``; ``None`` on anything weird."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


async def _last_stored_conf(hass: HomeAssistant) -> dict[str, Any] | None:
    """Best-effort：拿到"最近一次生效"的 http 配置 dict（跨版本）。

    * 2026.x：``hass.data["http"]`` 是 ``HTTPConfigStore``，``.stable`` 是 ConfData；
    * 2025.x：走 ``homeassistant.components.http.async_get_last_config``。
      用 ``importlib`` 而不是顶部 ``from``：该函数 2026.x 已删除，静态 import 会
      ImportError；同时避免把易变符号写进 ha_api_check 的快照契约。
    """
    store = getattr(hass, "data", {}).get("http")
    stable = getattr(store, "stable", None)
    if isinstance(stable, dict) and stable:
        return stable
    try:
        http_component = importlib.import_module("homeassistant.components.http")
        getter = getattr(http_component, "async_get_last_config", None)
        if getter is None:
            return None
        conf = await getter(hass)
    except Exception:  # noqa: BLE001 - 探测失败绝不外抛
        return None
    return conf if isinstance(conf, dict) else None


async def async_ha_http_port(hass: HomeAssistant) -> int:
    """Return the port HA's HTTP server is actually listening on.

    优先 ``hass.http.server_port``（绑定后的运行态，含 SETUP_PORT 覆盖与
    Supervisor 默认 80）；读不到再退到 storage；最后是 8123 兜底。
    """
    server = getattr(hass, "http", None)
    if (port := _int_port(getattr(server, "server_port", None))) is not None:
        return port
    conf = await _last_stored_conf(hass)
    if conf is not None and (port := _int_port(conf.get("server_port"))) is not None:
        return port
    _LOGGER.debug("无法探测 HA HTTP 端口，回退 %d", DEFAULT_HA_PORT)
    return DEFAULT_HA_PORT


async def async_use_x_forwarded_for(hass: HomeAssistant) -> bool | None:
    """读出**生效中**的 ``use_x_forwarded_for``。

    返回值语义（决定 issues.trusted_proxies 会不会误报/漏报）：

    * ``True``  → 已开启；
    * ``False`` → **读到了完整的 HTTP 配置，但里面没有这一项**。两代 HA 的
      schema 都把它设为默认关闭（2025.x 用的是 ``vol.Inclusive(..., "proxy")``，
      用户没配时键**完全不存在**）——所以"读到 conf 却没有键"就是"没配"，
      必须返回 ``False`` 才能让 Repairs 报出这个"不配就登录死循环"的硬门槛；
    * ``None``  → 连 HTTP 配置本身都读不到（http 组件未 setup / 探测失败）。
      此时**不能**断言"没配"，否则会在探测失败的机器上误报。

    ⚠️ 曾经的写法是"没有这个键就返回 None"，于是 2025.x 上真正没配的用户
    永远收不到 Repairs 提示——正好漏掉了最需要提示的那批人。
    """
    conf = await _last_stored_conf(hass)
    if conf is None:
        return None
    # 只把"看起来确实是 HTTP 配置"的 dict 当作可信来源，避免把任意 dict 的
    # 缺失键误判成"用户没配"。server_port 是两代 conf 都必然存在的字段。
    if "server_port" not in conf and "trusted_proxies" not in conf:
        return None
    return bool(conf.get("use_x_forwarded_for", False))
