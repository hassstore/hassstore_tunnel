"""HAOS / Supervised 路径：集成充当"安装器"，把 app 装好并启动。

调用序列（**全部证据来自 ``docs/design/02a-ha-client-delivery.md`` §B.1.3 路线 2/3**）：

    1) POST /store/repositories                    ← get_supervisor_client(hass).store.add_repository(
                                                          StoreAddRepository(repository=...))
       已存在时 Supervisor 抛 StoreRepositoryAlreadyAddedError —— 必须幂等吞掉。
    2) GET  /store/addons/<slug>/availability      ← async_get_addon_availability(slug)
       200 = 本机可安装；4xx = 架构不匹配/版本不满足 → 给用户明确 abort 原因。
    3) POST /store/addons/<slug>/install           ← AddonManager.async_install_addon()
    4) POST /addons/<slug>/options                 ← AddonManager.async_set_addon_options()
       写 bind_code / server_url / local_target / protocol / log_level。
    5) POST /addons/<slug>/start                   ← AddonManager.async_start_addon()
    6) GET  /addons/<slug>/info                    ← AddonManager.async_get_addon_info() 核对状态

为什么不用 service：**``hassio.addon_install`` 在现行 HA Core 中已不存在**
（02a §B.1.5：``homeassistant/components/hassio/services.py`` 里 grep ``install`` 零命中），
现存的 hassio service 只有 start/stop/restart/stdin 且都是 admin-only。

为什么 Container 上不能走这条路：``homeassistant/components/hassio/__init__.py`` 的
``async_setup`` 第一步就检查 ``SUPERVISOR`` / ``SUPERVISOR_TOKEN``，缺失即 setup 失败，
于是 ``hass.data[DATA_COMPONENT]`` 不存在，``get_supervisor_client()`` 会 KeyError
（02a §B.1.1）。所以入口一律用 ``async_supervisor_available()`` 先探测。
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .const import APP_REPOSITORY_URL, APP_SLUG

_LOGGER = logging.getLogger(__name__)

# 需要写进 app options 的键（与 ha/apps/tunnel/config.yaml 的 `options:`/`schema:` 一一对应）。
# 注意 key 名必须与 config.yaml **完全一致**，否则 Supervisor 会 400。
# `AddonManager` 的相关方法类型别名（从 HA 源码照抄签名，便于阅读与静态检查）：
#   async_get_addon_info() -> AddonInfo
#   async_install_addon(version: str | None = None) -> None
#   async_set_addon_options(config: AddonOptions) -> None
#   async_start_addon() -> None
#   async_update_addon(version: str | None = None, *, backup: bool = False) -> None
# 证据：homeassistant/components/hassio/addon_manager.py（02a §B.1.3）
ADDON_OPTION_KEYS = (
    "bind_code",
    "device_token",
    "server_url",
    "local_target",
    "protocol",
    "log_level",
)


async def async_supervisor_available(hass: HomeAssistant) -> bool:
    """True only when the ``hassio`` integration is set up (i.e. HAOS/Supervised).

    这是 02a §B.2.3 推荐的探测方式：优先看 hassio config entry（它已经做过环境变量检查），
    而不是只看 ``os.environ["SUPERVISOR"]``。两者都查，任一失败即为 False。
    """
    try:
        # 延迟 import：Container 上这个模块不会被加载（02a §B.2.2 的依赖说明）。
        from homeassistant.components.hassio import async_get_hassio_entry
    except ImportError:
        return False
    try:
        return async_get_hassio_entry(hass) is not None
    except Exception:  # noqa: BLE001 - 任何异常都视为"没有 Supervisor"，走降级路径
        _LOGGER.debug("探测 hassio config entry 失败，按无 Supervisor 处理", exc_info=True)
        return False


def _import_hassio() -> tuple[Any, Any, Any]:
    """Import hassio helpers lazily; raises HomeAssistantError when unavailable."""
    try:
        from homeassistant.components.hassio import (
            AddonError,
            AddonManager,
            get_supervisor_client,
        )
    except ImportError as err:  # pragma: no cover - only on non-Supervisor installs
        raise HomeAssistantError(
            "homeassistant.components.hassio 不可用（当前不是 HAOS/Supervised 环境）"
        ) from err
    return AddonManager, AddonError, get_supervisor_client


def _addon_state(info: Any) -> str:
    """把 ``AddonInfo.state`` 归一化成小写字符串。

    ⚠️ 这里踩过两个"恒假判断"的坑，全部由"猜 HA 的类型"引起：

    1. ``AddonInfo`` **没有** ``installed`` 字段（真源码：
       ``available/hostname/options/state/update_available/version``）——
       未安装是用 ``state=AddonState.NOT_INSTALLED`` 表示的。
       ``info.installed`` 会 AttributeError，而 ``getattr(info,"installed",False)``
       恒为 False（静默把"已安装"判成"未安装"）。
    2. ``AddonState`` 是纯 ``Enum``，取值是 ``not_installed/installing/updating/
       not_running/running``；``"started"`` 只是 Supervisor **API 原始字符串**，
       拿它跟枚举比恒为 False。

    所以统一取 ``.value``（枚举）或原值（字符串），再比较。
    """
    state = getattr(info, "state", None)
    if state is None:
        return ""
    return str(getattr(state, "value", state)).strip().lower()


def _addon_installed(info: Any) -> bool:
    """是否已安装。兼容枚举与原始字符串两种形态。"""
    return _addon_state(info) not in ("", "not_installed", "unknown")


def _addon_running(info: Any) -> bool:
    """是否正在运行。``running``（枚举）与 ``started``（API 原始串）都认。"""
    return _addon_state(info) in ("running", "started")


async def async_get_addon_state(hass: HomeAssistant) -> str:
    """Query the app's current state ("running"/"not_running"/…); "" on error.

    给 coordinator 用：addon 模式下 hs-frpc 跑在 app 容器的网络命名空间里，
    集成本机访问不到它的 127.0.0.1:7401，"数据面是否活着"只能用
    Supervisor 的 app 状态近似。
    """
    try:
        addon_manager = get_addon_manager(hass, name="HassStore Tunnel")
        info = await addon_manager.async_get_addon_info()
    except Exception as err:  # noqa: BLE001 - 探测失败按"未知"处理，不能掀翻刷新
        _LOGGER.debug("查询 app 状态失败：%s", err)
        return ""
    return _addon_state(info)


def get_addon_manager(hass: HomeAssistant, *, name: str) -> Any:
    """Return an :class:`AddonManager` for our app (same pattern as Z-Wave JS).

    官方先例：``homeassistant/components/zwave_js/addon.py``
    （``AddonManager(hass, LOGGER, "Z-Wave JS", ADDON_SLUG)``）。
    """
    addon_manager_cls, _, _ = _import_hassio()
    return addon_manager_cls(hass, _LOGGER, name, APP_SLUG)


async def async_ensure_repository(hass: HomeAssistant) -> bool:
    """Add our app repository; idempotent. Returns True if it was newly added.

    ``AddonManager`` **没有**封装 add_repository（02a §B.1.3 明确点名），
    所以这里直接用 ``get_supervisor_client(hass).store.add_repository(...)``。

    Core 的 ``SUPERVISOR_TOKEN`` 在 Supervisor 的鉴权中间件里走 "Home Assistant 分支"，
    匹配后直接 ``return await handler(request)``，**跳过 role_access 正则检查**
    （02a §0 事实 3 / §B.1.2），所以集成能调 ``/store/*`` 这类只对 manager/admin 开放的路由。
    """
    _, _, get_supervisor_client = _import_hassio()
    try:
        from aiohasupervisor.models import StoreAddRepository
    except ImportError as err:  # pragma: no cover
        raise HomeAssistantError(
            "aiohasupervisor 不可用（该包由 hassio 集成提供；非 HAOS 环境无法代装 app）"
        ) from err

    client = get_supervisor_client(hass)
    try:
        await client.store.add_repository(StoreAddRepository(repository=APP_REPOSITORY_URL))
    except Exception as err:  # noqa: BLE001 - 需要按异常类型名做幂等判定
        if _is_already_added(err):
            _LOGGER.debug("app 仓库已存在，跳过：%s", APP_REPOSITORY_URL)
            return False
        raise HomeAssistantError(
            f"添加 app 仓库失败（{APP_REPOSITORY_URL}）：{err}。"
            "请检查 HA 主机能否访问 github.com，或手动在 设置 → 应用 → 仓库 中添加。"
        ) from err
    _LOGGER.info("已添加 app 仓库：%s", APP_REPOSITORY_URL)
    return True


def _is_already_added(err: Exception) -> bool:
    """Detect ``StoreRepositoryAlreadyAddedError`` without importing it eagerly.

    Supervisor 对重复添加返回 ``StoreRepositoryAlreadyAddedError``；
    ``aiohasupervisor`` 会把 JSON 的 ``error_key`` 映射成同名异常类
    （02a §A.5 / §B.1.3）。用类名匹配，避免因版本差异导致 import 失败。
    """
    return type(err).__name__ == "StoreRepositoryAlreadyAddedError"


async def async_assert_addon_installable(hass: HomeAssistant) -> None:
    """Raise a readable error when the app cannot be installed on this machine.

    ``AddonManager`` 没有封装 availability 检查，所以直接用
    ``get_supervisor_client(hass).store.addon_availability(slug)``
    （``GET /store/addons/<slug>/availability``）：**200 = 可安装，4xx = 不可安装并给原因**
    （02a §B.1.4 端点表 / §B.1.3 路线 2）。
    """
    _, _, get_supervisor_client = _import_hassio()
    client = get_supervisor_client(hass)
    try:
        await client.store.addon_availability(APP_SLUG)
    except Exception as err:  # noqa: BLE001 - 4xx 会变成 aiohasupervisor 的异常
        raise HomeAssistantError(
            f"本机无法安装 HassStore Tunnel app（{err}）。"
            "常见原因：CPU 架构不在 amd64/aarch64 内、HA 版本低于 app 要求、"
            "或仓库尚未拉取完成。可改用「在本集成内运行」模式绕开 app。"
        ) from err


async def async_install_and_configure(
    hass: HomeAssistant,
    *,
    addon_options: dict[str, Any],
) -> str:
    """Full install/configure/start sequence. Returns the app's final state.

    幂等：已安装则跳过 install；每次都重写 options（换绑就是在改 ``bind_code``）。

    关于 ``auto_update_app``：本函数**不**在每次 setup 时调 ``async_update_addon``，
    否则用户每次重启 HA 都可能被换版本。选项 ``auto_update_app`` 的语义是
    "允许 Supervisor 的自动更新"（``POST /addons/<slug>/options`` 里的
    ``auto_update`` 字段才是权威开关，用户在 app 的 Info 页也能看到）。
    """
    addon_manager = get_addon_manager(hass, name="HassStore Tunnel")

    # 1) 仓库（幂等）
    await async_ensure_repository(hass)

    # 2) 可安装性：架构不匹配/版本不满足会拿到 4xx，给出可读原因
    await async_assert_addon_installable(hass)

    # 3) 安装（已安装时 addon_info 能拿到，直接跳过）
    info = await addon_manager.async_get_addon_info()
    if not _addon_installed(info):
        _LOGGER.info("开始安装 app：%s", APP_SLUG)
        await addon_manager.async_install_addon()
        info = await addon_manager.async_get_addon_info()
        if not _addon_installed(info):  # pragma: no cover - 理论上不会走到
            raise HomeAssistantError("app 安装后仍未处于 installed 状态，请查看 Supervisor 日志")

    # 4) 写 options（只提交本集成负责的键，保留 Supervisor 里的其它设置）
    current_options = _as_dict(getattr(info, "options", None)) or {}
    merged = _merge_options(info, addon_options)
    # ⚠️ 用"与现状比较"判断配置是否真的变了。
    # 曾经的 `if merged:` 恒为真（_merge_options 返回"现有 options + 我们的键"），
    # 一旦下面的重启条件修好，就会**每次 setup（每次 HA 启动/reload）都重启 app**，
    # 造成隧道秒级中断。HA 自己的 async_configure_addon 也是这么比的。
    options_changed = bool(merged) and merged != current_options
    if options_changed:
        _LOGGER.debug("写入 app options：%s", sorted(merged))
        await addon_manager.async_set_addon_options(merged)

    # 5) 启动 / 重启
    # ⚠️ options 有变化且 app 已在运行时**必须重启**：app 内的 run.sh 只在启动时
    # 读一次 /data/options.json。曾经的 bug 是"只写 options 不重启"→ 换绑
    # （改 bind_code/server_url）对正在运行的 app 完全无效，而 reauth 走的正是这条路。
    if _addon_running(info):
        if options_changed:
            _LOGGER.info("app options 已更新，重启 app 使其生效：%s", APP_SLUG)
            await addon_manager.async_restart_addon()
        # 已在运行且配置无变化：什么都不做
    else:
        _LOGGER.info("启动 app：%s", APP_SLUG)
        await addon_manager.async_start_addon()

    final = await addon_manager.async_get_addon_info()
    return _addon_state(final) or "unknown"


async def async_stop_addon(hass: HomeAssistant) -> None:
    """停掉 app（卸载集成时调用；幂等，未安装/已停止时静默）。"""
    try:
        addon_manager = get_addon_manager(hass, name="HassStore Tunnel")
        info = await addon_manager.async_get_addon_info()
    except Exception as err:  # noqa: BLE001 - 拿不到 manager 就当作"没有 app 要停"
        _LOGGER.debug("读取 app 信息失败（忽略）：%s", err)
        return
    # 用 state 判"是否安装"与"是否在跑"：AddonInfo 没有 installed 字段（见 _addon_state）
    if not _addon_installed(info) or not _addon_running(info):
        return
    _LOGGER.info("停止 app：%s", APP_SLUG)
    await addon_manager.async_stop_addon()


def _merge_options(info: Any, addon_options: dict[str, Any]) -> dict[str, Any]:
    """Merge our desired options into the app's current options.

    ``GET /addons/<slug>/info`` 的 ``options`` 字段对 **Core** 调用者是完整返回的
    （只有非特权 app 调用别人才会被脱敏，02a §B.1.4），所以这里能安全做增量合并，
    不会把用户在 app 配置页手填的其它项冲掉。
    """
    current = _as_dict(getattr(info, "options", None)) or {}
    merged = {key: value for key, value in current.items() if key not in ADDON_OPTION_KEYS}
    merged.update({key: value for key, value in addon_options.items() if value is not None})
    return merged


def build_addon_options(
    *,
    device_token: str,
    server_url: str,
    local_target: str,
    protocol: str,
    log_level: str,
) -> dict[str, Any]:
    """Shape our values exactly like ``ha/apps/tunnel/config.yaml`` expects.

    ``device_token`` 由集成直接下发：绑定码是一次性的，config_flow 按设计
    不持久化它（绑定成功即从 data 弹出），旧代码只下发 bind_code 意味着
    app 永远拿不到令牌而 fatal 退出。
    """
    return {
        "bind_code": "",  # 令牌已下发，留空防止误用一次性码
        "device_token": device_token,
        "server_url": server_url,
        "local_target": local_target,
        "protocol": protocol,
        "log_level": log_level,
    }


def _as_dict(value: Any) -> dict[str, Any] | None:
    """Normalise aiohasupervisor model objects to plain dicts."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    for attr in ("to_dict", "as_dict", "dict"):
        method = getattr(value, attr, None)
        if callable(method):
            try:
                result = method()
            except Exception:  # noqa: BLE001 - pydantic 的 .dict 在新版本会废弃
                continue
            if isinstance(result, dict):
                return result
    if hasattr(value, "__dict__"):
        return {k: v for k, v in vars(value).items() if not k.startswith("_")}
    return None
