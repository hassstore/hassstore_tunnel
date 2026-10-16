"""HassStore Tunnel —— HA 自定义集成（安装器 + 控制面 + Container 兜底数据面）。

架构（``docs/design/02-tunnel-service.md`` §9.3、§9.5；``02a`` §B.2.3、§C.2）::

    有 Supervisor（HAOS）          集成 = 安装器：加仓库 → 装 app → 写 options → 启动
                                  数据面 = app 容器里的 hs-frpc（独立生命周期 + watchdog）
    无 Supervisor（Container/Core）集成 = 数据面：下载/校验 hs-frpc → 托管子进程
    有 Supervisor 但用户想内置运行  同"无 Supervisor"，只是回源走 127.0.0.1:<HA端口>

三条铁律：
  * ``async_unload_entry`` **必须** kill 子进程（否则重载集成会留下孤儿进程继续占隧道）。
  * 事件循环里**不做**阻塞 IO（下载/哈希/chmod 全走 ``hass.async_add_executor_job``）。
  * ``manifest.json`` **不能**把 ``hassio`` 放进 ``dependencies``（Container 上会让整个
    集成 setup 失败）；只能放 ``after_dependencies`` + 运行时探测（02a §B.2.2）。
"""

from __future__ import annotations

import logging
import os
import platform
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_network
from pathlib import Path
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import issue_registry as ir

from .api import HassStoreAuthError, HassStoreClient, HassStoreCommError, HassStoreError
from .const import (
    APP_LOCAL_HOST,
    BINARY_NAME,
    CONFIG_CACHE_FILE_NAME,
    CONF_ACCEPT_TERMS,  # noqa: F401 - 协议同意键名，记录在此便于检索（由 config_flow 写入）
    CONF_AUTO_UPDATE_APP,  # noqa: F401 - 同上：由 config_flow 写入 options，集成侧只读不判
    CONF_BIND_CODE,
    CONF_BINARY_MIRROR,
    CONF_BINARY_SHA256,
    CONF_DEVICE_ID,
    CONF_DEVICE_TOKEN,
    CONF_LOCAL_CLIENT,
    CONF_LOCAL_TARGET,
    CONF_LOG_LEVEL,
    CONF_PROTOCOL,
    CONF_SERVER_URL,
    DEFAULT_BINARY_MIRROR,
    DEFAULT_HA_PORT,
    DEFAULT_HEALTH_ADDR,
    DEFAULT_LOG_LEVEL,
    DEFAULT_PROTOCOL,
    DOMAIN,
    LOCAL_HOST,
    MODE_ADDON,
    MODE_LOCAL,
    NAME,
    TERMS_URL,
    ha_version,
)
from .coordinator import HassStoreTunnelCoordinator
from .ha_http import async_ha_http_port, async_use_x_forwarded_for
from .local_process import BinaryIntegrityError, TunnelProcess, async_prepare_binary
from .supervisor import (
    async_get_addon_state,
    async_install_and_configure,
    async_supervisor_available,
    build_addon_options,
)

_LOGGER = logging.getLogger(__name__)


PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR]

# 修复中心（Repairs）用的问题 ID（02a §B.2.3：用 async_create_issue 给用户可操作提示）。
ISSUE_BINARY_INTEGRITY = "binary_integrity"
# trusted_proxies 缺失表现为"登录后无限跳转"（forwarded.py 直接 400），
# 属于"不配就 100% 失败"的硬门槛——持久通知之外必须有 Repairs issue。
ISSUE_TRUSTED_PROXIES = "trusted_proxies"


@dataclass
class HassStoreTunnelRuntimeData:
    """Everything ``async_setup_entry`` produced, kept on ``entry.runtime_data``.

    这里**故意**只用普通 dataclass + ``entry.runtime_data``，不用
    ``type X = ConfigEntry[Y]``（PEP 695 泛型别名）。原因：那个泛型下标支持较新，
    而本集成要在较宽的 HA 版本区间上 import 成功 —— 少一个版本敏感的语法，
    就少一类"装完重启直接 ImportError"的线上事故。
    """
    mode: str
    coordinator: HassStoreTunnelCoordinator | None
    client: HassStoreClient
    process: TunnelProcess | None = None
    addon_state: str | None = None


# ---------------------------------------------------------------------------
# setup / unload
# ---------------------------------------------------------------------------
async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up HassStore Tunnel from a config entry."""
    _migrate_legacy_token(hass, entry)
    server_url: str = entry.data[CONF_SERVER_URL]
    # 令牌只在 options（兼容旧 entry 的 data 回落，见 _migrate_legacy_token）
    token: str | None = entry.options.get(CONF_DEVICE_TOKEN) or entry.data.get(CONF_DEVICE_TOKEN)
    client = HassStoreClient(hass, server_url, token)

    # 1) 环境探测（02a §B.2.3）：有 Supervisor 且用户没选"内置运行" → app 数据面
    has_supervisor = await async_supervisor_available(hass)
    prefer_local: bool = bool(entry.options.get(CONF_LOCAL_CLIENT, False))
    mode = MODE_LOCAL if (not has_supervisor or prefer_local) else MODE_ADDON
    # 双保险探测（02a §B.2.3）：先看 hassio config entry，再看环境变量。
    # 只看环境变量是不够的 —— 变量存在但 hassio 集成 setup 失败（缺 token）时，
    # get_supervisor_client() 仍会 KeyError。
    _LOGGER.debug(
        "环境探测：SUPERVISOR=%s, hassio entry=%s, 用户选择内置运行=%s → mode=%s",
        bool(os.environ.get("SUPERVISOR")),
        has_supervisor,
        prefer_local,
        mode,
    )

    # 2) 没有令牌时先绑定（bind_code 只在全新安装/换绑时存在）
    token = await _async_ensure_device_token(hass, entry, client, token, mode=mode)

    # ⚠️ 先把 runtime_data 占位挂到 entry 上，再启动数据面。
    # 曾经的 bug：数据面启动失败（ConfigEntryNotReady）时 runtime_data 从未赋值，
    # 而 TunnelProcess 已经创建 → 子进程与 supervisor task 泄漏，
    # 且 async_unload_entry 拿不到它、无法收敛。
    entry.runtime_data = HassStoreTunnelRuntimeData(
        mode=mode,
        coordinator=None,  # 占位：下面真正构造后覆盖
        client=client,
        process=None,
        addon_state=None,
    )
    # ⚠️ 但"占位挂上"是**不够的**：HA 官方行为是 setup 抛 ConfigEntryNotReady 时
    # 只调用 _async_process_on_unload（跑 entry.async_on_unload 回调），
    # **从不调用 async_unload_entry**。所以必须在创建进程后立刻注册收敛回调，
    # 否则 coordinator.async_config_entry_first_refresh() 一旦失败（控制面不可达/
    # 401 是很常见的），就会留下一个孤儿 hs-frpc；而 setup 会按 5s…10min 退避重试，
    # 每次重试再建一个 TunnelProcess —— 同一个 device token 会有多个进程抢同一条隧道。
    entry.async_on_unload(_make_process_reaper(hass, entry))

    # 3) 按模式启动数据面
    process: TunnelProcess | None = None
    addon_state: str | None = None
    if mode == MODE_ADDON:
        addon_state = await _async_start_addon_side(hass, entry, client, token)
    else:
        try:
            process = await _async_start_local_side(hass, entry, token, client)
        except Exception:
            # 启动中途失败：此时可能已经 spawn 了子进程，交给注册的回收回调处理，
            # 然后原样抛出（HA 会转成 SETUP_RETRY）。
            await _reap_local_process_async(entry)
            raise
        entry.runtime_data.process = process

    # 4) coordinator（两条路径共用）
    coordinator = HassStoreTunnelCoordinator(
        hass,
        entry,
        client,
        device_token=token,
        # addon 模式下 hs-frpc 跑在 app 容器 netns，本机 127.0.0.1:7401 访问不到
        # （曾经因此 tunnel_online 恒 off、client_version 恒 unknown）；
        # 改用 Supervisor 的 app state 近似数据面健康。
        health_addr=(None if mode == MODE_ADDON else DEFAULT_HEALTH_ADDR),
        process_health_cb=(process.state_snapshot if process is not None else None),
        action_cb=(_make_action_handler(process) if process is not None else None),
        addon_state_cb=(
            (lambda: async_get_addon_state(hass)) if mode == MODE_ADDON else None
        ),
    )
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = HassStoreTunnelRuntimeData(
        mode=mode,
        coordinator=coordinator,
        client=client,
        process=process,
        addon_state=addon_state,
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _async_shutdown(entry))
    )
    _async_notify_setup_result(hass, mode, process, addon_state)
    await _async_check_trusted_proxies(hass, mode)
    _LOGGER.info(
        "%s 已就绪（mode=%s，数据面=%s）",
        NAME,
        mode,
        "app/hassstore_tunnel" if mode == MODE_ADDON else BINARY_NAME,
    )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry — **must** reap the child process (02a §B.3.3 要点 2).

    ⚠️ 顺序很重要（曾经的 bug）：先把运行时资产收敛掉，**再**判断平台卸载是否成功。
    原实现先 `await async_unload_platforms(...)`，平台卸载返回 False 时直接 return，
    下面的 `process.async_stop()` 被完全跳过 —— "铁律"在最需要它的路径上不成立。
    """
    runtime: HassStoreTunnelRuntimeData | None = getattr(entry, "runtime_data", None)

    async def _reap() -> None:
        if runtime is None:
            return
        if runtime.process is not None:
            # 幂等：reload 之后如果这里没收敛，孤儿 hs-frpc 会继续占着隧道，
            # 用户看到的现象是"集成删了隧道还在"。
            await runtime.process.async_stop()
        # ⚠️ **不在这里停 app**：unload 会被 reload 复用
        # （_async_options_updated → async_reload → unload → setup）。
        # 停 app 会让"改一次选项"变成一次容器停/启（隧道秒级中断），
        # 且若随后的 setup 失败，app 会一直停在 stopped 直到重试成功。
        # app 的回收放在 async_remove_entry（真正移除集成时）。

    await _reap()
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        # 兜底：平台卸载失败也要再杀一次，绝不留下孤儿进程。
        await _reap()
    return unload_ok


async def _reap_local_process_async(entry: ConfigEntry) -> None:
    """收敛 entry 上挂着的 TunnelProcess（幂等；没有则什么也不做）。

    为什么不用 async_unload_entry 兜底：HA 在 setup 失败（ConfigEntryNotReady）
    或 setup 首次抛错时**不会**调用 async_unload_entry，只会跑 async_on_unload
    注册的回调。所以回收必须走 async_on_unload。
    """
    runtime: HassStoreTunnelRuntimeData | None = getattr(entry, "runtime_data", None)
    if runtime is None or runtime.process is None:
        return
    process = runtime.process
    runtime.process = None
    try:
        await process.async_stop()
    except Exception as err:  # noqa: BLE001 - 回收失败不应掩盖原始错误
        _LOGGER.warning("收敛 hs-frpc 子进程失败：%s", err)


def _make_process_reaper(hass: HomeAssistant, entry: ConfigEntry) -> Any:
    """构造 ``async_on_unload`` 回调（签名 Callable[[], None]）。

    用闭包捕获 hass/entry 而不是全局状态：回调与 entry 同生命周期，
    entry 卸载后回调即被丢弃，不存在跨 entry 串扰。
    """

    @callback
    def _reap() -> None:
        hass.async_create_task(_reap_local_process_async(entry))

    return _reap


@callback
def _migrate_legacy_token(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """一次性迁移：把老 entry 里存在 ``data`` 的令牌搬到 ``options`` 并删掉。

    为什么值得做：``data`` 会进 ``/config/.storage/core.config_entries``，
    而该文件出现在诊断包、备份快照与 reauth flow 上下文里；设计 §9.2 明确
    「设备令牌存 /data，不写 /config」。新 entry 已只写 options，但**存量用户**
    若不迁移就永远不会被清理（这是"只改写入端"解决不了的部分）。

    幂等：data 里没有令牌时直接返回。失败只记日志，绝不阻断 setup。
    """
    if CONF_DEVICE_TOKEN not in entry.data:
        return
    legacy = entry.data.get(CONF_DEVICE_TOKEN)
    new_data = {k: v for k, v in entry.data.items() if k != CONF_DEVICE_TOKEN}
    new_options = dict(entry.options)
    if legacy and not new_options.get(CONF_DEVICE_TOKEN):
        new_options[CONF_DEVICE_TOKEN] = legacy
    try:
        hass.config_entries.async_update_entry(entry, data=new_data, options=new_options)
        _LOGGER.info("已把设备令牌从 config entry 的 data 迁移到 options（避免进诊断/备份快照）")
    except Exception as err:  # noqa: BLE001 - 迁移失败不该阻断启动
        _LOGGER.warning("令牌迁移失败（将继续按 data 回落读取）：%s", err)


async def _async_stop_addon_best_effort(hass: HomeAssistant) -> None:
    """app 模式下卸载集成时停掉 app 容器（失败只记日志，不阻断卸载）。"""
    try:
        from .supervisor import async_stop_addon

        await async_stop_addon(hass)
    except Exception as err:  # noqa: BLE001 - 卸载路径不能被这一步卡死
        _LOGGER.debug("停 app 失败（忽略，用户可在 Supervisor 里手动停）：%s", err)


@callback
def _async_notify_setup_result(
    hass: HomeAssistant,
    mode: str,
    process: TunnelProcess | None,
    addon_state: str | None,
) -> None:
    """setup 成功后发一条持久通知：告知面板位置 + `trusted_proxies` 这个硬门槛。

    `persistent_notification` 早已在 manifest 的 `after_dependencies` 里，但代码从未
    使用过（明显半成品）。`trusted_proxies` 是整个交付物里**唯一一个不配就 100% 失败**
    的硬门槛（不配的表现是"登录后无限跳转回登录页"），必须主动告知而不是让用户读文档。
    """
    if mode == MODE_ADDON:
        where = "侧边栏已出现「内网穿透」面板（ingress）"
        # addon_state 让用户一眼看到容器是否真的在跑（stopped 时面板也是空的）
        extra = f"\n\napp 状态：{addon_state}" if addon_state else ""
    else:
        where = "实体 sensor.tunnel_* / binary_sensor.tunnel_online"
        tail: Any = {}
        if process is not None:
            try:
                tail = process.state_snapshot()
            except Exception:  # noqa: BLE001 - 通知不能因取状态失败而崩
                tail = {}
        if isinstance(tail, dict) and tail.get("last_error"):
            extra = f"\n\n当前状态：{tail['last_error']}"
        else:
            extra = ""
    try:
        # 用 `persistent_notification.async_create`（@callback，同步、无任务编排），
        # 而不是 `hass.services.async_call(..., blocking=False)`：
        # 后者的返回值随 blocking 取值而变（协程 / Task / None），再包一层
        # `async_create_task` 很容易在 Task/None 上 TypeError。helper 是 HA 官方
        # 给集成用的入口，签名确定为 (hass, message, title=None, notification_id=None)。
        from homeassistant.components import persistent_notification

        persistent_notification.async_create(
            hass,
            (
                "隧道客户端已启动。\n\n"
                f"**在哪里看状态**：{where}\n\n"
                "**⚠️ 还需做一步（否则会「登录后无限跳转」）**："
                "在 `/config/configuration.yaml` 的 `http:` 下补全 "
                "`use_x_forwarded_for: true` 与 `trusted_proxies`"
                "（app 模式必须包含 `172.30.32.0/23`——app 容器走 bridge 网关回源；"
                "另加 `127.0.0.1`、`::1`），然后重启 Home Assistant。\n\n"
                f"详细说明见 app/集成的 Documentation 页。{extra}"
            ),
            title="HassStore 内网穿透已就绪",
            notification_id=f"{DOMAIN}_setup",
        )
    except Exception as err:  # noqa: BLE001 - 通知失败绝不影响隧道
        _LOGGER.debug("发送 setup 通知失败（忽略）：%s", err)


# ---------------------------------------------------------------------------
# trusted_proxies 检测（Repairs）
# ---------------------------------------------------------------------------
# 集成模式下 hs-frpc 从本机回环回源；app 模式下 hs-frpc 在 app 容器 netns
# 里，回源经 bridge 网关 172.30.32.0/23。两者都是 HA 视角的"代理来源"，
# 必须都在 http.trusted_proxies 里，否则 forwarded.py 会对每个带
# X-Forwarded-For 的请求直接 400 —— 现象即"登录后无限跳转回登录页"。
_LOCAL_REQUIRED_PROXIES: tuple[str, ...] = ("127.0.0.1", "::1")
_ADDON_REQUIRED_PROXIES: tuple[str, ...] = ("172.30.32.0/23",)


def _proxy_covers(proxies: list, needed_net) -> bool:
    """``needed_net`` 是否被 trusted_proxies 里某一项覆盖（真子网或相等）。"""
    for raw in proxies:
        try:
            net = ip_network(raw)
        except (TypeError, ValueError):
            continue
        if net.version != needed_net.version:
            continue  # subnet_of 对 v4/v6 混用直接 TypeError
        if needed_net == net or needed_net.subnet_of(net):
            return True
        # HA 某些版本把 "127.0.0.1" 存成纯 IP（不是 /32）：
        # ip_network 会归一成 /32，上面的比较已覆盖。
    return False


def _trusted_proxies_missing(
    proxies: list | None,
    mode: str,
    *,
    xff: bool | None,
) -> list[str]:
    """计算当前生效 HTTP 配置里**缺**的项（人话列表，供翻译占位 {missing}）。

    返回 ``[]`` 表示齐全。``proxies`` 传 ``None`` 视为空列表（全缺）——
    调用方已经确认 server 存在但拿不到列表时使用。
    """
    missing: list[str] = []
    if xff is False:
        missing.append("use_x_forwarded_for: true")
    needed = _ADDON_REQUIRED_PROXIES if mode == MODE_ADDON else _LOCAL_REQUIRED_PROXIES
    for cidr in needed:
        # 宿主机地址按 /32（v6 /128）比较；app 段按本身 /23。
        net = ip_network(cidr if "/" in cidr else f"{cidr}/{'128' if ':' in cidr else '32'}")
        if not _proxy_covers(proxies or [], net):
            missing.append(f"trusted_proxies: {cidr}")
    return missing





async def _async_check_trusted_proxies(hass: HomeAssistant, mode: str) -> None:
    """探测生效中的 HTTP 代理配置；缺项建 Repairs issue，齐了清理 issue。

    * ``hass.http`` 只在 http 组件 setup 完成后才有（recovery mode / setup 极早期
      可能没有）→ 探测不到就跳过本次，**不删也不建** issue；
    * ``hass.http.trusted_proxies`` 是**运行态**列表（list[IPv4Network|IPv6Network]），
      比读 .storage 更贴近"现在生效的值"；
    * 修复后需要重启 HA 才生效，issue 在下次 setup 时自然被清理（不存在
      "issue 永久赖着"的问题）。
    """
    server = getattr(hass, "http", None)
    if server is None:
        _LOGGER.debug("hass.http 尚未就绪，跳过 trusted_proxies 探测")
        return
    proxies = getattr(server, "trusted_proxies", None)
    if not isinstance(proxies, list):
        _LOGGER.debug("无法读取 hass.http.trusted_proxies，跳过探测")
        return
    missing = _trusted_proxies_missing(
        proxies,
        mode,
        xff=await async_use_x_forwarded_for(hass),
    )
    if missing:
        ir.async_create_issue(
            hass,
            DOMAIN,
            ISSUE_TRUSTED_PROXIES,
            is_fixable=False,
            severity=ir.IssueSeverity.ERROR,
            translation_key=ISSUE_TRUSTED_PROXIES,
            translation_placeholders={"missing": "、".join(missing)},
            learn_more_url=TERMS_URL,
        )
        _LOGGER.warning("HTTP 代理配置不完整，远程访问会出现登录死循环：缺 %s", missing)
    else:
        ir.async_delete_issue(hass, DOMAIN, ISSUE_TRUSTED_PROXIES)


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """真正移除集成时收尾：清修复项 + 停 app + 收敛子进程。

    这是**唯一**该停 app 的地方：``async_unload_entry`` 会被 reload 复用，
    在那里停 app 会让"改一次选项"变成一次容器停/启（见其注释）。
    """
    ir.async_delete_issue(hass, DOMAIN, ISSUE_BINARY_INTEGRITY)
    ir.async_delete_issue(hass, DOMAIN, ISSUE_TRUSTED_PROXIES)
    runtime: HassStoreTunnelRuntimeData | None = getattr(entry, "runtime_data", None)
    # 子进程（local 模式）：unload 正常时会话已收敛，这里再兜一次幂等。
    if runtime is not None and runtime.process is not None:
        await _reap_local_process_async(entry)
    # app（addon 模式）：与 DOCS/README 的"移除集成=回收"承诺对齐。
    await _async_stop_addon_best_effort(hass)


@callback
def _async_shutdown(entry: ConfigEntry) -> Any:
    """Return a HA-stop listener that reaps the child process."""

    async def _handle(event: Event) -> None:
        runtime: HassStoreTunnelRuntimeData | None = getattr(entry, "runtime_data", None)
        if runtime is not None and runtime.process is not None:
            await runtime.process.async_stop()

    return _handle


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload on options change (local_target / protocol / log_level …)."""
    await hass.config_entries.async_reload(entry.entry_id)


# ---------------------------------------------------------------------------
# 令牌
# ---------------------------------------------------------------------------
async def _async_ensure_device_token(
    hass: HomeAssistant,
    entry: ConfigEntry,
    client: HassStoreClient,
    token: str | None,
    *,
    mode: str,
) -> str | None:
    """Bind if we have a ``bind_code``; persist the resulting token in options.

    令牌只写 ``entry.options``（历史上也写过 ``data``，但 data 会进
    ``/config/.storage/core.config_entries`` 的诊断/备份快照，与设计 §9.2
    "令牌存 /data，不写 /config" 相悖）。为了兼容旧 entry，读取时仍回看 data。

    ``options`` 会随 config entry 一起存储，并且 **不会** 因为
    ``async_update_entry`` 触发 reload（reload 只由 ``add_update_listener``
    在**用户**改 options 时触发）。
    """
    bind_code: str = entry.data.get(CONF_BIND_CODE, "")
    if not bind_code or token:
        if not token:
            _LOGGER.warning("既没有设备令牌也没有绑定码；隧道无法建立，请在集成里重新配置")
        return token

    # 绑定即登记真实回源端口：HA 2026.x 起 Supervisor 下 Core 默认是 80 而非
    # 8123，若等心跳自愈，节点插件会在首个心跳周期（默认 60s）先拒一次接入。
    bind_host = APP_LOCAL_HOST if mode == MODE_ADDON else LOCAL_HOST
    bind_port = await async_ha_http_port(hass)
    try:
        result = await client.async_bind(
            bind_code,
            hostname=platform.node() or "homeassistant",
            ha_version=ha_version(),
            arch=platform.machine(),
            local_target=f"http://{bind_host}:{bind_port}",
        )
    except HassStoreAuthError as err:  # pragma: no cover - bind 用 bind_code 不用 token
        raise ConfigEntryAuthFailed(str(err)) from err
    except HassStoreCommError as err:
        raise ConfigEntryNotReady(f"无法连接 HassStore（{client.server_url}）：{err}") from err
    except HassStoreError as err:
        raise ConfigEntryAuthFailed(f"绑定失败：{err}") from err

    new_token: str = result[CONF_DEVICE_TOKEN]
    client.set_token(new_token)
    new_options = dict(entry.options)
    new_options[CONF_DEVICE_TOKEN] = new_token
    if device_id := result.get(CONF_DEVICE_ID):
        new_options[CONF_DEVICE_ID] = device_id
    # 绑定码是一次性的：清掉它，避免每次 HA 重启都拿已作废的码去换令牌。
    new_data = dict(entry.data)
    new_data.pop(CONF_BIND_CODE, None)
    # 旧版本可能把令牌写进过 data：一并清掉，避免诊断快照里留明文。
    new_data.pop(CONF_DEVICE_TOKEN, None)
    hass.config_entries.async_update_entry(entry, data=new_data, options=new_options)
    _LOGGER.info("设备令牌绑定成功（device_id=%s）", new_options.get(CONF_DEVICE_ID, "?"))
    return new_token


# ---------------------------------------------------------------------------
# 数据面 A：HAOS app（集成 = 安装器）
# ---------------------------------------------------------------------------
async def _async_start_addon_side(
    hass: HomeAssistant,
    entry: ConfigEntry,
    client: HassStoreClient,
    token: str | None,
) -> str:
    """Add repository → availability → install → options → start (02a §B.1.3)."""
    if not token:
        raise ConfigEntryNotReady("尚未完成设备绑定，无法配置 app")

    addon_options = build_addon_options(
        # 令牌由集成直接下发：bind_code 一次性、不持久化（绑定成功即从 data 弹出），
        # 传它意味着 app 永远拿不到令牌而 fatal。
        device_token=token,
        server_url=entry.data[CONF_SERVER_URL],
        # app 是 bridge 网络 → 用容器 DNS 名回源（02a §A.2）。
        # 端口必须探测：HA 2026.x 起 Supervisor 下 Core 默认是 80 不是 8123
        # （SUPERVISOR_DEFAULT_PORT），写死 8123 会让新版 HAOS 连错端口。
        local_target=f"http://{APP_LOCAL_HOST}:{await async_ha_http_port(hass)}",
        protocol=entry.options.get(CONF_PROTOCOL, DEFAULT_PROTOCOL),
        log_level=entry.options.get(CONF_LOG_LEVEL, DEFAULT_LOG_LEVEL),
    )
    try:
        state = await async_install_and_configure(hass, addon_options=addon_options)
    except Exception as err:  # noqa: BLE001 - 统一转成 ConfigEntryNotReady，交给 HA 重试
        raise ConfigEntryNotReady(
            f"安装/启动 HassStore Tunnel app 失败：{err}。"
            "可在集成选项中改为「在集成内运行」（无需 Supervisor 的 app 能力）。"
        ) from err
    _LOGGER.info("app 状态：%s", state)
    return state


# ---------------------------------------------------------------------------
# 数据面 B：Container/Core（集成 = 数据面）
# ---------------------------------------------------------------------------
# 站点只接受"回环 / homeassistant"这两类主机的回源（见后端
# normalizeLocalTargetRules），所以本地目标必然是下面这个规范形态之一。
_CANONICAL_TARGET_HOSTS: frozenset[str] = frozenset(
    {LOCAL_HOST, "localhost", APP_LOCAL_HOST, "home-assistant"}
)
# 旧版本集成**写死**过这个端口的默认值并存进 options；把它当作"自动"，
# 存量用户才能在 HA 端口迁移（8123→80）后自愈，而不是连向已不监听的端口。
_LEGACY_TARGET_PORTS: frozenset[int] = frozenset({DEFAULT_HA_PORT})


def _target_port(value: str) -> int | None:
    """解析 ``http://<回环|localhost|homeassistant>:<端口>`` 的端口。

    非规范形态（其它主机、非 http、缺端口、非法端口）返回 ``None`` ——
    调用方据此把它当"用户显式指定的非常规目标"原样保留。
    """
    v = value.strip().rstrip("/").lower()
    if not v.startswith("http://"):
        return None
    host, sep, port = v.removeprefix("http://").rpartition(":")
    if not sep or host not in _CANONICAL_TARGET_HOSTS or not port.isdigit():
        return None
    parsed = int(port)
    return parsed if 0 < parsed < 65536 else None


async def _async_effective_local_target(hass: HomeAssistant, entry: ConfigEntry) -> str:
    """Return the local (in-integration) mode origin URL.

    "自动"判定（→ ``http://127.0.0.1:<探测到的端口>``）：
      * 留空；或
      * 规范形态且端口**等于当前探测到的端口**（选项页预填值保存后的回显）；或
      * 规范形态且端口是旧版写死的默认端口（存量 entry 的 8123）。

    * 规范形态但端口**不同**（用户想固定到别的端口）→ 保留其端口意图，但
      主机名仍归一为回环：local 模式与 Core 同 netns，`homeassistant` 这个
      主机名在非 Supervisor 环境根本解析不了（只有 hassio_dns 认识它）。

    非规范形态（其它主机 / 非 http）原样返回——那本来就是"用户显式选择"，
    交给站点侧的 host 白名单去拒。
    """
    stored = (entry.options.get(CONF_LOCAL_TARGET) or "").strip()
    port = await async_ha_http_port(hass)
    if not stored:
        return f"http://{LOCAL_HOST}:{port}"
    parsed = _target_port(stored)
    if parsed is None:
        return stored
    if parsed == port or parsed in _LEGACY_TARGET_PORTS:
        parsed = port
    return f"http://{LOCAL_HOST}:{parsed}"


async def _async_start_local_side(
    hass: HomeAssistant,
    entry: ConfigEntry,
    token: str | None,
    client: HassStoreClient,
) -> TunnelProcess:
    """Download+verify ``hs-frpc``, then supervise it as a child process."""
    if not token:
        raise ConfigEntryNotReady(
            "尚未完成设备绑定：请先在集成配置里填入绑定码（HassStore → 内网穿透 → 绑定到 HA）"
        )

    # 双隧道防护：HAOS 上用户切到"内置运行"时，如果 app 还在跑，同一个
    # device token 会有两条隧道互踢（frps 对同一 token 只保一条连接，
    # 表现为隧道来回掉线）。尽力停掉 app——失败不阻断（可能只是没装）。
    if await async_supervisor_available(hass):
        await _async_stop_addon_best_effort(hass)

    # Container/Core 上 /config 是**唯一**持久目录（02 附录 D、02a §B.3.1）。
    dir_path = Path(hass.config.path("hassstore_tunnel"))
    try:
        binary = await async_prepare_binary(
            hass,
            directory=dir_path,
            # ⚠️ sha 在 **options**（config_flow 的 binary 步骤与 OptionsFlow 都写 options），
            # 不是 data。这里若只读 data，用户按新步骤填了 SHA 仍会拿到 "" →
            # BinaryIntegrityError → SETUP_RETRY 无限循环（比改动前更难排查）。
            # 读法与令牌一致：options 优先，data 回落（兼容历史 entry）。
            expected_sha256=entry.options.get(CONF_BINARY_SHA256)
            or entry.data.get(CONF_BINARY_SHA256, ""),
            mirror=entry.options.get(CONF_BINARY_MIRROR, DEFAULT_BINARY_MIRROR),
        )
    except BinaryIntegrityError as err:
        # 修复中心留一条可操作提示（02a §B.2.3 / §B.6）。
        ir.async_create_issue(
            hass,
            DOMAIN,
            ISSUE_BINARY_INTEGRITY,
            is_fixable=False,
            severity=ir.IssueSeverity.ERROR,
            translation_key=ISSUE_BINARY_INTEGRITY,
            translation_placeholders={"error": str(err)},
            learn_more_url=TERMS_URL,
        )
        raise ConfigEntryNotReady(str(err)) from err

    process = TunnelProcess(
        hass,
        binary=binary,
        server_url=client.server_url,
        device_token=token,
        local_target=await _async_effective_local_target(hass, entry),
        protocol=entry.options.get(CONF_PROTOCOL, DEFAULT_PROTOCOL),
        log_level=entry.options.get(CONF_LOG_LEVEL, DEFAULT_LOG_LEVEL),
        config_cache=dir_path / CONFIG_CACHE_FILE_NAME,
        on_state_change=_make_event_reporter(hass, client),
    )
    await process.async_start()
    return process


def _make_action_handler(process: TunnelProcess) -> Any:
    """Map the server's ``action`` (``none`` / ``reload`` / ``stop``) onto the child.

    * ``stop``   → 期望态 = 暂停（到期/超额/被停用，02 §7.6、§9.4 流程图 ``action=stop`` 分支）
    * ``reload`` → 期望态 = 运行（曾经的 bug：这里注释写"reload 不需要宿主做任何事"，
      但若客户端刚被 ``action=stop`` pause 过，续费后就不会自愈，用户必须手动重载集成）
    * 其它值      → 期望态 = 运行（用户续费/兑换后自动恢复，02 §9.4 "离线容忍/热更新"）

    hs-frpc 自己按 ``config_revision`` 热更新代理（``svc.UpdateAllConfigurer``，02 附录 B），
    所以 ``reload`` 不需要我们重启进程——但必须把 pause 状态解除。

    ⚠️ 本回调是**同步**入口：只翻转期望位，真正的 pause/resume 由
    ``TunnelProcess`` 内部的收敛任务串行执行。旧实现每条动作各起一个
    ``create_background_task(pause()/resume())``，两个协程可能交错——
    pause 的 SIGTERM 等待窗口里 resume 先跑完，最终状态与最新指令相反
    （续费后隧道不起来 / 停用后还在重连）。
    """

    def _handle(action: str | None) -> None:
        if action is None:
            return
        process.set_desired_paused(action == "stop")

    return _handle


def _make_event_reporter(hass: HomeAssistant, client: HassStoreClient) -> Any:
    """Build the ``on_state_change`` hook that reports events to ``/tunnel/client/event``.

    事件类型：``proxy_start`` / ``proxy_fail`` / ``tunnel_down``（02 §6.3）。
    这是**诊断通道**，失败静默，绝不影响隧道。
    """

    def _report(event: dict[str, Any]) -> None:
        hass.async_create_background_task(
            client.async_report_event({"at": _utcnow_iso(), **event}),
            name=f"{DOMAIN}-event",
        )

    return _report


def _utcnow_iso() -> str:
    """Return the current UTC time as ISO-8601 (``at`` 字段，02 §6.3）。"""
    return datetime.now(UTC).isoformat()


__all__ = [
    "DOMAIN",
    "ISSUE_BINARY_INTEGRITY",
    "HassStoreTunnelRuntimeData",
    "async_setup_entry",
    "async_unload_entry",
]
