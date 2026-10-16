"""Thin async client for the HassStore HA-client API.

端点契约来自 ``docs/design/02-tunnel-service.md`` §6.3：

============================  ==================================================
``POST /api/v1/tunnel/client/bind``      绑定码 → 长期设备令牌（一次性，10 分钟有效）
``GET  /api/v1/tunnel/client/config``    结构化客户端配置 + ``config_revision``
============================================================================================

心跳与用量上报由 ``hs-frpc`` **自己**直接发给站点（它要据此驱动
``action=stop/reload``），集成不重复发——所以没有 ``async_heartbeat`` /
``async_report_usage`` 方法（曾经的残留死代码）。

鉴权统一为 ``Authorization: Bearer <device_token>``（``bind`` 除外，它用 ``bind_code``）。
所有请求都用 HA 共享的 ``aiohttp`` session（不要自己 new ClientSession —— 那会绕过 HA
的代理/证书配置，并在卸载时泄漏连接池）。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from aiohttp import ClientError, ClientResponse, ClientSession
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    API_BIND,
    API_CONFIG,
    API_EVENT,
    API_RELEASE_MANIFEST,
    CONF_BIND_CODE,
    CONF_DEVICE_TOKEN,
    HS_CLIENT_VERSION,
    REQUEST_TIMEOUT_SECONDS,
)

_LOGGER = logging.getLogger(__name__)


class HassStoreError(Exception):
    """Base error for the HassStore client API."""


class HassStoreAuthError(HassStoreError):
    """401 —— 设备令牌缺失/无效（``internal/service/tunnel_device.go``
    ``AuthenticateDevice`` 对令牌问题只返回 401）。

    调用方应触发 ``async_step_reauth``（02a §B.4.1）。
    **403 不在这里**：客户端 API 走 Bearer、不带 Cookie，后端的 403 只可能来自
    CSRF 中间件或上游 WAF/CDN 拦截——把它当"令牌失效"会让用户无谓地重走授权流程。
    """


class HassStoreBindError(HassStoreError):
    """绑定失败：绑定码错误/过期/已使用、设备数超限等（02 §6.5 业务错误码）。"""


class HassStoreCommError(HassStoreError):
    """网络层或 5xx 错误：站点不可达、超时、服务端故障。"""


class HassStoreClient:
    """Minimal, dependency-free client (standard library + aiohttp only)."""

    def __init__(self, hass: HomeAssistant, server_url: str, token: str | None = None) -> None:
        self._hass = hass
        self._server_url = server_url.rstrip("/")
        self._token = token

    @property
    def server_url(self) -> str:
        """Return the configured site base URL."""
        return self._server_url

    def set_token(self, token: str) -> None:
        """Update the in-memory device token (after bind or reauth)."""
        self._token = token

    def _url(self, path: str) -> str:
        return f"{self._server_url}{path}"

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_data: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Perform one request and translate errors into our exception hierarchy.

        ⚠️ **响应信封**：站点 API 的所有响应都被包在
        ``{"code": "...", "message": "...", "data": {...}}`` 里
        （``internal/httpx/httpx.go`` → ``Resp`` / ``func OK`` / ``func Fail``）。
        所以这里必须**剥掉 ``data``**，否则上层永远拿不到 ``device_token``。
        注意只有 ``data`` 是 object 时才剥；``hs-frpc`` 的本地 ``/healthz``
        **不走这个方法**（它是裸对象，契约见 ha/README.md）。
        """
        session: ClientSession = async_get_clientsession(self._hass)
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
                response: ClientResponse = await session.request(
                    method,
                    self._url(path),
                    json=json_data,
                    headers=self._headers(),
                )
                if response.status == 401:
                    raise HassStoreAuthError(
                        f"{method} {path} → HTTP 401"
                        f"（设备令牌失效或被停用）{await _error_detail(response)}"
                    )
                if response.status == 403:
                    # 服务端 AuthenticateDevice 只发 401；403 的来源是
                    # CSRFGuard（有会话 Cookie 时缺 X-Requested-With）或上游
                    # WAF/CDN/边缘代理拦截——无论哪种都不该按"令牌失效"处理，
                    # 否则会把网络/边缘问题引入 reauth 死循环。
                    raise HassStoreCommError(
                        f"{method} {path} → HTTP 403"
                        f"（被站点网关/防护层拒绝，非令牌问题）{await _error_detail(response)}"
                    )
                if response.status >= 400:
                    raise HassStoreError(
                        f"{method} {path} → HTTP {response.status}{await _error_detail(response)}"
                    )
                return _unwrap(await response.json(content_type=None))
        except HassStoreError:
            raise
        except (TimeoutError, asyncio.TimeoutError) as err:
            raise HassStoreCommError(f"{method} {path} 超时（{REQUEST_TIMEOUT_SECONDS}s）") from err
        except ClientError as err:
            raise HassStoreCommError(f"{method} {path} 网络错误：{err}") from err
        except ValueError as err:  # 非 JSON 响应
            raise HassStoreCommError(f"{method} {path} 返回了非 JSON 响应") from err

    # -- 业务方法 ----------------------------------------------------------
    async def async_bind(
        self,
        bind_code: str,
        *,
        hostname: str,
        ha_version: str,
        arch: str,
        local_target: str | None = None,
    ) -> dict[str, Any]:
        """Exchange a one-time bind code for a long-lived device token (02 §6.3).

        请求体字段（与 app 的 ``run.sh`` 完全一致，方便后台按 client_type 区分灰度）：
        ``bind_code`` / ``hostname`` / ``client_type`` / ``client_version`` /
        ``ha_version`` / ``arch`` / ``local_target``。

        ``local_target`` 是**可选**的客户端实际回源地址：带上它能让站点在绑定
        时就登记正确端口（HA 2026.x 起 Supervisor 下 Core 默认 80，与站点默认
        8123 不一致会让节点插件首次拒绝接入）。旧站点忽略该字段，不影响绑定。
        """
        payload = {
            CONF_BIND_CODE: bind_code,
            "hostname": hostname,
            "client_type": "integration",
            "client_version": HS_CLIENT_VERSION,
            "ha_version": ha_version,
            "arch": arch,
        }
        if local_target:
            payload["local_target"] = local_target
        try:
            data = await self._request("POST", API_BIND, json_data=payload)
        except HassStoreError as err:
            if isinstance(err, HassStoreCommError):
                raise
            raise HassStoreBindError(str(err)) from err
        if not data or not data.get(CONF_DEVICE_TOKEN):
            raise HassStoreBindError("绑定响应缺少 device_token")
        return data

    async def async_get_config(self) -> dict[str, Any]:
        """Fetch the structured client config (``{config_revision, device, line, ...}``)."""
        data = await self._request("GET", API_CONFIG)
        if not data:
            raise HassStoreCommError("config 响应为空")
        return data

    async def async_report_event(self, event: dict[str, Any]) -> None:
        """Best-effort event report (``proxy_start|proxy_fail|tunnel_down``).

        这是**诊断通道**，失败只记 debug，绝不影响隧道本身。
        """
        try:
            await self._request("POST", API_EVENT, json_data=event)
        except HassStoreError as err:
            _LOGGER.debug("上报事件失败（忽略）：%s", err)

    async def async_get_release_manifest(self) -> dict[str, Any]:
        """GET ``{site}/api/v1/tunnel/release/manifest`` — 客户端二进制发布清单。

        **公开端点，不需要令牌**。返回
        ``{version, mirror_base, binaries: {arch: {sha256, size, url}}}``。
        失败时返回 ``{}``（配置流把它当作"没发布"——用户仍可手动填，
        不能因后端没配 TUNNEL_RELEASE_DIR 就把整个 flow 卡死）。
        """
        try:
            return await self._request("GET", API_RELEASE_MANIFEST) or {}
        except HassStoreError:
            return {}


def _unwrap(payload: Any) -> dict[str, Any] | None:
    """Strip the site's ``{code,message,data}`` envelope.

    ``internal/httpx/httpx.go``：``func OK(c, data)`` 返回
    ``{"code":"OK","message":"","data":{...}}``。所以业务字段在 ``data`` 里。
    兼容两种形态：
      * 有 ``code`` 字段 → 认为是被包过的响应，取 ``data``；
      * 没有 ``code`` 字段 → 认为已经是裸对象（例如有人把集成指向了一个
        直接返回业务对象的网关），原样返回，避免过度剥壳把数据剥没。

    ⚠️ 曾经的 bug：条件写成 ``"code" in payload or "message" in payload and "data" in payload``，
    依赖 Python 的 ``and`` 优先于 ``or`` 的隐式顺序；且 ``data`` 非对象时返回 None，
    把 ``{"message":"x","data":"string"}`` 这种合法响应判成"响应为空"。
    这里显式加括号，并把"有信封但 data 非对象"与"裸对象"分开处理。
    """
    if not isinstance(payload, dict):
        return None
    if "code" in payload:
        data = payload.get("data")
        return data if isinstance(data, dict) else None
    # 无 code：只有"看起来就是信封"（键集合 ⊆ {code,message,data,msg}）才剥壳。
    # 曾经的写法是"只要 data 是 dict 就剥"，会把恰好带 data 字段的**业务裸对象**
    # （例如 {"data": {...}, "config_revision": 7}）剥掉外壳，静默丢掉 config_revision。
    if set(payload) <= {"code", "message", "msg", "data"} and "data" in payload:
        data = payload["data"]
        return data if isinstance(data, dict) else None
    return payload


async def _error_detail(response: ClientResponse) -> str:
    """Return ``（code: message）`` from an error envelope, or an empty string.

    错误响应形如 ``{"code":"BAD_REQUEST","message":"请提供绑定码"}``（无 ``data``）。
    把这句人话带进异常里，用户才能在 config flow 里看到"到底哪里不对"。
    """
    try:
        payload = await response.json(content_type=None)
    except (ClientError, ValueError):
        return ""
    if not isinstance(payload, dict):
        return ""
    code = str(payload.get("code") or "")
    message = str(payload.get("message") or payload.get("msg") or "")
    if code and message:
        return f"（{code}: {message}）"
    if code:
        return f"（{code}）"
    if message:
        return f"（{message}）"
    return ""
