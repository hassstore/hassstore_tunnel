"""Config flow / Options flow / Reauth for HassStore Tunnel.

文档依据：``docs/design/02a-ha-client-delivery.md`` §B.4.1（config flow / options flow / reauth
的官方写法与推荐步骤）；接口依据：``docs/design/02-tunnel-service.md`` §6.3。

实现要点：
  * ``manifest.json`` 里 ``single_config_entry: true`` → 一台 HA 只跑一个隧道客户端，
    所以 ``async_step_user`` 遇到已有 entry 直接 ``abort("single_instance_allowed")``。
  * 用户必须**显式勾选**同意用户协议与跨境传输单独同意（``docs/legal/tunnel-terms.md``
    第十条 / 附录 B）—— 这是协议要求"单独征求同意"在客户端侧的落点。
  * 环境探测用 ``async_supervisor_available``（内部走 ``async_get_hassio_entry``，
    并保留 ``os.environ["SUPERVISOR"]`` 作为旁证），**不**依赖 ``dependencies: ["hassio"]``。
  * 令牌失效 → ``async_step_reauth`` / ``async_step_reauth_confirm``，收尾用
    ``async_update_reload_and_abort``。
"""

from __future__ import annotations

import platform
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.core import callback
from homeassistant.helpers import selector

from .api import HassStoreAuthError, HassStoreClient, HassStoreCommError, HassStoreError
from .const import (
    CONF_ACCEPT_TERMS,
    CONF_AUTO_UPDATE_APP,
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
    DEFAULT_LOCAL_TARGET,
    DEFAULT_LOG_LEVEL,
    DEFAULT_PROTOCOL,
    DEFAULT_SERVER_URL,
    DOMAIN,
    LOG_LEVELS,
    NAME,
    PROTOCOLS,
    ha_version,
)
from .supervisor import async_supervisor_available


class HassStoreTunnelConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the initial setup and reauth."""

    VERSION = 1
    MINOR_VERSION = 1

    def __init__(self) -> None:
        self._server_url: str = DEFAULT_SERVER_URL
        self._bind_code: str = ""
        self._device_token: str | None = None
        self._device_id: str | None = None
        self._has_supervisor: bool = False
        self._prefer_local: bool = False
        self._binary_sha256: str = ""
        self._binary_mirror: str = DEFAULT_BINARY_MIRROR

    # -- helpers ------------------------------------------------------------
    def _build_schema(self, *, defaults: dict[str, Any] | None = None) -> vol.Schema:
        """Build the user / reauth schema: ``server_url`` + ``bind_code`` + 协议同意。

        ``binary_sha256`` 不在这里 —— 它只在"集成内置运行"模式下才需要，
        放到 OptionsFlow 里（否则 app 模式的用户会被一个必填项拦住）。
        """
        values = defaults or {}
        return vol.Schema(
            {
                vol.Required(
                    CONF_SERVER_URL, default=values.get(CONF_SERVER_URL, DEFAULT_SERVER_URL)
                ): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.URL)
                ),
                vol.Required(
                    CONF_BIND_CODE, default=values.get(CONF_BIND_CODE, "")
                ): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                ),
                vol.Required(
                    CONF_ACCEPT_TERMS, default=values.get(CONF_ACCEPT_TERMS, False)
                ): selector.BooleanSelector(),
            }
        )

    async def _async_try_bind(
        self, server_url: str, bind_code: str
    ) -> tuple[str | None, dict[str, Any] | None]:
        """Try to exchange the code immediately; returns ``(token, config)``.

        在 config flow 阶段就调用 ``/tunnel/client/bind`` 的好处：绑定码一次性且 10 分钟
        有效（02 §6.3），错误要**当场**告诉用户，而不是等 entry setup 才失败。
        """
        client = HassStoreClient(self.hass, server_url)
        result = await client.async_bind(
            bind_code,
            hostname=platform.node() or "homeassistant",
            ha_version=ha_version(),
            arch=platform.machine(),
        )
        return result.get(CONF_DEVICE_TOKEN), result

    # -- steps --------------------------------------------------------------
    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """First step: site URL + bind code + (advanced) binary hash + terms consent."""
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        errors: dict[str, str] = {}
        if user_input is not None:
            self._server_url = str(user_input[CONF_SERVER_URL]).rstrip("/")
            self._bind_code = str(user_input.get(CONF_BIND_CODE, "")).strip()

            if not user_input.get(CONF_ACCEPT_TERMS):
                errors["base"] = "terms_required"
            elif not self._server_url.startswith(("http://", "https://")):
                errors["base"] = "invalid_url"
            elif not self._bind_code:
                errors["base"] = "bind_code_required"
            else:
                try:
                    token, result = await self._async_try_bind(self._server_url, self._bind_code)
                except HassStoreAuthError:
                    errors["base"] = "invalid_auth"
                except HassStoreCommError:
                    errors["base"] = "cannot_connect"
                except HassStoreError:
                    errors["base"] = "invalid_bind_code"
                else:
                    if not token:
                        errors["base"] = "invalid_bind_code"
                    else:
                        self._device_token = token
                        # device_id 一并存下：否则只有"setup 时才绑定"的路径会写它
                        # （__init__._async_ensure_device_token），走 config_flow
                        # 绑定的 entry 里 device_id 恒缺，诊断/面板拿不到。
                        self._device_id = result.get(CONF_DEVICE_ID)
                        return await self._async_finish_bind()

        return self.async_show_form(
            step_id="user",
            data_schema=self._build_schema(),
            errors=errors,
        )

    async def async_step_environment(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask HAOS users where the data plane should live (02 §9.3 步骤 3).

        ⚠️ 必须有"返回上一步"：绑定码一次性且 10 分钟有效，用户想改 server_url 或
        换一个绑定码时，取消整个 flow 重来意味着必须回站点重新生成码（高频踩坑）。
        """
        if user_input is not None:
            self._prefer_local = user_input[CONF_LOCAL_CLIENT]
            if self._prefer_local:
                # 内置运行需要 hs-frpc 二进制的 SHA256（缺省拒绝运行，见 local_process）
                return await self.async_step_binary()
            return self._async_create_entry()

        return self.async_show_form(
            step_id="environment",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_LOCAL_CLIENT, default=False): selector.BooleanSelector(),
                }
            ),
            # HA 用 errors + description_placeholders 呈现"上一步"入口
            last_step=None,
        )

    async def async_step_binary(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect ``binary_sha256`` for the in-integration (local) data plane.

        曾经的 bug：这个必填项只藏在 OptionsFlow 的"高级选项"里（还依赖已废弃的
        ``show_advanced_options``），Container 用户装完直接 SETUP_RETRY 循环，
        UI 里却找不到填的地方 → 100% 卡死。这里在内置模式下**必填**。
        """
        errors: dict[str, str] = {}
        if user_input is not None:
            sha = str(user_input.get(CONF_BINARY_SHA256, "")).strip().lower()
            if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
                errors["base"] = "invalid_sha256"
            else:
                self._binary_sha256 = sha
                # 镜像地址也要收下：此前这一步展示了输入框却丢弃用户输入
                # （_async_create_entry 硬编码 DEFAULT），用户填了等于没填。
                mirror = str(user_input.get(CONF_BINARY_MIRROR, "")).strip()
                self._binary_mirror = mirror or DEFAULT_BINARY_MIRROR
                return self._async_create_entry()

        return self.async_show_form(
            step_id="binary",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_BINARY_SHA256, default=""): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                    ),
                    vol.Optional(
                        CONF_BINARY_MIRROR, default=DEFAULT_BINARY_MIRROR
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.URL)
                    ),
                }
            ),
            errors=errors,
        )

    async def _async_finish_bind(self) -> ConfigFlowResult:
        """After a successful bind: ask the environment question only on Supervisor."""
        self._has_supervisor = await async_supervisor_available(self.hass)
        if self._has_supervisor:
            return await self.async_step_environment()
        self._prefer_local = True  # Container / Core：没有 app 可用，只能内置运行
        return await self.async_step_binary()

    def _async_create_entry(self) -> ConfigFlowResult:
        # 令牌只写 options 一处：data 里再放一份会同时出现在
        # /config/.storage/core.config_entries 的诊断/备份快照里（设计 §9.2 说"不写 /config"）。
        return self.async_create_entry(
            title=f"{NAME}（{self._server_url}）",
            data={
                CONF_SERVER_URL: self._server_url,
                # 绑定码一次性：绑定成功后不再保留（换绑走 reauth）。
            },
            options={
                CONF_DEVICE_TOKEN: self._device_token,
                **({CONF_DEVICE_ID: self._device_id} if self._device_id else {}),
                CONF_LOCAL_TARGET: DEFAULT_LOCAL_TARGET,
                CONF_PROTOCOL: DEFAULT_PROTOCOL,
                CONF_LOG_LEVEL: DEFAULT_LOG_LEVEL,
                CONF_AUTO_UPDATE_APP: True,
                CONF_LOCAL_CLIENT: self._prefer_local,
                CONF_BINARY_MIRROR: getattr(self, "_binary_mirror", DEFAULT_BINARY_MIRROR),
                CONF_BINARY_SHA256: getattr(self, "_binary_sha256", ""),
            },
        )

    # -- reauth -------------------------------------------------------------
    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        """Triggered when the device token was revoked on the site."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect a fresh bind code and update the existing entry in place."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}

        if user_input is not None:
            server_url = str(user_input[CONF_SERVER_URL]).rstrip("/")
            bind_code = str(user_input.get(CONF_BIND_CODE, "")).strip()
            # 表单里有 accept_terms 复选框就必须真校验（首次安装路径同款）；
            # 缺这段的话"勾选"形同摆设。
            if not user_input.get(CONF_ACCEPT_TERMS):
                errors["base"] = "terms_required"
            elif not bind_code:
                errors["base"] = "bind_code_required"
            else:
                try:
                    token, result = await self._async_try_bind(server_url, bind_code)
                except HassStoreAuthError:
                    errors["base"] = "invalid_auth"
                except HassStoreCommError:
                    errors["base"] = "cannot_connect"
                except HassStoreError:
                    errors["base"] = "invalid_bind_code"
                else:
                    if not token:
                        errors["base"] = "invalid_bind_code"
                    else:
                        # 令牌**只**写 options：写进 data 会随
                        # /config/.storage/core.config_entries 进诊断/备份快照，
                        # 与设计 §9.2「令牌不写 /config」相悖。
                        # 老 entry 遗留在 data 的令牌由 async_setup_entry 的
                        # 一次性迁移清掉（那里能用 async_update_entry 真正删键；
                        # 这里的 data_updates 只是 dict 合并，写 None 删不掉）。
                        # server_url 是配置项（非敏感），留在 data。
                        new_options = {**entry.options, CONF_DEVICE_TOKEN: token}
                        # 换绑可能换设备：把新 device_id 一并刷新（有则写）。
                        if device_id := result.get(CONF_DEVICE_ID):
                            new_options[CONF_DEVICE_ID] = device_id
                        return self.async_update_reload_and_abort(
                            entry,
                            data_updates={CONF_SERVER_URL: server_url},
                            options=new_options,
                        )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=self._build_schema(
                defaults={
                    CONF_SERVER_URL: entry.data.get(CONF_SERVER_URL, DEFAULT_SERVER_URL),
                    CONF_BIND_CODE: "",
                    CONF_ACCEPT_TERMS: True,
                }
            ),
            errors=errors,
        )

    # -- options ------------------------------------------------------------
    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Return the options flow handler."""
        return HassStoreTunnelOptionsFlow()


class HassStoreTunnelOptionsFlow(OptionsFlow):
    """Optional settings: local target, protocol, log level, auto update, run mode.

    注意：``OptionsFlow`` 的自定义流程在 2024.11 之后**不能**再自己持有
    ``config_entry`` 属性（基类提供 ``self.config_entry``）。这里只读不写。
    """

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Single-step options form."""
        if user_input is not None:
            # ⚠️ 必须保留既有 options：async_create_entry 会**整体替换** options，
            # 而表单只产出 local_target/protocol/log_level 等可选项——CONF_DEVICE_TOKEN
            # 与 CONF_DEVICE_ID 也在 options 里（config_flow 只把它们写 options、
            # 不写 data），直接传 user_input 会把令牌抹掉，集成随后永远
            # ConfigEntryNotReady 且不构成 auth 错误、不会触发 reauth。
            return self.async_create_entry(
                title="", data={**self.config_entry.options, **user_input}
            )

        current = self.config_entry.options
        data = self.config_entry.data
        fields: dict[Any, Any] = {
            vol.Required(
                CONF_LOCAL_TARGET,
                default=current.get(CONF_LOCAL_TARGET, DEFAULT_LOCAL_TARGET),
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.URL)
            ),
            vol.Required(
                CONF_PROTOCOL, default=current.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)
            ): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=PROTOCOLS, mode=selector.SelectSelectorMode.DROPDOWN
                )
            ),
            vol.Required(
                CONF_LOG_LEVEL, default=current.get(CONF_LOG_LEVEL, DEFAULT_LOG_LEVEL)
            ): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=LOG_LEVELS, mode=selector.SelectSelectorMode.DROPDOWN
                )
            ),
            vol.Required(
                CONF_AUTO_UPDATE_APP, default=current.get(CONF_AUTO_UPDATE_APP, True)
            ): selector.BooleanSelector(),
            vol.Required(
                CONF_LOCAL_CLIENT, default=current.get(CONF_LOCAL_CLIENT, False)
            ): selector.BooleanSelector(),
            # binary_mirror / binary_sha256 **无条件**展示。
            # 曾经的 bug：它们藏在 `getattr(self, "show_advanced_options", False)` 里，
            # 而该属性在现行 HA 中被 deprecated_function 包裹、2027.6 后行为未定；
            # 结果是 Container 用户看不到必填项 → SETUP_RETRY 循环且无从下手。
            vol.Optional(
                CONF_BINARY_MIRROR,
                default=current.get(CONF_BINARY_MIRROR, DEFAULT_BINARY_MIRROR),
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.URL)
            ),
            vol.Optional(
                CONF_BINARY_SHA256,
                default=current.get(CONF_BINARY_SHA256)
                or data.get(CONF_BINARY_SHA256, ""),
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
            ),
        }

        return self.async_show_form(step_id="init", data_schema=vol.Schema(fields))
