"""Constants for the HassStore Tunnel integration.

设计依据
--------
* ``docs/design/02-tunnel-service.md`` §6.3（HA 客户端 API）、§9.3（集成设计）、
  §9.4（运行循环与环境变量契约）、附录 B（客户端配置：代码内构造、无 toml）、
  附录 D（app vs 集成 要点速查）。
* ``docs/design/02a-ha-client-delivery.md`` §B.2（manifest 与降级）、§B.3（子进程托管）、
  §B.4（config flow / 无 ingress）、§B.5.1（trusted_proxies）。
* 用户协议：``docs/legal/tunnel-terms.md`` 第十条 / 附录 B（个人信息跨境传输**单独同意**）。
"""

from __future__ import annotations

from homeassistant.const import __version__ as _HA_VERSION

from typing import Final

# --- 集成标识 ---------------------------------------------------------------
DOMAIN: Final = "hassstore_tunnel"
NAME: Final = "HassStore Tunnel"
VERSION: Final = "1.0.0"

# --- 站点与 app 交付物 ------------------------------------------------------
# 站点地址占位（与 ha/apps/tunnel/config.yaml 的 options.server_url 默认值一致）。
DEFAULT_SERVER_URL: Final = "https://hass.wiki"
# 用户协议落地页（`docs/legal/tunnel-terms.md` 附录 C 第 11 项：/legal/tunnel-terms）。
TERMS_URL: Final = "https://hass.wiki/legal/tunnel-terms"
# 一键添加集成深链（config flow 入口）：官方 my.home-assistant.io 生成器
#   https://my.home-assistant.io/create-link/
MY_HOME_ASSISTANT_URL: Final = (
    "https://my.home-assistant.io/redirect/config_flow_start/?domain=" + DOMAIN
)

# HA app（加载项）仓库与 slug —— 集成作为"安装器"时用
#   docs/design/02-tunnel-service.md §9.2、02a §B.1.3 路线 2/3。
APP_REPOSITORY_URL: Final = "https://github.com/hassstore/apps"
APP_REPOSITORY_SLUG: Final = "hassstore/apps"
APP_SLUG: Final = "hassstore_tunnel"

# --- 客户端 API（设备令牌鉴权，02 §6.3）-------------------------------------
API_CLIENT_BASE: Final = "/api/v1/tunnel/client"
API_BIND: Final = f"{API_CLIENT_BASE}/bind"
API_CONFIG: Final = f"{API_CLIENT_BASE}/config"
API_HEARTBEAT: Final = f"{API_CLIENT_BASE}/heartbeat"
API_USAGE: Final = f"{API_CLIENT_BASE}/usage"
API_EVENT: Final = f"{API_CLIENT_BASE}/event"

# --- 本地客户端（hs-frpc）CLI 契约 ------------------------------------------
# 与 ha/apps/tunnel/run.sh、ha/README.md「统一 CLI 契约」一节 **必须逐字一致**。
# 契约（`docs/design/02-tunnel-service.md` §9.4 + 附录 B）：
#   * 无配置文件、无 toml、无命令行参数、无管理口
#   * 配置只来自环境变量 + ``GET /api/v1/tunnel/client/config``
#   * ``GET /healthz`` → {"ok":true,"connected":true,"version":"v0.71.0-hs.1","config_revision":7}
#   * 致命错误退出码非 0
# 两个易错点（都曾因契约漂移出过故障）：
#   * ``HS_CONFIG_CACHE`` 是**文件路径**（不是目录），令牌缓存放同目录的 ``token``；
#   * ``HS_LOG_LEVEL`` 合法值 = frp 实际支持的集合 ``trace|debug|info|warning|error``
#     （frp 内部叫 ``warn``，hs-frpc 会归一化；notice/fatal 不在集合里，
#     传给 frp 会直接报错退出，**不会**静默回落——旧注释里的"回落 info"已不存在）。
ENV_API_BASE: Final = "HS_API_BASE"
ENV_DEVICE_TOKEN: Final = "HS_DEVICE_TOKEN"
ENV_BIND_CODE: Final = "HS_BIND_CODE"  # 仅一次性使用（run.sh 与集成都先换令牌再启动）
ENV_HEALTH_ADDR: Final = "HS_HEALTH_ADDR"
ENV_LOCAL_TARGET: Final = "HS_LOCAL_TARGET"
ENV_PROTOCOL: Final = "HS_PROTOCOL"
ENV_LOG_LEVEL: Final = "HS_LOG_LEVEL"
ENV_CONFIG_CACHE: Final = "HS_CONFIG_CACHE"
ENV_CLIENT_TYPE: Final = "HS_CLIENT_TYPE"
# HA 版本号（Supervisor 注入的是 HA_VERSION，run.sh 会转成这个名字；
# 集成内置模式直接传 self.hass.config.version，让后台能看到客户端跑在哪个 HA 上）。
ENV_HA_VERSION: Final = "HS_HA_VERSION"

DEFAULT_HEALTH_ADDR: Final = "127.0.0.1:7401"
DEFAULT_LOCAL_TARGET: Final = "http://127.0.0.1:8123"
# app 形态默认 bridge 回源；集成内置形态与 Core 同 netns，用回环。
APP_LOCAL_TARGET: Final = "http://homeassistant:8123"

PROTOCOLS: Final = ["wss", "tcp"]
DEFAULT_PROTOCOL: Final = "wss"
# 合法值 = frp 实际支持的日志级别。曾经的契约写了 notice/fatal，frp 不认 →
# 静默回落 info（用户以为关了 debug，实际还在刷）。warning 是给用户的友好名，
# hs-frpc 会归一化成 frp 的 warn。
LOG_LEVELS: Final = ["trace", "debug", "info", "warning", "error"]
DEFAULT_LOG_LEVEL: Final = "info"

CLIENT_TYPE_INTEGRATION: Final = "integration"
HS_CLIENT_VERSION: Final = "v0.71.0-hs.1"  # v{上游 frp 版本}-hs.{补丁号}

# --- 本地文件布局（02 附录 D：Container/Core 只有 /config 持久）------------
CONF_DIR_NAME: Final = "hassstore_tunnel"
BINARY_NAME: Final = "hs-frpc"
TOKEN_FILE_NAME: Final = "token"
CONFIG_CACHE_FILE_NAME: Final = "last_config.json"

# 集成内置模式的二进制下载（02 §13 / §9.3）：
#   镜像地址可配置（国内建议自建镜像）；SHA256 白名单**缺省拒绝运行**。
DEFAULT_BINARY_MIRROR: Final = "https://hass.wiki/mirror/hs-frpc"
BINARY_URL_TEMPLATE: Final = "{mirror}/{arch}/hs-frpc"

# --- 配置项键名（config entry data / options）-------------------------------
CONF_SERVER_URL: Final = "server_url"
CONF_BIND_CODE: Final = "bind_code"
CONF_DEVICE_TOKEN: Final = "device_token"
CONF_DEVICE_ID: Final = "device_id"
CONF_BINARY_SHA256: Final = "binary_sha256"
CONF_BINARY_MIRROR: Final = "binary_mirror"
# options（可选配置）
CONF_LOCAL_TARGET: Final = "local_target"
CONF_PROTOCOL: Final = "protocol"
CONF_LOG_LEVEL: Final = "log_level"
CONF_AUTO_UPDATE_APP: Final = "auto_update_app"
CONF_LOCAL_CLIENT: Final = "local_client"  # HAOS 上用户可选"不装 app，集成内直接跑"
CONF_ACCEPT_TERMS: Final = "accept_terms"

# --- 轮询 ---------------------------------------------------------------
# `DataUpdateCoordinator` 定时拉 `/healthz` 与 `/tunnel/client/config`（02 §9.4：
# 客户端每 60s 心跳 + 拉配置；UI 状态刷新 30s 足够）。
UPDATE_INTERVAL_SECONDS: Final = 30
REQUEST_TIMEOUT_SECONDS: Final = 15
# 连续多少次 401/403 才判定"令牌真的失效"（触发 reauth）。
# 单次抖动（站点重启、边缘 502 被误判、网络中间盒）不足以让用户重走授权流程。
AUTH_ERROR_THRESHOLD: Final = 3

# --- 子进程自愈 -------------------------------------------------------------
RESTART_BACKOFF_INITIAL: Final = 2.0
RESTART_BACKOFF_MAX: Final = 300.0
STOP_TIMEOUT_SECONDS: Final = 10.0
# 连续稳定运行超过该秒数后，下次崩溃把退避重置回初值。
# 曾经的 bug：判据是 300s 且重置判断写在 sleep **之后** → 崩溃循环里 ran_for 永远很小，
# backoff 翻倍到 300s 后永远锁死（用户改完配置也要等 5 分钟才重试）。
STABLE_RUN_SECONDS: Final = 60.0

# --- 实体 / 属性 ------------------------------------------------------------
BINARY_SENSOR_ONLINE: Final = "tunnel_online"
SENSOR_TRAFFIC_TODAY: Final = "tunnel_traffic_today"
SENSOR_EXPIRE_AT: Final = "tunnel_expire_at"
SENSOR_URL: Final = "tunnel_url"
SENSOR_VERSION: Final = "tunnel_version"
SENSOR_CONFIG_REVISION: Final = "tunnel_config_revision"

# 计费口径：上行 + 下行合计，展示单位 **GB = 10^9 字节**（02 §17.3 ✅Q4）。
BYTES_PER_GB: Final = 10**9

# --- 运行模式 ---------------------------------------------------------------
MODE_ADDON: Final = "addon"  # 有 Supervisor：集成=安装器，app=数据面
MODE_LOCAL: Final = "local"  # 无 Supervisor：集成内托管 hs-frpc 子进程
MODE_LOCAL_ON_SUPERVISOR: Final = "local_on_supervisor"  # 用户在有 Supervisor 的机器上选了内置运行

# --- 其它 -------------------------------------------------------------------
ATTR_LAST_ERROR: Final = "last_error"
ATTR_CHILD_PID: Final = "child_pid"
ATTR_HEALTH: Final = "health"

STORAGE_VERSION: Final = 1


def ha_version() -> str:
    """HA 版本号（Config.version 已在 2024.x 移除；统一走 const.__version__）。"""
    return _HA_VERSION
