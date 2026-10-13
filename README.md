# HassStore Tunnel · Home Assistant 自定义集成（HACS 自定义仓库）

HassStore 内网穿透集成：把 Home Assistant 的公网访问能力（`https://<子域名>`）
接到你的 HassStore 账户，同时上报隧道状态、当日流量、到期时间与当前穿透地址。

集成位于本仓库的 `custom_components/hassstore_tunnel/`。

---

## 一、能力概览

按运行环境自动选择落地形态：

| 环境 | 集成角色 | 数据面 |
|---|---|---|
| **HAOS**（有 Supervisor） | 安装器：自动加 app 仓库 → 安装 → 写配置 → 启动 | `hassstore_tunnel` app 容器里的 `hs-frpc`（独立生命周期 + Supervisor watchdog） |
| **HAOS，但选择"在集成内运行"** | 控制面 + 数据面 | 集成下载并托管 `hs-frpc` 子进程 |
| **HA Container / Core（无 Supervisor）** | 控制面 + 数据面（唯一选择） | 同上；`/config` 是唯一持久目录 |

集成提供的实体：

- `binary_sensor.tunnel_online`
- `sensor.tunnel_traffic_today`
- `sensor.tunnel_expire_at`
- `sensor.tunnel_url`
- `sensor.tunnel_version`
- `sensor.tunnel_config_revision`

> 集成**没有 ingress 内嵌面板**（ingress 是 Supervisor 给 app 的能力）。
> HAOS 用户的面板由 `hassstore_tunnel` app 提供；Container/Core 用户从站点进入。

---

## 二、安装（HACS 自定义仓库）

### 1. 安装 HACS（若尚未安装）

HACS 本身是自定义集成，安装方式见官方文档 <https://hacs.xyz/docs/use/download/download/>。
HAOS 用户也可以用 `hacs/addons` 商店里的 "Get HACS" app。

### 2. 添加自定义仓库

```
HACS（侧边栏）→ 右上角 ⋮ → Custom repositories
  Repository: https://github.com/hassstore/hassstore_tunnel
  Category:   Integration
  → ADD
```

### 3. 下载并重启 Home Assistant Core

```
HACS → 搜索 "HassStore Tunnel" → DOWNLOAD → RESTART
```

⚠️ **必须重启一次，不是可选步骤。** 新的 `custom_components/<domain>/` 目录只在
启动期被 HA 发现，运行期无法载入。

**不用 HACS 的手动安装**（同样要重启）：

```bash
# 1) 解压 Release 资产或 clone 仓库后，把目录【内容】落到下面的目标，
#    最终 HA 必须能直接看到 /config/custom_components/hassstore_tunnel/manifest.json
#
#    zip 包顶层就是 hassstore_tunnel/ 一层——解开 zip 后得到的 hassstore_tunnel/ 目录
#    才是要复制到 custom_components/ 下的单元，别把"custom_components/" 这层一起复制
#    进去，否则会变成 .../custom_components/custom_components/hassstore_tunnel/，
#    报 "No such file or directory: manifest.json"
#
# 目标目录
#   HAOS/Container: /config/custom_components/hassstore_tunnel/
#   Core(venv):     <配置目录>/custom_components/hassstore_tunnel/
cp -r custom_components/hassstore_tunnel /config/custom_components/

# 校验（应输出 manifest.json 等文件，不再有嵌套）：
ls /config/custom_components/hassstore_tunnel/

# 2) 然后：设置 → 右上角 ⋮ → 重启 Home Assistant
```

### 4. 添加集成

```
设置 → 设备与服务 → 右下角 + 添加集成 → 搜索 "HassStore Tunnel"
```

或一键深链：<https://my.home-assistant.io/redirect/config_flow_start/?domain=hassstore_tunnel>

填写顺序：

1. **HassStore 站点地址**（默认 `https://hassstore.nextrt.com`）
2. **绑定码**：站点「用户中心 → 内网穿透 → 绑定到 HA」生成的 8 位码（10 分钟有效、一次性）
3. **勾选同意**《用户协议》与《个人信息跨境传输单独同意》
4. HAOS 会多问一步「数据面运行位置」：装成 app（推荐）还是集成内直接跑

之后集成自动完成 app 仓库注册、安装、写配置、启动。

---

## 三、⚠️ 必配：`configuration.yaml` 的 `http:` 反代信任

外网访问必然带 `X-Forwarded-For`；HA 看到该头但 `trusted_proxies` 没配好时会**直接返回 400**。

```yaml
# /config/configuration.yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 172.30.32.0/23   # app bridge 模式：frpc 容器 → Core(host 网络) 的对端是 bridge 网关
    - 127.0.0.1        # host_network app / 集成内置子进程（与 Core 同容器）
    - ::1
```

- 掩码**必须写网段地址**（`172.30.32.0/23`），不能写 `172.30.32.1/23`。
- 改完：**设置 → 工具 → YAML → 检查配置** → 重启 Home Assistant。

同时到 **设置 → 系统 → 网络 → Home Assistant URL → Internet** 填 `https://<你的子域名>`。

---

## 四、Container / Core 用户（无 Supervisor）

- 集成**只能**走"内置运行"模式，会把 `hs-frpc` 下载到 **`/config/hassstore_tunnel/`**。
- **必须先在集成选项里填 `binary_sha256`**：缺校验值时代码**拒绝下载与运行**。
  校验值随每次发布给出。
- 内置模式启动前会做一次 `--version` 可执行性探测，捕获 `noexec` 挂载点并给出可读提示。
- **HA 重启/升级会中断隧道**（子进程随 Core 生命周期）；HAOS 的 app 模式不受影响。
- 下载失败先在集成选项里检查 `binary_mirror`（国内网络建议自建镜像）。

---

## 五、安全建议

1. **开启 Home Assistant 双因素认证与强密码**（公网可达后 HA 自身鉴权是唯一防线）：
   设置 → 个人资料 → 安全 → 多因素认证。
2. 不要在公网地址上关闭 HA 登录，也不要让"免登录可信网络"覆盖公网来源。
3. 定期检查 **设置 → 系统 → 日志** 是否出现
   `Received X-Forwarded-For header from an untrusted proxy` —— 出现说明 `trusted_proxies` 还没配全。

---

## 六、用户协议与跨境传输同意

集成配置界面会要求勾选：

- 《HassStore 内网穿透服务用户协议》
- 《个人信息跨境传输单独同意》（独立勾选，不并入总协议）

使用限制：本服务只做 **HTTP/HTTPS 网页穿透**（仅 `type=http`、仅 8123 回源），
不得用于代理、翻墙、机场、跨境流量中转或绕过任何网络访问管理措施。
协议层面不开放 TCP/UDP 转发。

---

## 七、排障速查

| 现象 | 处理 |
|---|---|
| 配置界面报"绑定码无效/已过期" | 绑定码一次性 + 10 分钟；回站点重新生成 |
| 集成显示"设备令牌失效"并弹出重新认证 | 令牌被轮换/设备被停用；跑一遍 reauth 重新绑定 |
| 外网 400 Bad Request | 第三节 `trusted_proxies` 没配全 |
| HAOS 上 app 装不上 | 集成会给出原因；可在选项改为"集成内运行" |
| 内置模式报"hs-frpc 未通过完整性校验" | 集成选项里填正确的 `binary_sha256`，或改 app 模式 |
| 内置模式报不可执行 | `/config` 挂载点可能是 `noexec`，检查挂载参数或改 app 模式 |
| 内置模式隧道频繁重启 | 看 HA 日志 `[hs-frpc]` 前缀行；常见为套餐到期/超额被拒 |

集成 logger 名：`custom_components.hassstore_tunnel`（可在 `configuration.yaml` 调级别）。

## 八、图标

本集成**已自带** `custom_components/hassstore_tunnel/brand/icon.png`（+
`icon@2x.png`），HA 2024.6+ 会在 `brands` 集成里命中 `has_branding` 直接显示，
无需等待 brands 仓 PR。

如需在 HACS 官方商店 / marketplace 列表里也显示图标，可再把
`brands/custom_integrations/hassstore_tunnel/` 的 PNG 提到
<https://github.com/home-assistant/brands> 的 `custom_integrations/` 下
（`icon.png` ≥256×256 + `icon@2x.png` ≥512×512，跑 `pytest` 验证后提 PR）。

