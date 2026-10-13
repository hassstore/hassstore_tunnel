# brands 提交流程说明

本目录是 **home-assistant/brands** 风格的目录（`custom_integrations/<domain>/icon.png|icon@2x.png`）。

HA/HACS 里的集成图标**不是**从集成自身仓库加载，而是从
`https://brands.home-assistant.io/custom_integrations/<domain>/icon.png` 拉取。
要让 "HassStore Tunnel" 在 HA 里显示图标，必须给
<https://github.com/home-assistant/brands> 提 PR：

1. Fork `home-assistant/brands`
2. 把本目录的 `custom_integrations/hassstore_tunnel/` 拷到 fork 的
   `custom_integrations/` 下（brands 要求 `icon.png` ≥256×256，`icon@2x.png` ≥512×512）
3. 跑 brands 仓库的 `pytest`（校验尺寸/格式）→ 提 PR，标题建议
   `Add HassStore Tunnel (hassstore_tunnel)`
4. 合并后 icon 立即生效（无需发版）

提 PR 前，HA 里该集成会一直显示默认占位图标（灰色齿轮），属预期。
