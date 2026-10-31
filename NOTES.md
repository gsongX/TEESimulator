# 本 fork 的改动与结论（gxy1110/TEESimulator）

基于上游 `dev` 分支（起点 `06f9f2e`）。以下每个提交都是为解决具体问题加的，
**升级上游前必须先 rebase，否则这些改动会丢**。

## 提交清单

| 提交 | 内容 | 为什么 |
|---|---|---|
| `47ac5c3` | `importKey` 拒绝带 `TAG_EARLY_BOOT_ONLY` 的导入，返回 `EARLY_BOOT_ENDED(-73)` | 真 TEE 在早期启动结束后必然拒绝；TA 原先照收，是“这是模拟器”的一击证据（检测工具 `aj` 项） |
| `72a0e25` | ① 转发操作析构时立即 `abort()`，`begin` 遇 `-31` 做 4/8/12 ms 退避重试；② TA 路径加 TEE 时序模型 | ① 操作槽靠 binder GC 回收，小表容易被占满；② 软件 TA 1 ms 出证 vs 真机几十 ms，本身就是指纹 |
| `befc8ba` | 所有设备级转发调用打日志（方法名 + 调用者 uid + 返回）；`getHardwareInfo` 真 HAL 失败时描述 TA 而不是报错 | 诊断用：确认检测工具到底问了哪些接口（结论：Luna 只调 generateKey/begin，不碰这些） |
| `4ce560a` | 配置新增 `"mode": "auto"` | 按设备自动决定 patch / generation |

## auto 模式的语义

`Resolver` 在每次 push 配置时，用 `Harvester.noWorkingHardware()`（开机时“生成一把一次性证明密钥”的探测结果）决定：

- 硬件能出证明 → `patch`（真机行为不变）
- 硬件出不了证明 → `generation`（完全不碰失效 HAL）

`patch` / `generation` 两种旧模式行为完全不变；`auto` 在 daemon 侧解析成具体值后才下发，router 不需要知道它。

## 两台设备的事实（2026-10-31）

| | 平板（骁龙，OPPO 系） | 手机（天玑，OPPO PLG110） |
|---|---|---|
| 解锁后密钥证明 | **被厂商禁用**（`generateKey` 返回 `-49`） | 正常可用 |
| Luna 检测 | 需要 `generation` | `patch` 也能过 |
| 当前模式 | `auto` → generation | `auto` → patch |

**关键发现**：先前在平板用 `patch` 模式时，模块每次都先问真 HAL、等约 17 ms 拿 `-49`、再回退生成；产出的链与 `generation` **逐字段相同**（5 张证书、keybox 叶子 `CN=405d3d10…,O=TEE`、`serial=01`），唯一差别就是这次失败的往返。Luna 能识别出这一差别，所以 `auto` 一旦在 push 时定成 generation，问题消失。

也就是说：**在这台平板上，patch 模式本来就没有“自己的链”**，所谓“让 patch 的字段更像真机”无从谈起——差的不是字段，是那条失败路径。

## 排查过程中已排除的假设

日志与对照实验证明以下都不是 `Luna` 的判据：keybox（两台同一份）、设备身份/补丁级别字段（均为 `system_property`）、证书链结构（逐字段相同）、生成 vs 改签的链内容（手机强制 generation 也通过）、时序（加模型后仍报）、`-31`（对账闭合，非泄漏）、设备级 KeyMint 接口（Luna 一次未调）、系统属性（两台都是 green/locked）、内核 `cmdline`/`bootconfig`（两台都是 `orange`/`unlocked`）。

## 时序模型

配置：`/data/adb/teesim/latency.conf`（进程启动时读一次，改完重启 keystore2 或重启设备）：

```ini
enabled=1          # 0 = 关闭
scale=0            # 0 = 按本机 CPU 自动标定；也可写 0.8 / 1.5
sigma=0.30         # 对数正态离散度
tail=0.04          # 长尾概率
tail_mult=2.5      # 长尾倍数
```

分档中位数（微秒）：EC 密钥 18000、RSA 密钥 150000、导入 20000、begin 1500、update 500、finish 4000。

## 刷机与验证

```bash
# 模式
su -c 'grep -a "mode auto ->" /data/adb/teesim/log/teesim.log | tail -3'
# 平板应为 -> generation，手机应为 -> patch

# EARLY_BOOT_ONLY 拒绝是否生效
su -c 'grep -a "refusing EARLY_BOOT_ONLY" /data/adb/teesim/log/teesim.log | tail -2'

# 设备级调用（诊断时才有输出）
su -c 'grep -aE "getHardwareInfo|RootOfTrust|earlyBootEnded" /data/adb/teesim/log/teesim.log | tail'
```

## 已知残留

- 部分链的 `issuer=[CN=Fake]`（attest key 由模块自己生成时的占位名，1 张证书）。出现在通过检测的路径上，不是判据，但作为指纹建议以后清理。
- `attestationVersion` / `keymasterVersion` 由 TA 固定为 400；设备真值若不同，可考虑由 daemon 下发。
- 手机上有个别 App（如 `com.eltavine.duckdetector`）的 patch 请求被真 HAL 以 `-21(INVALID_INPUT_LENGTH)` 拒绝后回退生成，属于该 App 请求参数的问题，与 TEE 无关。

## 升级上游注意

1. `git fetch upstream && git rebase upstream/dev`，冲突大概率集中在 `keymint/keymint_router.cpp`；
2. 必须保留：`EARLY_BOOT_ONLY` 拒绝、`-31` 清理、`auto` 模式解析（`ConfigStore.kt` / `Resolver.kt` / `schema.js`）；
3. 升级后重新确认：平板日志 `mode auto -> generation`、Luna 通过。
