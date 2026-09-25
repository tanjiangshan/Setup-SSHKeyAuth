# Setup-SSHKeyAuth

**SSH 免密登录一键配置工具（MobaXterm + Xshell）**

从 MobaXterm / Xshell **当前已建立的 SSH 连接**中提取服务器 IP、用户名、密码，自动完成密钥生成、公钥部署，并把 MobaXterm 和 Xshell 都配置成免密登录。

```
 已建立的 SSH 连接 ──► 提取 IP/用户名/密码 ──► 生成或复用密钥对
      │                                              │
      ▼                                              ▼
 配置 MobaXterm 会话 ◄──────────────────── 部署公钥到服务器
 配置 Xshell + Xagent ◄─────────────────── 验证免密登录
```

## 快速开始

```powershell
# 方式 1：自动发现当前已建立的连接，交互式选择要处理哪些
.\Setup-SSHKeyAuth.ps1

# 方式 2：处理所有已建立的连接（无需选择）
.\Setup-SSHKeyAuth.ps1 -All

# 方式 3：手动指定服务器
.\Setup-SSHKeyAuth.ps1 -Ip 192.168.1.10,192.168.1.11

# 修改 MobaXterm 配置需要先关闭 MobaXterm，-Force 表示自动关闭（会断开现有终端会话）
.\Setup-SSHKeyAuth.ps1 -Ip 192.168.1.10 -Force
```

> 如果遇到执行策略限制：`powershell -ExecutionPolicy Bypass -File .\Setup-SSHKeyAuth.ps1 -All`

## 参数说明

| 参数 | 说明 |
|---|---|
| `-Ip <ip1,ip2,...>` | 手动指定目标服务器 IP（跳过自动发现） |
| `-All` | 处理所有自动发现的目标（活跃连接 + 本地存储的会话） |
| `-Force` | 自动结束 MobaXterm 进程以便写入其配置文件（**会断开现有终端**，工具会先备份配置） |
| `-User <name>` | 覆盖自动识别的登录用户名（默认从会话记录中取，取不到则为 root） |
| `-SkipServer` | 跳过服务器端公钥部署（只配置客户端） |
| `-SkipMoba` | 跳过 MobaXterm 配置 |
| `-SkipXshell` | 跳过 Xshell 配置 |

不带 `-Ip` / `-All` 且存在活跃连接时，会列出连接清单让你输入序号选择（回车 = 全选）。

## 工作流程

```
 ① 发现目标        扫描 MobaXterm / MoTTY / Xshell / PuTTY 进程的 22 端口活跃 TCP 连接
                   同时解析 MobaXterm.ini 书签和 Xshell 会话文件作为补充
 ② 提取凭据        IP / 用户名：来自会话记录
                   密码：尝试解密客户端本地存储的加密密码（见"密码提取能力"）
 ③ 准备密钥        复用 %USERPROFILE%\.ssh\id_ed25519；不存在则自动生成（无口令）
 ④ 部署公钥        先测试密钥是否已能登录；不能则用密码自动部署到
                   服务器 ~/.ssh/authorized_keys（幂等，自动设置 700/600 权限）
 ⑤ 配置 MobaXterm  备份 MobaXterm.ini 后，将目标会话的私钥字段指向
                   _ProfileDir_\.ssh\id_ed25519（即 C:\Users\<你>\.ssh\id_ed25519）
 ⑥ 配置 Xshell     a. 把 OpenSSH 私钥转换为 NetSarang 专有格式，写入
                      文档\NetSarang Computer\<版本>\SECSH\UserKeys\id_ed25519.pri
                   b. 在 Sessions\ 目录生成 <ip>.xshf 会话（公钥认证方式）
                   c. 确保 Xagent 已运行（Xshell 免密依赖它）
 ⑦ 验证报告        逐台实测密钥登录，输出最终结果表
```

### 密码提取能力（尽力而为）

| 客户端 / 版本 | 能否解密 | 算法 |
|---|---|---|
| Xshell 7 / 8 | ✅ | SHA256(逆序SID + Windows用户名) + RC4，尾部 SHA256 校验 |
| Xshell 5.3 ~ 6 | ✅ | SHA256(用户名 + SID) + RC4 |
| Xshell 5.1 ~ 5.2 | ✅ | SHA256(SID) + RC4 |
| Xshell ≤ 5.0 | ✅ | MD5 固定密钥 + RC4 |
| MobaXterm v22 ~ v24 | ✅ | [Sesspass] DPAPI 解出密钥 → AES-256-CFB8 |
| MobaXterm 旧版（无主密码） | ✅ | 静态查表算法 |
| **MobaXterm v25 / v26** | ❌ | 新版 `_@` 前缀凭据格式目前**业界无公开解密方案** |

> **v25/v26 怎么办**：工具会先检测该服务器密钥是否已经能登录（能登录就完全不需要密码）；
> 不能登录则**提示你手动输入一次密码**完成公钥部署，之后永久免密。
> 密码只经内存用于这一次部署，不会保存到任何文件。

## 输出示例

```
======== SSH 免密登录一键配置 (MobaXterm + Xshell) ========

[..] scanning established SSH connections ...
      active: 192.168.1.10  (client: MobaXterm)
[..] MobaXterm config: D:\...\MobaXterm.ini
      moba session: 192.168.1.10:22  login=root  key=_ProfileDir_\.ssh\id_ed25519
[OK] targets: 192.168.1.10
[OK] private key: C:\Users\me\.ssh\id_ed25519

---- 192.168.1.10 ----
[OK] server: public-key auth already works (nothing to do)
[OK] Xshell user key written: ...\SECSH\UserKeys\id_ed25519.pri (ssh-ed25519)
[OK] Xshell session files written: 1
[OK] Xagent running (agent-based passwordless auth active)

=========================== 报告 =========================
Server       User 免密登录
------       ---- --------
192.168.1.10 root OK
===========================================================
```

## 注意事项

1. **修改 MobaXterm.ini 前必须关闭 MobaXterm**
   MobaXterm 退出时会把内存中的配置回写到 INI，运行中修改会被覆盖。
   工具检测到 MobaXterm 在运行时会询问（输入 y 自动关闭）或直接用 `-Force`。
   修改前自动备份为 `MobaXterm.ini.toolbak-<时间戳>`。

2. **Xshell 免密依赖 Xagent**
   工具会自动启动 NetSarang 的 Xagent（SSH 代理），它加载 `SECSH\UserKeys\` 下的密钥。
   Xshell 连接时通过代理自动完成密钥认证。正常情况下 Xshell 启动时也会自动带起 Xagent。

3. **私钥口令（passphrase）**
   工具使用的私钥必须**无口令**（自动生成的即为无口令）。若你的 `id_ed25519` 设了口令，
   工具会在转换 Xshell 密钥时报错——可先 `ssh-keygen -p -f ~\.ssh\id_ed25519` 去掉口令后重跑。
   支持 ed25519 和 RSA（openssh 新格式）两种密钥类型。

4. **安全提示**
   无口令私钥 + 本机账户 = 服务器访问权。请确保本机登录安全；
   需要撤销时删除服务器 `~/.ssh/authorized_keys` 中对应公钥行即可。

5. **备份与回滚**
   - MobaXterm.ini → `<原路径>\MobaXterm.ini.toolbak-<时间戳>`
   - Xshell 用户密钥 / 会话文件均为新增文件，删除即可回滚
   - 服务器端公钥为追加式（有则不重复添加），删除 authorized_keys 对应行可回滚

## 环境要求

| 组件 | 要求 |
|---|---|
| 操作系统 | Windows 10 / 11（PowerShell 5.1） |
| OpenSSH 客户端 | ≥ 8.4（Win10 21H1+ / Win11 自带即满足；密码部署用到 `SSH_ASKPASS_REQUIRE`） |
| MobaXterm | 任意版本均可配置；密码自动解密支持 v24 及以下 |
| Xshell | 6 / 7 / 8（通过注册表定位用户数据目录） |

## 故障排查

| 现象 | 原因与处理 |
|---|---|
| 某台服务器报告 FAILED | 公钥部署没成功：检查输入的密码是否正确、服务器 sshd 是否允许公钥认证（`PubkeyAuthentication yes`） |
| Xshell 双击会话仍提示密码 | 检查 Xagent 是否在运行（任务栏 / 任务管理器）；也可在 Xshell 中 Tools → User Key Manager 确认 `id_ed25519` 已在列表中 |
| MobaXterm 配置改了但不生效 | MobaXterm 当时在运行，退出时覆盖了修改 → 关闭后重跑（或 `-Force`） |
| 找不到活跃连接 | 目标连接已断开；用 `-Ip` 手动指定，或 `-All` 处理所有本地会话 |
| `ssh-keygen failed` | `~\.ssh` 目录权限异常或磁盘问题，检查后重试 |
| Xshell 密钥写入报 "encrypted private key not supported" | 私钥带口令，先去掉口令（见注意事项 3） |

## 原理速览（供安全审计）

- **密码获取**全部来自本机客户端的本地存储（你的电脑上本来就有这些数据），不涉及网络嗅探。
- **公钥部署**通过 `ssh.exe` 的 `SSH_ASKPASS` 机制自动输入密码执行远端命令
  （`mkdir/grep/echo/chmod`），不向磁盘写入明文密码，临时 askpass 文件用后即删。
- **Xshell 密钥库格式**：`---- BEGIN NSSSH PRIVATE KEY ----`（NetSarang 专有封装，
  结构为 openssh-key-v1 的变体），工具按字节级兼容格式直接生成，与官方导入结果一致。
- **MobaXterm 书签**：INI 中 `[Bookmarks*]` 段的会话串以 `%` 分隔，
  第 14 个字段为私钥路径，工具仅修改该字段，其余字节保持不变。

## License

[MIT](LICENSE)
