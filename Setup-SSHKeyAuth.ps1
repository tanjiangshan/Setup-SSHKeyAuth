#Requires -Version 5.1
<#
.SYNOPSIS
  SSH 免密登录一键配置工具 (MobaXterm + Xshell) - 命令行入口

.DESCRIPTION
  1. 从当前 MobaXterm / Xshell 已建立的 SSH 连接中提取服务器 IP / 用户名 / 密码
     (密码来自客户端本地存储的加密凭据, 支持解密 Xshell 5~8 及 MobaXterm v24 及以下格式;
      MobaXterm v25+ 新格式暂无公开解密方案, 会自动改用密钥探测/手动输入兜底)
  2. 复用或生成 SSH 密钥对 (%USERPROFILE%\.ssh\id_ed25519)
  3. 将公钥部署到服务器 ~/.ssh/authorized_keys (幂等)
  4. 配置 MobaXterm 会话 (INI 书签) 使用私钥
  5. 配置 Xshell: 生成 NSSSH 用户密钥 + 会话文件, 并确保 Xagent 运行 (agent 免密)
  6. 逐台验证免密登录并输出报告

  图形界面: 运行 Setup-SSHKeyAuthGui.ps1 或双击 启动工具.bat

.EXAMPLE
  .\Setup-SSHKeyAuth.ps1                 # 交互: 选择当前已建立的连接
  .\Setup-SSHKeyAuth.ps1 -All            # 处理所有已建立的连接
  .\Setup-SSHKeyAuth.ps1 -Ip 192.168.1.10,192.168.1.11
  .\Setup-SSHKeyAuth.ps1 -All -Force     # 自动关闭 MobaXterm 以便修改其 INI
  .\Setup-SSHKeyAuth.ps1 -ExportCred "creds.md"   # 仅生成凭据清单文档
#>
[CmdletBinding()]
param(
    [string[]]$Ip,
    [switch]$All,
    [switch]$Force,
    [string]$User,
    [switch]$SkipServer,
    [switch]$SkipMoba,
    [switch]$SkipXshell,
    [string]$ExportCred
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'Setup-SSHKeyAuthCore.ps1')

# ---- 仅生成凭据文档模式 ----
if($ExportCred){
    $inv = Get-SshCredentialInventory
    if(-not $inv -or $inv.Count -eq 0){ Err "no SSH connection or stored session found"; exit 1 }
    if(Test-Path $ExportCred -PathType Container){ $ExportCred = Join-Path $ExportCred "SSH连接凭据_$(Get-Date -Format yyyyMMdd-HHmmss).md" }
    Export-CredentialMarkdown $inv $ExportCred | Out-Null
    Ok "credential document written: $ExportCred"
    exit 0
}

# ---- 控制台版交互回调 ----
$targetSelector = {
    param($candidates)
    Write-Host ""
    Write-Host "  detect targets: (input numbers, comma separated, or Enter = all)" -ForegroundColor Cyan
    for($i=0; $i -lt $candidates.Count; $i++){
        Write-Host ("    [{0}] {1}  ({2})" -f ($i+1), $candidates[$i].Ip, $candidates[$i].Tool)
    }
    $ans = Read-Host "  select"
    if([string]::IsNullOrWhiteSpace($ans)){ return @($candidates | ForEach-Object { $_.Ip }) }
    return @($ans -split '[,\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { $candidates[[int]$_ - 1].Ip })
}
$pwPrompter = {
    param($ip, $user)
    return (Read-Host "  input password for $user@$ip to deploy key (Enter = skip)")
}
$confirmer = {
    param($message)
    return ((Read-Host "  $message (y/N)") -match '^[Yy]')
}

# ---- 主流程 ----
$report = Invoke-PasswordlessSetup -TargetIps $Ip -UserName $User -All:$All -ForceCloseMoba:([bool]$Force) `
    -SkipServer:$SkipServer -SkipMoba:$SkipMoba -SkipXshell:$SkipXshell `
    -TargetSelector $targetSelector -PasswordPrompter $pwPrompter -ConfirmPrompter $confirmer

if($null -eq $report){ exit 1 }

Write-Host ""
Write-Host "=========================== 报告 ===========================" -ForegroundColor Cyan
$report | Format-Table @{L='Server';E={$_.Ip}}, @{L='Port';E={$_.Port}}, @{L='User';E={$_.User}}, @{L='免密登录';E={ if($_.KeyAuth){'OK'}else{'FAILED'} }} -AutoSize
Write-Host "提示: MobaXterm 重新打开后, 会话将自动优先使用私钥登录;"
Write-Host "      Xshell 会话位于会话面板, 双击即免密连接 (Xagent 需保持运行)."
Write-Host "===========================================================" -ForegroundColor Cyan
$failed = @($report | Where-Object { -not $_.KeyAuth })
exit $(if($failed.Count -gt 0){ 2 } else { 0 })
