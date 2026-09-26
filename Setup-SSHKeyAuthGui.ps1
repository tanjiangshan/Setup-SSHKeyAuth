#Requires -Version 5.1
<#
.SYNOPSIS
  SSH 免密登录配置工具 - 图形界面入口 (WinForms, 零依赖)

.DESCRIPTION
  两个功能:
    [一键配置免密登录]   发现目标 -> 提取凭据 -> 部署公钥 -> 配置 MobaXterm/Xshell -> 验证
    [一键生成账号密码文档] 汇总本机所有 SSH 连接/会话的 IP/用户名/密码, 导出 Markdown 表格
  建议通过 启动工具.bat 双击运行 (自动带 -STA 与执行策略参数)
#>
$ErrorActionPreference = 'Continue'

# ---- STA 自检: WinForms 需要 STA, 否则用 -STA 重启自身 ----
if([Threading.Thread]::CurrentThread.ApartmentState -ne [Threading.ApartmentState]::STA){
    Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File', ('"{0}"' -f $PSCommandPath))
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
. (Join-Path $PSScriptRoot 'Setup-SSHKeyAuthCore.ps1')

# ---- 与后台 Runspace 共享的同步对象 ----
$script:Sync = [hashtable]::Synchronized(@{})
$script:Sync['LogQueue'] = [System.Collections.Queue]::Synchronized((New-Object System.Collections.Queue))
$script:Sync['Busy'] = $false
$script:Sync['Done'] = $false
$script:Sync['Action'] = $null
$script:Sync['Report'] = $null
$script:Sync['Inventory'] = $null
$script:BgPs = $null
$script:BgRs = $null
$script:BgHandle = $null

function AppendLog([string]$level, [string]$msg){
    $color = switch($level){
        'OK'     { [System.Drawing.Color]::MediumSpringGreen }
        'WARN'   { [System.Drawing.Color]::Khaki }
        'ERR'    { [System.Drawing.Color]::Salmon }
        'BANNER' { [System.Drawing.Color]::DeepSkyBlue }
        'DIM'    { [System.Drawing.Color]::DimGray }
        default  { [System.Drawing.Color]::Gainsboro }
    }
    $script:LogBox.SelectionStart = $script:LogBox.TextLength
    $script:LogBox.SelectionLength = 0
    $script:LogBox.SelectionColor = $color
    $script:LogBox.AppendText($msg + "`r`n")
    $script:LogBox.ScrollToCaret()
}

function Set-BusyUi([bool]$busy, [string]$statusText){
    $script:BtnSetup.Enabled = -not $busy
    $script:BtnDoc.Enabled = -not $busy
    $script:Status.Text = $statusText
    [System.Windows.Forms.Application]::DoEvents()
}

function Stop-BgAction{
    try{ if($script:BgPs){ $script:BgPs.Stop() } } catch { }
    try{
        if($script:BgPs -and $script:BgHandle){
            $null = $script:BgPs.EndInvoke($script:BgHandle)
        }
    } catch { }
    try{ if($script:BgPs){ $script:BgPs.Dispose() } } catch { }
    try{ if($script:BgRs){ $script:BgRs.Dispose() } } catch { }
    $script:BgPs = $null; $script:BgRs = $null; $script:BgHandle = $null
}

function Start-BgAction([string]$action, [scriptblock]$body, [object[]]$arguments){
    if($script:Sync.Busy){ return }
    $script:Sync.Busy = $true
    $script:Sync.Done = $false
    $script:Sync.Action = $action
    $script:Sync.Report = $null
    $script:Sync.Inventory = $null
    $script:LogBox.Clear()
    Set-BusyUi $true '运行中 ...'
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions = 'ReuseThread'
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('Sync', $script:Sync)
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($body.ToString())
    foreach($a in $arguments){ [void]$ps.AddArgument($a) }
    $script:BgPs = $ps
    $script:BgRs = $rs
    $script:BgHandle = $ps.BeginInvoke()
}

function Finish-Action{
    # 收尾: 停止后台, 恢复界面, 处理结果
    Stop-BgAction
    $script:Sync.Busy = $false
    if($script:Sync.Action -eq 'setup'){
        $report = $script:Sync.Report
        Banner ''
        Banner '=========================== 报告 ==========================='
        if($report){
            foreach($r in $report){
                $mark = if($r.KeyAuth){ 'OK' } else { 'FAILED' }
                AppendLog $(if($r.KeyAuth){'OK'}else{'ERR'}) ("  {0,-16} port={1,-5} user={2,-10} 免密登录: {3}" -f $r.Ip, $r.Port, $r.User, $mark)
            }
            $failed = @($report | Where-Object { -not $_.KeyAuth })
            Info '提示: MobaXterm 重新打开后, 会话将自动优先使用私钥登录;'
            Info '      Xshell 会话位于会话面板, 双击即免密连接 (Xagent 需保持运行).'
            if($failed.Count -eq 0){ Set-BusyUi $false '完成: 全部目标免密登录配置成功'; AppendLog 'OK' '  全部目标配置成功' }
            else { Set-BusyUi $false "完成: $(@($report).Count - $failed.Count)/$(@($report).Count) 成功, $($failed.Count) 台失败"; AppendLog 'ERR' "  $($failed.Count) 台失败: $(($failed | ForEach-Object { $_.Ip }) -join ', ')" }
        } else {
            Set-BusyUi $false '结束 (未产生报告, 详见日志)'
        }
    }
    elseif($script:Sync.Action -eq 'doc'){
        $inv = $script:Sync.Inventory
        if(-not $inv -or $inv.Count -eq 0){
            AppendLog 'ERR' '  未发现任何 SSH 连接或本地会话'
            Set-BusyUi $false '完成: 未发现数据'
            return
        }
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Title = '保存 SSH 凭据文档'
        $sfd.Filter = 'Markdown 文档 (*.md)|*.md|所有文件 (*.*)|*.*'
        $sfd.FileName = "SSH连接凭据_$(Get-Date -Format yyyyMMdd-HHmmss).md"
        if($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){
            try{
                Export-CredentialMarkdown $inv $sfd.FileName | Out-Null
                AppendLog 'OK' "  凭据文档已生成: $($sfd.FileName)"
                AppendLog 'WARN' '  文档含明文密码, 请妥善保管, 严禁上传到仓库/网盘!'
                Set-BusyUi $false '完成: 凭据文档已生成'
                Start-Process explorer.exe -ArgumentList "/select,`"$($sfd.FileName)`""
            } catch {
                AppendLog 'ERR' "  文档生成失败: $($_.Exception.Message)"
                Set-BusyUi $false '失败'
            }
        } else {
            AppendLog 'WARN' '  已取消保存'
            Set-BusyUi $false '已取消'
        }
    }
}

# ---- 后台任务体 -----------------------------------------------------------

# 功能一: 一键配置免密登录 (GUI 弹窗交互)
$script:SetupBody = {
    param($CorePath, $Sync, $TargetIps, $UserName, $SkipServer, $SkipMoba, $SkipXshell, $ForceCloseMoba)
    try{
        . $CorePath
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        Set-LogSink { param($level,$msg) $Sync.LogQueue.Enqueue(@($level,$msg)) }

        # 目标选择对话框 (在后台线程上弹窗)
        $selector = {
            param($candidates)
            $f = New-Object System.Windows.Forms.Form
            $f.Text = '选择目标服务器'
            $f.Size = New-Object System.Drawing.Size(440, 400)
            $f.StartPosition = 'CenterScreen'
            $f.FormBorderStyle = 'FixedDialog'
            $f.MaximizeBox = $false
            $f.TopMost = $true
            $lbl = New-Object System.Windows.Forms.Label
            $lbl.Text = '勾选要配置免密登录的服务器:'
            $lbl.Location = New-Object System.Drawing.Point(14, 12)
            $lbl.AutoSize = $true
            $clb = New-Object System.Windows.Forms.CheckedListBox
            $clb.Location = New-Object System.Drawing.Point(14, 40)
            $clb.Size = New-Object System.Drawing.Size(396, 250)
            $clb.CheckOnClick = $true
            $clb.HorizontalScrollbar = $true
            $ips = @()
            foreach($c in $candidates){
                $ips += $c.Ip
                [void]$clb.Items.Add(('{0}    ({1})' -f $c.Ip, $c.Tool), $true)
            }
            $btnAll = New-Object System.Windows.Forms.Button
            $btnAll.Text = '全选'
            $btnAll.Location = New-Object System.Drawing.Point(14, 304)
            $btnAll.Size = New-Object System.Drawing.Size(70, 30)
            $btnAll.Add_Click({ for($i=0; $i -lt $clb.Items.Count; $i++){ $clb.SetItemChecked($i, $true) } }.GetNewClosure())
            $btnNone = New-Object System.Windows.Forms.Button
            $btnNone.Text = '全不选'
            $btnNone.Location = New-Object System.Drawing.Point(90, 304)
            $btnNone.Size = New-Object System.Drawing.Size(70, 30)
            $btnNone.Add_Click({ for($i=0; $i -lt $clb.Items.Count; $i++){ $clb.SetItemChecked($i, $false) } }.GetNewClosure())
            $btnOk = New-Object System.Windows.Forms.Button
            $btnOk.Text = '确定'
            $btnOk.Location = New-Object System.Drawing.Point(250, 304)
            $btnOk.Size = New-Object System.Drawing.Size(75, 30)
            $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $btnCancel = New-Object System.Windows.Forms.Button
            $btnCancel.Text = '取消'
            $btnCancel.Location = New-Object System.Drawing.Point(335, 304)
            $btnCancel.Size = New-Object System.Drawing.Size(75, 30)
            $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            $f.AcceptButton = $btnOk
            $f.CancelButton = $btnCancel
            $f.Controls.AddRange(@($lbl, $clb, $btnAll, $btnNone, $btnOk, $btnCancel))
            if($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){
                $sel = @($clb.CheckedIndices | ForEach-Object { $ips[[int]$_] })
                return $sel
            }
            return @()
        }

        # 密码输入对话框 (密钥未授权且存储密码解不开时)
        $pwPrompter = {
            param($ip, $user)
            $f = New-Object System.Windows.Forms.Form
            $f.Text = '输入密码'
            $f.Size = New-Object System.Drawing.Size(420, 170)
            $f.StartPosition = 'CenterScreen'
            $f.FormBorderStyle = 'FixedDialog'
            $f.MaximizeBox = $false
            $f.TopMost = $true
            $lbl = New-Object System.Windows.Forms.Label
            $lbl.Text = "输入 $user@$ip 的密码以部署公钥:"
            $lbl.Location = New-Object System.Drawing.Point(14, 14)
            $lbl.AutoSize = $true
            $tb = New-Object System.Windows.Forms.TextBox
            $tb.Location = New-Object System.Drawing.Point(14, 44)
            $tb.Size = New-Object System.Drawing.Size(376, 24)
            $tb.UseSystemPasswordChar = $true
            $btnOk = New-Object System.Windows.Forms.Button
            $btnOk.Text = '确定'
            $btnOk.Location = New-Object System.Drawing.Point(220, 88)
            $btnOk.Size = New-Object System.Drawing.Size(80, 30)
            $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $btnCancel = New-Object System.Windows.Forms.Button
            $btnCancel.Text = '跳过'
            $btnCancel.Location = New-Object System.Drawing.Point(310, 88)
            $btnCancel.Size = New-Object System.Drawing.Size(80, 30)
            $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            $f.AcceptButton = $btnOk
            $f.CancelButton = $btnCancel
            $f.Controls.AddRange(@($lbl, $tb, $btnOk, $btnCancel))
            if($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK -and $tb.Text){ return $tb.Text }
            return $null
        }

        # 确认对话框
        $confirmer = {
            param($message)
            return ([System.Windows.Forms.MessageBox]::Show($message, '确认', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question) -eq [System.Windows.Forms.DialogResult]::Yes)
        }

        $report = Invoke-PasswordlessSetup -TargetIps $TargetIps -UserName $UserName `
            -SkipServer:$SkipServer -SkipMoba:$SkipMoba -SkipXshell:$SkipXshell `
            -ForceCloseMoba $ForceCloseMoba `
            -TargetSelector $selector -PasswordPrompter $pwPrompter -ConfirmPrompter $confirmer
        $Sync.Report = $report
    } catch {
        $Sync.LogQueue.Enqueue(@('ERR', "unhandled error: $($_.Exception.Message)"))
    } finally {
        $Sync.Done = $true
    }
}

# 功能二: 生成凭据清单 (无交互)
$script:DocBody = {
    param($CorePath, $Sync)
    try{
        . $CorePath
        Set-LogSink { param($level,$msg) $Sync.LogQueue.Enqueue(@($level,$msg)) }
        $inv = Get-SshCredentialInventory
        $Sync.Inventory = $inv
    } catch {
        $Sync.LogQueue.Enqueue(@('ERR', "unhandled error: $($_.Exception.Message)"))
    } finally {
        $Sync.Done = $true
    }
}

# ---- 界面 -----------------------------------------------------------------

$script:Form = New-Object System.Windows.Forms.Form
$script:Form.Text = 'SSH 免密登录配置工具'
$script:Form.Size = New-Object System.Drawing.Size(780, 600)
$script:Form.StartPosition = 'CenterScreen'
$script:Form.FormBorderStyle = 'FixedSingle'
$script:Form.MaximizeBox = $false
$script:Form.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 9)
$script:Form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font

$script:BtnSetup = New-Object System.Windows.Forms.Button
$script:BtnSetup.Text = '一键配置免密登录'
$script:BtnSetup.Location = New-Object System.Drawing.Point(20, 20)
$script:BtnSetup.Size = New-Object System.Drawing.Size(352, 64)
$script:BtnSetup.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 11, [System.Drawing.FontStyle]::Bold)
$script:BtnSetup.BackColor = [System.Drawing.Color]::FromArgb(46, 134, 87)
$script:BtnSetup.ForeColor = [System.Drawing.Color]::White
$script:BtnSetup.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:BtnSetup.Add_Click({
    Start-BgAction 'setup' $script:SetupBody @(
        (Join-Path $PSScriptRoot 'Setup-SSHKeyAuthCore.ps1'), $script:Sync,
        $null,                # TargetIps
        $null,                # UserName
        $script:ChkSkipServer.Checked, $script:ChkSkipMoba.Checked, $script:ChkSkipXshell.Checked,
        $false                # ForceCloseMoba (弹窗确认)
    )
})

$script:BtnDoc = New-Object System.Windows.Forms.Button
$script:BtnDoc.Text = '一键生成账号密码文档'
$script:BtnDoc.Location = New-Object System.Drawing.Point(392, 20)
$script:BtnDoc.Size = New-Object System.Drawing.Size(352, 64)
$script:BtnDoc.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 11, [System.Drawing.FontStyle]::Bold)
$script:BtnDoc.BackColor = [System.Drawing.Color]::FromArgb(51, 108, 168)
$script:BtnDoc.ForeColor = [System.Drawing.Color]::White
$script:BtnDoc.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:BtnDoc.Add_Click({
    Start-BgAction 'doc' $script:DocBody @(
        (Join-Path $PSScriptRoot 'Setup-SSHKeyAuthCore.ps1'), $script:Sync
    )
})

$grp = New-Object System.Windows.Forms.GroupBox
$grp.Text = '选项 (仅对"配置免密登录"生效)'
$grp.Location = New-Object System.Drawing.Point(20, 96)
$grp.Size = New-Object System.Drawing.Size(724, 56)
$script:ChkSkipServer = New-Object System.Windows.Forms.CheckBox
$script:ChkSkipServer.Text = '跳过服务器端部署'
$script:ChkSkipServer.Location = New-Object System.Drawing.Point(12, 22)
$script:ChkSkipServer.AutoSize = $true
$script:ChkSkipMoba = New-Object System.Windows.Forms.CheckBox
$script:ChkSkipMoba.Text = '跳过 MobaXterm 配置'
$script:ChkSkipMoba.Location = New-Object System.Drawing.Point(170, 22)
$script:ChkSkipMoba.AutoSize = $true
$script:ChkSkipXshell = New-Object System.Windows.Forms.CheckBox
$script:ChkSkipXshell.Text = '跳过 Xshell 配置'
$script:ChkSkipXshell.Location = New-Object System.Drawing.Point(330, 22)
$script:ChkSkipXshell.AutoSize = $true
$grp.Controls.AddRange(@($script:ChkSkipServer, $script:ChkSkipMoba, $script:ChkSkipXshell))

$script:LogBox = New-Object System.Windows.Forms.RichTextBox
$script:LogBox.Location = New-Object System.Drawing.Point(20, 164)
$script:LogBox.Size = New-Object System.Drawing.Size(724, 352)
$script:LogBox.ReadOnly = $true
$script:LogBox.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:LogBox.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 28)
$script:LogBox.ForeColor = [System.Drawing.Color]::Gainsboro
$script:LogBox.DetectUrls = $false

$statusStrip = New-Object System.Windows.Forms.StatusStrip
$script:Status = New-Object System.Windows.Forms.ToolStripStatusLabel
$script:Status.Text = '就绪'
$script:Status.Spring = $true
$script:Status.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
[void]$statusStrip.Items.Add($script:Status)

$script:Form.Controls.AddRange(@($script:BtnSetup, $script:BtnDoc, $grp, $script:LogBox, $statusStrip))

# 关闭确认 (任务运行中)
$script:Form.Add_FormClosing({
    param($s, $e)
    if($script:Sync.Busy){
        $r = [System.Windows.Forms.MessageBox]::Show('任务正在运行, 确定退出吗?', '确认', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if($r -ne [System.Windows.Forms.DialogResult]::Yes){ $e.Cancel = $true; return }
        try{ if($script:BgPs){ $script:BgPs.Stop() } } catch { }
    }
})

# 轮询定时器: 消费日志队列 + 完成检测
# 注意: 不能在 tick 回调里直接 ShowDialog (FileDialog 会死锁),
#       用 BeginInvoke 把收尾工作投递到正常消息循环上下文执行
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 200
$timer.Add_Tick({
    while($script:Sync.LogQueue.Count -gt 0){
        $it = $script:Sync.LogQueue.Dequeue()
        AppendLog $it[0] $it[1]
    }
    if($script:Sync.Busy -and $script:Sync.Done){
        $script:Sync.Busy = $false
        $script:Form.BeginInvoke([Action]{ Finish-Action })
    }
})
$timer.Start()

AppendLog 'BANNER' 'SSH 免密登录配置工具 已就绪'
AppendLog 'DIM'     '  [一键配置免密登录]  发现目标 -> 提取凭据 -> 部署公钥 -> 配置客户端'
AppendLog 'DIM'     '  [一键生成账号密码文档] 汇总本机 SSH 连接/会话的 IP / 用户名 / 密码'
AppendLog 'DIM'     '  密码来自客户端本地加密存储; MobaXterm v25+ 新格式暂无法自动解密, 会在文档中标注'

[void]$script:Form.ShowDialog()
$timer.Stop()
Stop-BgAction
