#Requires -Version 5.1
<#
.SYNOPSIS
  Setup-SSHKeyAuth 核心函数库 (被 CLI / GUI 入口点源使用, 也可单独点源二次开发)

.DESCRIPTION
  - 日志: Info/Ok/Warn/Err/Banner/Dim, 默认输出到控制台; GUI 可用 Set-LogSink 重定向
  - 发现: Get-ActiveSshTargets / Find-MobaConfig / Read-MobaSessions / Get-XshellStoredPasswords
  - 解密: ConvertFrom-XshellPassword (Xshell5-8) / ConvertFrom-MobaPasswordV24 / ConvertFrom-MobaPasswordLegacy
  - 密钥: Ensure-SshKey / Test-KeyAuth / Install-PubKey (askpass)
  - 客户端配置: Update-MobaIni / New-NssshPri / New-XshellSessionFile / Ensure-Xagent
  - 主流程: Invoke-PasswordlessSetup (交互点参数化为回调, CLI/GUI 共用)
  - 凭据清单: Get-SshCredentialInventory / Export-CredentialMarkdown
#>

$ErrorActionPreference = 'Continue'

# ================================================================ 日志 ======
$script:LogSink = $null
function Set-LogSink([scriptblock]$sink){ $script:LogSink = $sink }
function Info($m)  { if($script:LogSink){ & $script:LogSink 'INFO' $m } else { Write-Host "[..] $m" -ForegroundColor Gray } }
function Ok($m)    { if($script:LogSink){ & $script:LogSink 'OK' $m }   else { Write-Host "[OK] $m" -ForegroundColor Green } }
function Warn($m)  { if($script:LogSink){ & $script:LogSink 'WARN' $m } else { Write-Host "[!!] $m" -ForegroundColor Yellow } }
function Err($m)   { if($script:LogSink){ & $script:LogSink 'ERR' $m }  else { Write-Host "[XX] $m" -ForegroundColor Red } }
function Banner($m){ if($script:LogSink){ & $script:LogSink 'BANNER' $m } else { Write-Host $m -ForegroundColor Cyan } }
function Dim($m)   { if($script:LogSink){ & $script:LogSink 'DIM' $m }  else { Write-Host "      $m" -ForegroundColor DarkGray } }

function Read-IniFile([string]$Path){
    $map = [ordered]@{}
    $section = ''
    foreach($line in ((Get-IniText $Path).Text -split "`r?`n")){
        if($line -match '^\s*\[(.+)\]\s*$'){ $section = $Matches[1]; if(-not $map.Contains($section)){ $map[$section] = [ordered]@{} }; continue }
        if($line -match '^([^=]+?)=(.*)$'){
            $k = $Matches[1]; $v = $Matches[2]
            if(-not $map.Contains($section)){ $map[$section] = [ordered]@{} }
            $map[$section][$k] = $v
        }
    }
    return $map
}

# =========================================================== 1. 发现目标 ===
function Get-ActiveSshTargets{
    $targets = @{}
    $procs = @{}
    foreach($p in (Get-Process -ErrorAction SilentlyContinue)){
        if($p.Name -like 'MobaXterm*' -or $p.Name -eq 'MoTTY'){ $procs[$p.Id] = 'MobaXterm' }
        elseif($p.Name -like 'Xshell*'){ $procs[$p.Id] = 'Xshell' }
        elseif($p.Name -eq 'putty'){ $procs[$p.Id] = 'PuTTY' }
    }
    foreach($c in (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -eq 22 })){
        $tool = $procs[[int]$c.OwningProcess]
        if($tool){
            if(-not $targets.ContainsKey($c.RemoteAddress)){ $targets[$c.RemoteAddress] = $tool }
        }
    }
    return $targets
}

# ==================================================== 2. MobaXterm 会话 ====
# 读取 INI 为文本, 自动探测编码 (UTF-8 BOM / UTF-16 LE / 严格 UTF-8 / ANSI), 写回时保持原编码
function Get-IniText([string]$Path){
    $bytes = [IO.File]::ReadAllBytes($Path)
    if($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF){
        $enc = New-Object System.Text.UTF8Encoding($true)
        $text = $enc.GetString($bytes)
        if($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF){ $text = $text.Substring(1) }
        return @{ Text = $text; Encoding = $enc }
    }
    if($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE){
        $enc = [Text.Encoding]::Unicode
        return @{ Text = $enc.GetString($bytes, 2, $bytes.Length - 2); Encoding = $enc }
    }
    try{
        $strict = New-Object System.Text.UTF8Encoding($false, $true)
        $text = $strict.GetString($bytes)
        return @{ Text = $text; Encoding = (New-Object System.Text.UTF8Encoding($false)) }
    } catch {
        $enc = [Text.Encoding]::Default
        return @{ Text = $enc.GetString($bytes); Encoding = $enc }
    }
}

# 私钥绝对路径 -> MobaXterm 书签使用的形式 (%USERPROFILE% 下相对化为 _ProfileDir_\...)
function ConvertTo-MobaKeyPath([string]$Path){
    if(-not $Path){ return $Path }
    if($Path -like '_ProfileDir_*'){ return $Path }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    $full = [IO.Path]::GetFullPath($expanded).Replace('/','\')
    $up = $env:USERPROFILE.TrimEnd('\')
    if($full.StartsWith($up, [StringComparison]::OrdinalIgnoreCase)){
        return '_ProfileDir_\' + $full.Substring($up.Length).TrimStart('\')
    }
    return $full
}

# 记住上次成功定位的 MobaXterm.ini 路径 (注册表), 便携版主进程未运行时仍可找到
function Save-LastMobaIni([string]$Path){
    try{
        $rk = 'HKCU:\Software\Setup-SSHKeyAuth'
        if(-not (Test-Path $rk)){ New-Item -Path $rk -Force | Out-Null }
        Set-ItemProperty -Path $rk -Name 'LastMobaIni' -Value $Path
    } catch { }
}

# 定位 MobaXterm 配置源: 便携版/INI 模式返回 @{Type='ini';Path=...}
# 安装版(注册表模式, 会话存于 HKCU\Software\Mobatek\MobaXterm\S)返回 @{Type='registry';RegBase='HKCU\Software\Mobatek\MobaXterm'}
function Find-MobaConfig([scriptblock]$Prompter){
    # 1) 正在运行的 MobaXterm 进程所在目录 (便携版)
    $p = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MobaXterm*' } | Select-Object -First 1
    if($p -and $p.Path){
        $ini = Join-Path (Split-Path $p.Path) 'MobaXterm.ini'
        if(Test-Path $ini){ Save-LastMobaIni $ini; return @{ Type = 'ini'; Path = $ini } }
    }
    # 1.5) 开始菜单 / 桌面的 MobaXterm 快捷方式指向的目录
    try{
        $sh = New-Object -ComObject WScript.Shell
        $lnkDirs = @(
            (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'),
            (Join-Path $env:USERPROFILE 'Desktop'),
            'C:\Users\Public\Desktop'
        )
        foreach($d in $lnkDirs){
            foreach($lnk in (Get-ChildItem $d -Recurse -Filter '*.lnk' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'MobaXterm' })){
                $t = $sh.CreateShortcut($lnk.FullName).TargetPath
                if($t){
                    $ini = Join-Path (Split-Path $t -Parent) 'MobaXterm.ini'
                    if(Test-Path $ini){ Save-LastMobaIni $ini; return @{ Type = 'ini'; Path = $ini } }
                }
            }
        }
    } catch { }
    # 2) 上次成功定位的 INI 路径 (缓存; 便携版主进程关闭后仍有效)
    $cached = $null
    try{ $cached = (Get-ItemProperty 'HKCU:\Software\Setup-SSHKeyAuth' -Name 'LastMobaIni' -ErrorAction SilentlyContinue).LastMobaIni } catch { }
    if($cached -and (Test-Path $cached)){ return @{ Type = 'ini'; Path = $cached } }
    # 3) 安装版 INI 模式默认位置 (用户在设置中选择了使用 INI 文件)
    $ini = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'MobaXterm\MobaXterm.ini'
    if(Test-Path $ini){ Save-LastMobaIni $ini; return @{ Type = 'ini'; Path = $ini } }
    # 4) 安装版注册表模式: 会话存于 HKCU\Software\Mobatek\MobaXterm\S
    #    (便携版运行过也会写顶层 SessionP, 但会话不在注册表, 故以 S 键有 SSH 会话值为判据)
    if(Test-MobaRegistrySessions){
        return @{ Type = 'registry'; RegBase = 'HKCU\Software\Mobatek\MobaXterm' }
    }
    # 5) 浅层扫描常见根目录 (两层深度, 找 *MobaXterm* 目录)
    $roots = @([Environment]::GetFolderPath('Desktop'), (Join-Path $env:USERPROFILE 'Downloads'), 'C:\', 'D:\', 'E:\')
    foreach($root in $roots){
        if(-not $root -or -not (Test-Path $root)){ continue }
        foreach($d1 in (Get-ChildItem $root -Directory -ErrorAction SilentlyContinue)){
            if($d1.Name -like '*MobaXterm*'){
                $ini = Join-Path $d1.FullName 'MobaXterm.ini'
                if(Test-Path $ini){ Save-LastMobaIni $ini; return @{ Type = 'ini'; Path = $ini } }
            }
            foreach($d2 in (Get-ChildItem $d1.FullName -Directory -ErrorAction SilentlyContinue)){
                if($d2.Name -like '*MobaXterm*'){
                    $ini = Join-Path $d2.FullName 'MobaXterm.ini'
                    if(Test-Path $ini){ Save-LastMobaIni $ini; return @{ Type = 'ini'; Path = $ini } }
                }
            }
        }
    }
    # 6) 兜底: 提示用户指定 INI (回调返回路径或 null)
    if($Prompter){
        $ans = & $Prompter
        if($ans -and (Test-Path $ans)){ Save-LastMobaIni $ans; return @{ Type = 'ini'; Path = $ans } }
    }
    return $null
}

# 安装版注册表模式: S 键存在且含至少一个 SSH 会话值 (#109# 前缀)
function Test-MobaRegistrySessions{
    try{
        $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Mobatek\MobaXterm\S')
        if(-not $sk){ return $false }
        foreach($vn in $sk.GetValueNames()){
            $v = [string]$sk.GetValue($vn)
            if($v -and ($v.Trim() -split '%')[0] -match '^#109#\d+$'){ $sk.Close(); return $true }
        }
        $sk.Close()
        return $false
    } catch { return $false }
}

# 注册表模式工具: 打开子键 (可写)
function Open-MobaRegKey([string]$SubKey, [bool]$Writable = $false){
    $path = 'Software\Mobatek\MobaXterm'
    if($SubKey){ $path = "$path\$SubKey" }
    if($Writable){ return [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($path) }
    return [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($path)
}

# 注册表模式备份: 导出整个 MobaXterm 键为 .reg 文件
function Backup-MobaRegistry{
    try{
        $dir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'MobaXterm'
        if(-not (Test-Path $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $regFile = Join-Path $dir "MobaXterm-registry-backup-$(Get-Date -Format yyyyMMdd-HHmmss).reg"
        $null = & reg.exe export 'HKCU\Software\Mobatek\MobaXterm' "$regFile" /y 2>&1
        if(Test-Path $regFile){ Ok "MobaXterm registry backed up -> $regFile"; return $true }
    } catch { }
    Warn "MobaXterm registry backup failed (continuing without backup)"
    return $false
}

# 解析 MobaXterm SSH 会话 (书签):
#   INI 模式:     [Bookmarks*] 段的 "名称=#109#0%host%port%user%...%keyPath%..." 行
#   注册表模式:   HKCU\Software\Mobatek\MobaXterm\S 键的值 (值名=会话名, 值=同格式串)
# $Source: Find-MobaConfig 返回的对象; 也兼容直接传 INI 路径字符串
function Read-MobaSessions($Source){
    $result = @()
    if(-not $Source){ return $result }
    # 兼容: 直接传 INI 路径字符串
    if($Source -is [string]){ $Source = @{ Type = 'ini'; Path = $Source } }
    if($Source.Type -eq 'registry'){
        $sk = Open-MobaRegKey 'S'
        if($sk){
            foreach($vn in $sk.GetValueNames()){
                $v = [string]$sk.GetValue($vn)
                $f = $v.Trim() -split '%'
                if($f.Count -gt 14 -and $f[0] -match '^#109#\d+$'){
                    $result += [pscustomobject]@{
                        Name = $vn; Host = $f[1]; Port = $f[2]; Login = $f[3]
                        KeyPath = $f[14]; Source = 'registry'; IniPath = "$($Source.RegBase)\S"; LineNo = -1
                    }
                }
            }
            $sk.Close()
        }
        return $result
    }
    # INI 模式
    $lines = (Get-IniText $Source.Path).Text -split "`r?`n"
    $section = ''
    for($i=0; $i -lt $lines.Count; $i++){
        $line = $lines[$i]
        if($line -match '^\s*\[(.+)\]\s*$'){ $section = $Matches[1]; continue }
        if($section -like 'Bookmarks*' -and $line -match '^([^=]+)=(.*)$'){
            $name = $Matches[1]; $val = $Matches[2]
            if($name -in @('SubRep','ImgNum')){ continue }
            $f = ($val.Trim()) -split '%'
            if($f.Count -gt 14 -and $f[0] -match '^#109#\d+$'){
                $result += [pscustomobject]@{
                    Name = $name; Host = $f[1]; Port = $f[2]; Login = $f[3]
                    KeyPath = $f[14]; Source = 'ini'; Section = $section; IniPath = $Source.Path; LineNo = $i
                }
            }
        }
    }
    return $result
}

# 获取 MobaXterm 数据映射 (供密码解密用), 结构与 Read-IniFile 相同:
#   INI 模式:     [Misc]/[Sesspass]/[Credentials]/[Passwords] 各段
#   注册表模式:   顶层值 SessionP -> Misc; M/Sesspass, C/Credentials, P/Passwords 子键
function Get-MobaDataMap($Source){
    if($Source -is [string]){ $Source = @{ Type = 'ini'; Path = $Source } }
    if($Source -and $Source.Type -eq 'registry'){
        $base = Open-MobaRegKey $null
        $map = [ordered]@{}
        $map['Misc'] = [ordered]@{ SessionP = [string]$base.GetValue('SessionP') }
        $map['Sesspass'] = [ordered]@{}
        $map['Credentials'] = [ordered]@{}
        $map['Passwords'] = [ordered]@{}
        foreach($pair in @(@('M','Sesspass'), @('C','Credentials'), @('P','Passwords'))){
            $k = $base.OpenSubKey($pair[0])
            if($k){
                foreach($vn in $k.GetValueNames()){ $map[$pair[1]][$vn] = [string]$k.GetValue($vn) }
                $k.Close()
            }
        }
        $base.Close()
        return $map
    }
    if($Source -and $Source.Path){ return Read-IniFile $Source.Path }
    return $null
}

# ============================================ 3. 密码解密 (尽力而为) ========
function Get-Rc4([byte[]]$data, [byte[]]$key){
    $s = New-Object int[] 256; $j = 0
    for($i=0; $i -lt 256; $i++){ $s[$i] = $i }
    for($i=0; $i -lt 256; $i++){ $j = ($j + $key[$i % $key.Length] + $s[$i]) -band 255; $t = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $t }
    $i = 0; $j = 0
    $out = New-Object byte[] $data.Length
    for($k=0; $k -lt $data.Length; $k++){
        $i = ($i + 1) -band 255; $j = ($j + $s[$i]) -band 255
        $t = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $t
        $out[$k] = $data[$k] -bxor $s[($s[$i] + $s[$j]) -band 255]
    }
    return ,$out
}

function ConvertFrom-XshellPassword([string]$B64){
    try{
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        [byte[]]$data = [Convert]::FromBase64String(($B64 -replace '\s',''))
        if($data.Length -le 32){ return $null }
        [byte[]]$ct = $data[0..($data.Length-33)]
        [byte[]]$mac = $data[($data.Length-32)..($data.Length-1)]
        $sha = [Security.Cryptography.SHA256]::Create()
        $winUser = $env:USERNAME
        $sid = ([Security.Principal.WindowsIdentity]::GetCurrent().User).Value
        $rev = -join ($sid.ToCharArray()[($sid.Length-1)..0])
        $keyCands = @(
            $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($rev + $winUser)),                # v7/8
            $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($winUser + $sid)),                # v5.3-6
            $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($sid)),                           # v5.1-5.2
            [Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes('!X@s#h$e%l^l&'))  # v5.0-
        )
        foreach($kc in $keyCands){
            $pt = Get-Rc4 $ct $kc
            # verify: SHA256(plain) == trailing 32 bytes
            $h = $sha.ComputeHash($pt)
            $match = $true
            for($k=0; $k -lt 32; $k++){ if($h[$k] -ne $mac[$k]){ $match = $false; break } }
            if($match){ return [Text.Encoding]::UTF8.GetString($pt) }
        }
        return $null
    } catch { return $null }
}

# MobaXterm v22-24: [Sesspass] DPAPI blob -> AES-256-CFB8
function ConvertFrom-MobaPasswordV24([string]$CipherText, [hashtable]$Ini){
    try{
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        if(-not $Ini['Misc'] -or -not $Ini['Sesspass']){ return $null }
        $sessionP = $Ini['Misc']['SessionP']; if(-not $sessionP){ return $null }
        $upn = "$env:USERNAME@$env:COMPUTERNAME"
        $sv = $Ini['Sesspass'][$upn]; if(-not $sv){ return $null }
        $header = [byte[]](0x01,0,0,0,0xD0,0x8C,0x9D,0xDF,0x01,0x15,0xD1,0x11,0x8C,0x7A,0,0xC0,0x4F,0xC2,0x97,0xEB)
        [byte[]]$body = [Convert]::FromBase64String($sv)
        $full = New-Object byte[] (20 + $body.Length)
        [Array]::Copy($header,0,$full,0,20); [Array]::Copy($body,0,$full,20,$body.Length)
        $temp = [Security.Cryptography.ProtectedData]::Unprotect($full, [Text.Encoding]::UTF8.GetBytes($sessionP), 'CurrentUser')
        [byte[]]$keyMat = [Convert]::FromBase64String([Text.Encoding]::UTF8.GetString($temp))
        if($keyMat.Length -lt 32){ return $null }
        [byte[]]$key = $keyMat[0..31]
        $ecb = [Security.Cryptography.Aes]::Create(); $ecb.Mode = 'ECB'; $ecb.Padding = 'PKCS7'; $ecb.KeySize = 256; $ecb.Key = $key
        [byte[]]$iv = ($ecb.CreateEncryptor().TransformFinalBlock((New-Object byte[] 16),0,16))[0..15]
        $ct = $CipherText -replace '^_@',''
        $ct = ($ct -replace '[^A-Za-z0-9+/]','')
        $pad = (4 - ($ct.Length % 4)) % 4
        [byte[]]$cipher = [Convert]::FromBase64String($ct + ('=' * $pad))
        # AES-256-CFB8 (standard, ciphertext feedback)
        $e2 = [Security.Cryptography.Aes]::Create(); $e2.Mode = 'ECB'; $e2.Padding = 'None'; $e2.KeySize = 256; $e2.Key = $key
        $et = $e2.CreateEncryptor()
        $reg = New-Object byte[] 16; [Array]::Copy($iv,0,$reg,0,16)
        $out = New-Object byte[] $cipher.Length
        for($k=0; $k -lt $cipher.Length; $k++){
            $ks = $et.TransformFinalBlock($reg,0,16)
            $out[$k] = $cipher[$k] -bxor $ks[0]
            [Array]::Copy($reg,1,$reg,0,15); $reg[15] = $cipher[$k]
        }
        $s = [Text.Encoding]::UTF8.GetString($out).Trim([char]0)
        # CFB8 解密永远"成功", 必须校验明文可打印, 否则视为解密失败 (v25+ 密文用旧算法会得到乱码)
        if([string]::IsNullOrEmpty($s) -or $s -match '[\x00-\x1F\x7F]' -or $s.Contains([string][char]0xFFFD)){ return $null }
        return $s
    } catch { return $null }
}

# MobaXterm 旧版 (无 Sesspass, 静态查表算法)
function ConvertFrom-MobaPasswordLegacy([string]$CipherText, [string]$SessionP){
    try{
        if(-not $SessionP){ return $null }
        $s1 = $SessionP
        while($s1.Length -lt 20){ $s1 = $s1 + $s1 }
        $s1 = $s1.Substring(0,20)
        $keySpace = @($s1.ToUpper(), $s1.ToLower())
        [byte[]]$key = [Text.Encoding]::UTF8.GetBytes('0d5e9n1348/U2+67')
        $valid = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'
        for($i=0; $i -lt 16; $i++){
            $ch = $keySpace[($i+1) % 2][$i % 20]
            $kb = [byte][char]$ch
            $already = $false; foreach($x in $key){ if($x -eq $kb){ $already = $true; break } }
            if(-not $already -and $valid.Contains([string]$ch)){ $key[$i] = $kb }
        }
        $keySet = @{}; foreach($x in $key){ $keySet[$x] = $true }
        [System.Collections.Generic.List[byte]]$ct = New-Object 'System.Collections.Generic.List[byte]'
        foreach($b in [Text.Encoding]::ASCII.GetBytes($CipherText)){ if($keySet.ContainsKey($b)){ $ct.Add($b) } }
        if($ct.Count % 2 -ne 0){ return $null }
        $sb = New-Object Text.StringBuilder
        for($i=0; $i -lt $ct.Count; $i += 2){
            $l = [Array]::IndexOf($key, $ct[$i])
            $key = ,($key[15]) + $key[0..14]
            $h = [Array]::IndexOf($key, $ct[$i+1])
            $key = ,($key[15]) + $key[0..14]
            if($l -lt 0 -or $h -lt 0){ return $null }
            [void]$sb.Append([char](16*$h + $l))
        }
        $s = $sb.ToString()
        # 校验明文可打印, 排除错误密文解出的乱码
        if([string]::IsNullOrEmpty($s) -or $s -match '[\x00-\x1F\x7F]'){ return $null }
        return $s
    } catch { return $null }
}

# MobaXterm 密码统一入口: 依次尝试 v24 / 旧版; 返回 @{ Password=..; Status='decrypted'|'undecryptable'|'failed'|'none' }
function ConvertFrom-MobaPassword([string]$CipherText, [hashtable]$Ini){
    $r = @{ Password = $null; Status = 'none' }
    if(-not $CipherText){ $r.Status = 'none'; return $r }
    $pw = ConvertFrom-MobaPasswordV24 $CipherText $Ini
    # 旧版查表算法只适用于旧格式密文; _@ 前缀是 v25+ 新格式, 走旧算法必错且可能碰巧产出可打印乱码
    if(-not $pw -and $CipherText -notmatch '^_@' -and $Ini['Misc'] -and $Ini['Misc']['SessionP']){
        $pw = ConvertFrom-MobaPasswordLegacy $CipherText $Ini['Misc']['SessionP']
    }
    if($pw){ $r.Password = $pw; $r.Status = 'decrypted' }
    elseif($CipherText -match '^_@'){ $r.Status = 'undecryptable' }
    else { $r.Status = 'failed' }
    return $r
}

# Xshell 会话密码集合
function Get-XshellStoredPasswords{
    $result = @{}
    $udPath = $null
    foreach($v in 9,8,7,6){
        $udPath = (Get-ItemProperty "HKCU:\Software\NetSarang\Common\$v\UserData" -ErrorAction SilentlyContinue).UserDataPath
        if($udPath){ break }
    }
    if(-not $udPath){ $udPath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'NetSarang Computer' }
    foreach($dir in @((Join-Path $udPath 'Xshell\Sessions'), (Join-Path $udPath 'Xshell5\Sessions'))){
        if(-not (Test-Path $dir)){ continue }
        foreach($f in (Get-ChildItem $dir -Recurse -Include *.xshf,*.xsh -File -ErrorAction SilentlyContinue)){
            try{
                $bytes = [IO.File]::ReadAllBytes($f.FullName)
                $text = $null
                if($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE){ $text = [Text.Encoding]::Unicode.GetString($bytes,2,$bytes.Length-2) }
                elseif($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF){ $text = [Text.Encoding]::UTF8.GetString($bytes,3,$bytes.Length-3) }
                else { $text = [Text.Encoding]::Default.GetString($bytes) }
                $host_ = $null; $port = 22; $user_ = $null; $pw = $null
                foreach($line in ($text -split "`r?`n")){
                    if($line -match '^Host=(.+)$'){ $host_ = $Matches[1].Trim() }
                    elseif($line -match '^Port=(\d+)'){ $port = [int]$Matches[1] }
                    elseif($line -match '^UserName=(.*)$'){ $user_ = $Matches[1].Trim() }
                    elseif($line -match '^Password=(.+)$'){ $pw = $Matches[1].Trim() }
                }
                # 只要有 Host 即收录; UserName 可为空 (后续默认 root 或连接时输入)
                if($host_){
                    $result["$host_`:$port"] = [pscustomobject]@{ User = $user_; EncPassword = $pw; Path = $f.FullName }
                }
            } catch { }
        }
    }
    return $result
}

# ======================================================= 4. 密钥管理 =======
# $PrivateKey 指定则使用该私钥 (需无口令); 否则复用/生成 %USERPROFILE%\.ssh\id_ed25519
function Ensure-SshKey([string]$PrivateKey){
    if($PrivateKey){
        if(-not (Test-Path -LiteralPath $PrivateKey)){ Err "private key not found: $PrivateKey"; return $null }
        $priv = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($PrivateKey))
        $pub  = "$priv.pub"
        if(-not (Test-Path -LiteralPath $pub)){
            try{ & ssh-keygen -y -f $priv 2>$null | Set-Content -Path $pub -Encoding ascii } catch { }
        }
        if(-not (Test-Path -LiteralPath $pub)){ Err "cannot derive public key for: $priv"; return $null }
        $pubLine = (Get-Content -LiteralPath $pub | Where-Object { $_ -match '^(ssh-|ecdsa-)' } | Select-Object -First 1).Trim()
        if(-not $pubLine){ Err "cannot read public key: $pub"; return $null }
        Info "using specified private key: $priv"
        return [pscustomobject]@{ Pri = $priv; Pub = $pub; PubLine = $pubLine }
    }
    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if(-not (Test-Path $sshDir)){ New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }
    $priv = Join-Path $sshDir 'id_ed25519'
    $pub  = "$priv.pub"
    if(-not (Test-Path $priv)){
        Info "generate new ed25519 key pair: $priv"
        & ssh-keygen -t ed25519 -f $priv -N '""' -C "$env:USERNAME@${env:COMPUTERNAME}" -q
        if($LASTEXITCODE -ne 0 -or -not (Test-Path $priv)){ Err "ssh-keygen failed"; return $null }
    }
    if(-not (Test-Path $pub)){
        & ssh-keygen -y -f $priv | Set-Content -Path $pub -Encoding ascii
    }
    $pubLine = (Get-Content $pub | Where-Object { $_ -match '^(ssh-|ecdsa-)' } | Select-Object -First 1).Trim()
    if(-not $pubLine){ Err "cannot read public key"; return $null }
    return [pscustomobject]@{ Pri = $priv; Pub = $pub; PubLine = $pubLine }
}

function Test-KeyAuth([string]$Ip, [int]$Port, [string]$User, [string]$PrivKey){
    try{
        $args = @('-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=accept-new','-p',"$Port")
        if($PrivKey){ $args += @('-i',$PrivKey) }
        $args += @("$User@$Ip", 'echo __KEY_OK__')
        $out = & ssh @args 2>&1 | Out-String
        return ($out -match '__KEY_OK__')
    } catch { return $false }
}

# askpass: 用密码自动执行 ssh (OpenSSH >= 8.4)
function Invoke-SshWithPassword([string]$Ip,[int]$Port,[string]$User,[string]$Password,[string]$Command){
    try{
        $dir = Join-Path $env:TEMP ("ssh-askpass-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $dir 'pw.dat'), $Password, (New-Object System.Text.UTF8Encoding $false))
        $cmdFile = Join-Path $dir 'askpass.cmd'
        @("@echo off`r`npowershell -NoProfile -Command `"[Console]::Out.Write([IO.File]::ReadAllText('%~dp0pw.dat'))`"`r`n") | Set-Content -Path $cmdFile -Encoding ascii
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'ssh.exe'
        $psi.Arguments = "-o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new -o NumberOfPasswordPrompts=1 -o ConnectTimeout=8 -p $Port $User@$Ip `"$Command`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.EnvironmentVariables['SSH_ASKPASS'] = $cmdFile
        $psi.EnvironmentVariables['SSH_ASKPASS_REQUIRE'] = 'force'
        $psi.EnvironmentVariables['DISPLAY'] = '1'
        $p = [System.Diagnostics.Process]::Start($psi)
        $so = $p.StandardOutput.ReadToEnd()
        $se = $p.StandardError.ReadToEnd()
        $p.WaitForExit(30000) | Out-Null
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        return [pscustomobject]@{ ExitCode = $p.ExitCode; Output = $so; Error = $se }
    } catch { return [pscustomobject]@{ ExitCode = -1; Output = ''; Error = $_.Exception.Message } }
}

function Install-PubKey([string]$Ip,[int]$Port,[string]$User,[string]$Password,[string]$PubLine){
    if($PubLine -notmatch '^[A-Za-z0-9@+\/. \-]+$'){ Err "public key line contains unsafe characters"; return $false }
    # remote command deliberately contains NO quotes (ssh re-joins argv with spaces)
    $b64 = ($PubLine -split ' ')[1]
    $cmd = "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; grep -q $b64 ~/.ssh/authorized_keys || echo $PubLine >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; echo __INSTALL_OK__"
    $r = Invoke-SshWithPassword $Ip $Port $User $Password $cmd
    return ($r.Output -match '__INSTALL_OK__')
}

# ============================================= 5. MobaXterm INI 配置 =======
<#
.SYNOPSIS
  将目标 SSH 会话书签的私钥字段指向指定私钥, 并同步 [Misc] LastSession.
  - 编码探测与保留 (UTF-8 BOM / UTF-16 LE / UTF-8 / ANSI)
  - 变更前备份; 写入后回读校验
  - $PrivateKey 为私钥绝对路径, %USERPROFILE% 下自动相对化为 _ProfileDir_\... 形式
#>
function Update-MobaIni([object[]]$Sessions, [string]$PrivateKey){
    $iniPath = $Sessions[0].IniPath
    $mobaKey = ConvertTo-MobaKeyPath $PrivateKey
    $bak = "$iniPath.toolbak-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item $iniPath $bak -Force
    Ok "MobaXterm.ini backed up -> $bak"

    $data = Get-IniText $iniPath
    $sep = if($data.Text.IndexOf("`r`n") -ge 0){ "`r`n" } else { "`n" }
    $lines = $data.Text -split "`r?`n"
    $targetNames = @{}
    foreach($s in $Sessions){ $targetNames[$s.Name] = $true }

    $section = ''
    $changed = 0
    for($i=0; $i -lt $lines.Count; $i++){
        $line = $lines[$i]
        if($line -match '^\s*\[(.+?)\]\s*$'){ $section = $Matches[1]; continue }
        # 1) [Bookmarks*] 段中的目标会话行
        if($section -like 'Bookmarks*' -and $line -match '^([^=]+)=(.*)$'){
            $name = $Matches[1]
            if($name -in @('SubRep','ImgNum')){ continue }
            if(-not $targetNames.Contains($name)){ continue }
            $val = $Matches[2]
            $prefix = if($val -match '^\s'){ ' ' } else { '' }
            $f = ($val.Trim()) -split '%'
            if($f.Count -le 14){ continue }
            if($f[0] -notmatch '^#109#\d+$'){ continue }
            if($f[14] -ceq $mobaKey){ continue }
            $oldKey = $f[14]; if(-not $oldKey){ $oldKey = '<none>' }
            $f[14] = $mobaKey
            $lines[$i] = $name + '=' + $prefix + ($f -join '%')
            $changed++
            Dim ("  -> {0}  key: {1} => {2}" -f $name, $oldKey, $mobaKey)
        }
        # 2) [Misc] LastSession 同步 (MobaXterm 启动时自动重开的会话)
        elseif($line -match '^LastSession=(.+?)\|(#109#\d+%.*)$'){
            $lsName = $Matches[1]; $lsStr = $Matches[2]
            if($targetNames.Contains($lsName)){
                $f = $lsStr -split '%'
                if($f.Count -gt 14 -and $f[14] -cne $mobaKey){
                    $f[14] = $mobaKey
                    $lines[$i] = 'LastSession=' + $lsName + '|' + ($f -join '%')
                    Dim "  -> LastSession ($lsName) synced"
                }
            }
        }
    }
    if($changed -gt 0){
        [IO.File]::WriteAllText($iniPath, ($lines -join $sep), $data.Encoding)
        # 回读校验
        $verify = Get-IniText $iniPath
        $ok = 0
        foreach($vl in ($verify.Text -split "`r?`n")){
            if($vl -match '^[^=]+=\s*#109#\d+%'){
                $vp = (($vl -split '=',2)[1].Trim()) -split '%'
                if($vp.Count -gt 14 -and $vp[14] -ceq $mobaKey){ $ok++ }
            }
        }
        Ok "MobaXterm.ini updated ($changed session(s) -> private key: $mobaKey; verify read-back: $ok session line(s) OK)"
    } else {
        Info "MobaXterm.ini: all target sessions already configured"
    }
    return $changed
}

# 从 MobaXterm 书签中删除指定主机的 SSH 会话 (需 MobaXterm 未运行; 备份后原编码写回)
function Remove-MobaBookmarks([string]$IniPath, [string[]]$Ips){
    if(-not $IniPath -or -not $Ips -or $Ips.Count -eq 0){ return 0 }
    $data = Get-IniText $IniPath
    $sep = if($data.Text.IndexOf("`r`n") -ge 0){ "`r`n" } else { "`n" }
    $lines = $data.Text -split "`r?`n"
    $kept = New-Object System.Collections.Generic.List[string]
    $removedNames = @{}
    $removed = 0
    $section = ''
    foreach($line in $lines){
        if($line -match '^\s*\[(.+?)\]\s*$'){ $section = $Matches[1]; $kept.Add($line); continue }
        if($section -like 'Bookmarks*' -and $line -match '^([^=]+)=(.*)$'){
            $name = $Matches[1]
            if($name -notin @('SubRep','ImgNum')){
                $f = ($Matches[2].Trim()) -split '%'
                if($f.Count -gt 1 -and $f[0] -match '^#109#\d+$' -and $Ips -contains $f[1]){
                    $removed++
                    $removedNames[$name] = $true
                    Dim "  xx $name  (bookmark removed)"
                    continue
                }
            }
        }
        # LastSession 指向已删会话 -> 置空, 避免启动时指向不存在会话
        if($removedNames.Count -gt 0 -and $line -match '^LastSession=(.+?)\|'){
            if($removedNames.Contains($Matches[1])){ $kept.Add('LastSession='); continue }
        }
        $kept.Add($line)
    }
    if($removed -gt 0){
        $bak = "$IniPath.toolbak-$(Get-Date -Format yyyyMMdd-HHmmss)"
        Copy-Item $IniPath $bak -Force
        [IO.File]::WriteAllText($IniPath, ($kept -join $sep), $data.Encoding)
        Ok "MobaXterm.ini: $removed bookmark(s) removed (backup: $bak)"
    }
    return $removed
}

# 为缺失会话的主机创建 MobaXterm SSH 书签 (需 MobaXterm 未运行; 备份后原编码写回)
# $Entries: @{Ip;Port;User} 对象数组
function Add-MobaBookmarks([string]$IniPath, [object[]]$Entries, [string]$PrivateKey){
    if(-not $IniPath -or -not $Entries -or $Entries.Count -eq 0){ return 0 }
    $mobaKey = ConvertTo-MobaKeyPath $PrivateKey
    $data = Get-IniText $IniPath
    $sep = if($data.Text.IndexOf("`r`n") -ge 0){ "`r`n" } else { "`n" }
    $lines = @($data.Text -split "`r?`n")

    # 内置模板 (字段: 0=#109#0 1=host 2=port 3=login ... 14=keypath ... 终端设置)
    $builtinTemplate = '#109#0%192.168.0.1%22%root%%-1%0%%%%%0%-1%0%%%-1%-1%0%0%%1080%%0%0%1%%0%%%%0%-1%-1%0%%%0%#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1'
    # 优先用现有书签行做模板 (保留用户终端配色等设置)
    $template = $builtinTemplate
    $section = ''
    foreach($line in $lines){
        if($line -match '^\s*\[(.+?)\]\s*$'){ $section = $Matches[1]; continue }
        if($section -like 'Bookmarks*' -and $line -match '^[^=]+=(.*)$'){
            $v = $Matches[1].Trim()
            if($v -match '^#109#\d+%'){
                $f = $v -split '%'
                if($f.Count -gt 14){ $template = $v; break }
            }
        }
    }
    $tp = $template -split '%'
    if($tp.Count -le 14){ Err 'internal: invalid bookmark template'; return 0 }

    # 定位插入点: 优先 [Bookmarks] 段, 否则第一个 [Bookmarks*] 段, 都没有则文件末尾追加新段
    $targetSection = $null
    for($i=0; $i -lt $lines.Count; $i++){
        if($lines[$i] -match '^\s*\[(.+?)\]\s*$'){
            $n = $Matches[1]
            if($n -eq 'Bookmarks'){ $targetSection = 'Bookmarks'; break }
            if(-not $targetSection -and $n -like 'Bookmarks*'){ $targetSection = $n }
        }
    }
    $newLines = New-Object System.Collections.Generic.List[string]
    $inserted = 0
    $pending = @()
    foreach($e in $Entries){
        $f = $tp
        $f[1] = "$($e.Ip)"; $f[2] = "$($e.Port)"; $f[3] = "$($e.User)"
        $f[14] = $mobaKey
        $name = "$($e.Ip)"
        if($e.User){ $name = "$($e.Ip) ($($e.User))" }
        $pending += ($name + '=' + ($f -join '%'))
    }
    if(-not $targetSection){
        $newLines.AddRange([string[]]$lines)
        if($newLines.Count -gt 0 -and $newLines[$newLines.Count-1] -ne ''){ $newLines.Add('') }
        $newLines.Add('[Bookmarks]')
        $newLines.Add('SubRep=')
        $newLines.Add('ImgNum=0')
        foreach($p in $pending){ $newLines.Add($p); $inserted++ }
    } else {
        $inTarget = $false
        $section = ''
        for($i=0; $i -lt $lines.Count; $i++){
            $line = $lines[$i]
            if($line -match '^\s*\[(.+?)\]\s*$'){
                # 离开目标段: 在段尾插入待加行
                if($inTarget){
                    foreach($p in $pending){ $newLines.Add($p); $inserted++ }
                    $pending = @()
                    $inTarget = $false
                }
                $section = $Matches[1]
                if($section -eq $targetSection){ $inTarget = $true }
                $newLines.Add($line); continue
            }
            $newLines.Add($line)
        }
        if($inTarget -or $pending.Count -gt 0){
            foreach($p in $pending){ $newLines.Add($p); $inserted++ }
        }
    }
    if($inserted -gt 0){
        $bak = "$IniPath.toolbak-$(Get-Date -Format yyyyMMdd-HHmmss)"
        Copy-Item $IniPath $bak -Force
        [IO.File]::WriteAllText($IniPath, ($newLines -join $sep), $data.Encoding)
        Ok "MobaXterm.ini: $inserted bookmark(s) created in [$targetSection] (backup: $bak)"
    }
    return $inserted
}

# ================================ 5R. MobaXterm 注册表模式 (安装版) =========
# 使用 .NET RegistryKey API (避免 PowerShell 注册表 provider 的 -Name 通配符解析问题,
# 会话名常含 "[...]" 等会被误当作字符类的字符)

# 更新注册表会话的私钥字段 + 同步顶层 LastSession 值
function Update-MobaSessionsRegistry([object[]]$Sessions, [string]$PrivateKey){
    $mobaKey = ConvertTo-MobaKeyPath $PrivateKey
    $changed = 0
    $sk = Open-MobaRegKey 'S' $true
    if(-not $sk){ Err "cannot open MobaXterm registry sessions key"; return 0 }
    foreach($s in $Sessions){
        $v = [string]$sk.GetValue($s.Name)
        if(-not $v){ continue }
        $f = $v.Trim() -split '%'
        if($f.Count -le 14 -or $f[0] -notmatch '^#109#\d+$'){ continue }
        if($f[14] -ceq $mobaKey){ continue }
        $old = $f[14]; if(-not $old){ $old = '<none>' }
        $f[14] = $mobaKey
        $sk.SetValue($s.Name, ($f -join '%'), [Microsoft.Win32.RegistryValueKind]::String)
        $changed++
        Dim ("  -> {0}  key: {1} => {2}" -f $s.Name, $old, $mobaKey)
    }
    $sk.Close()
    # 同步顶层 LastSession (MobaXterm 启动时自动重开的会话)
    $top = Open-MobaRegKey $null $true
    if($top){
        $ls = [string]$top.GetValue('LastSession')
        if($ls -match '^([^|]+)\|(#109#\d+%.*)$'){
            $lsName = $Matches[1]
            foreach($s in $Sessions){
                if($s.Name -ceq $lsName){
                    $f = $Matches[2] -split '%'
                    if($f.Count -gt 14 -and $f[14] -cne $mobaKey){
                        $f[14] = $mobaKey
                        $top.SetValue('LastSession', ($lsName + '|' + ($f -join '%')), [Microsoft.Win32.RegistryValueKind]::String)
                        Dim "  -> LastSession ($lsName) synced"
                    }
                }
            }
        }
        $top.Close()
    }
    if($changed -gt 0){ Ok "MobaXterm registry sessions updated ($changed -> private key: $mobaKey)" }
    else { Info "MobaXterm registry: all target sessions already configured" }
    return $changed
}

# 注册表模式创建缺失会话
function Add-MobaSessionsRegistry([object[]]$Entries, [string]$PrivateKey){
    if(-not $Entries -or $Entries.Count -eq 0){ return 0 }
    $mobaKey = ConvertTo-MobaKeyPath $PrivateKey
    $sk = Open-MobaRegKey 'S' $true
    if(-not $sk){ Err "cannot open MobaXterm registry sessions key"; return 0 }
    # 模板: 优先复用现有会话值 (保留终端设置), 否则内置模板
    $builtinTemplate = '#109#0%192.168.0.1%22%root%%-1%0%%%%%0%-1%0%%%-1%-1%0%0%%1080%%0%0%1%%0%%%%0%-1%-1%0%%%0%#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1'
    $template = $builtinTemplate
    foreach($vn in $sk.GetValueNames()){
        $v = [string]$sk.GetValue($vn)
        $f = $v.Trim() -split '%'
        if($f.Count -gt 14 -and $f[0] -match '^#109#\d+$'){ $template = $v.Trim(); break }
    }
    $tp = $template -split '%'
    if($tp.Count -le 14){ $sk.Close(); Err 'internal: invalid bookmark template'; return 0 }
    $inserted = 0
    foreach($e in $Entries){
        $f = $tp
        $f[1] = "$($e.Ip)"; $f[2] = "$($e.Port)"; $f[3] = "$($e.User)"
        $f[14] = $mobaKey
        $name = "$($e.Ip)"
        if($e.User){ $name = "$($e.Ip) ($($e.User))" }
        $sk.SetValue($name, ($f -join '%'), [Microsoft.Win32.RegistryValueKind]::String)
        $inserted++
        Dim "  ++ new registry session: $($e.Ip):$($e.Port) login=$($e.User)"
    }
    $sk.Close()
    if($inserted -gt 0){ Ok "MobaXterm registry: $inserted session(s) created" }
    return $inserted
}

# 注册表模式删除会话 (含顶层 LastSession 清理)
function Remove-MobaSessionsRegistry([string[]]$Ips){
    if(-not $Ips -or $Ips.Count -eq 0){ return 0 }
    $removed = 0
    $removedNames = @{}
    $sk = Open-MobaRegKey 'S' $true
    if($sk){
        foreach($vn in @($sk.GetValueNames())){
            $v = [string]$sk.GetValue($vn)
            $f = $v.Trim() -split '%'
            if($f.Count -gt 1 -and $f[0] -match '^#109#\d+$' -and $Ips -contains $f[1]){
                $sk.DeleteValue($vn)
                $removed++
                $removedNames[$vn] = $true
                Dim "  xx $vn  (registry session removed)"
            }
        }
        $sk.Close()
    }
    $top = Open-MobaRegKey $null $true
    if($top){
        $ls = [string]$top.GetValue('LastSession')
        if($ls -match '^([^|]+)\|' -and $removedNames.Contains($Matches[1])){
            $top.SetValue('LastSession', '', [Microsoft.Win32.RegistryValueKind]::String)
            Dim "  -> LastSession cleared"
        }
        $top.Close()
    }
    if($removed -gt 0){ Ok "MobaXterm registry: $removed session(s) removed" }
    return $removed
}

# ================================================ 6. Xshell 配置 ==========
# OpenSSH 私钥 -> NSSSH .pri (NetSarang 用户密钥库格式)
function New-NssshPri([string]$OpensshPriv, [string]$OutPath){
    $lines = Get-Content -LiteralPath $OpensshPriv | Where-Object { $_ -notmatch '^-----' -and $_.Trim() -ne '' }
    [byte[]]$data = [Convert]::FromBase64String(($lines -join ''))
    $script:_d = $data; $script:_p = 0
    function RdU32{ $v = ([uint32]$script:_d[$script:_p] -shl 24) -bor ([uint32]$script:_d[$script:_p+1] -shl 16) -bor ([uint32]$script:_d[$script:_p+2] -shl 8) -bor [uint32]$script:_d[$script:_p+3]; $script:_p += 4; $v }
    function RdStr{ $len = RdU32; if($len -eq 0){ return ,[byte[]]@() }; $bb = New-Object byte[] $len; [Array]::Copy($script:_d, $script:_p, $bb, 0, $len); $script:_p += $len; return ,$bb }
    function WU32([uint32]$v){ ,[byte[]]((($v -shr 24) -band 255),(($v -shr 16) -band 255),(($v -shr 8) -band 255),($v -band 255)) }
    function WS([byte[]]$bb){ ,[byte[]]((WU32 ([uint32]$bb.Length)) + $bb) }

    $magic = [Text.Encoding]::ASCII.GetString($data[0..13])
    if($magic -ne 'openssh-key-v1'){ throw "not openssh new-format key" }
    $script:_p = 15
    $cipher = [Text.Encoding]::ASCII.GetString((RdStr))
    $kdf = [Text.Encoding]::ASCII.GetString((RdStr))
    $null = RdStr                       # kdfoptions
    $null = RdU32                       # numkeys
    [byte[]]$pubblob = RdStr
    [byte[]]$privsec = RdStr
    if($cipher -ne 'none' -or $kdf -ne 'none'){ throw "encrypted private key not supported" }

    $script:_d = $privsec; $script:_p = 8     # skip checkints
    $keytype = [Text.Encoding]::ASCII.GetString((RdStr))
    $check = [byte[]](0x5A,0xA5,0x5A,0xA5)
    $fields = @(); $keynum = 0; $typeStr = ''
    if($keytype -eq 'ssh-ed25519'){
        $null = RdStr                    # pk
        [byte[]]$sk = RdStr              # seed+pub
        [byte[]]$commentB = RdStr
        $keynum = 2; $typeStr = 'ssh-ed25519'
        $bodyLen = 8 + 4 + $sk.Length + 4 + $commentB.Length
        $padLen = (8 - ($bodyLen % 8)) % 8
        $fields = @((WS $sk), (WS $commentB))
    }
    elseif($keytype -eq 'ssh-rsa'){
        [byte[]]$n = RdStr; [byte[]]$e = RdStr; [byte[]]$d = RdStr; [byte[]]$iqmp = RdStr; [byte[]]$pp = RdStr; [byte[]]$qq = RdStr
        [byte[]]$commentB = RdStr
        $keynum = 1; $typeStr = 'ssh-rsa'
        $bodyLen = 8 + (4+$n.Length)+(4+$e.Length)+(4+$d.Length)+(4+$iqmp.Length)+(4+$pp.Length)+(4+$qq.Length)+(4+$commentB.Length)
        $padLen = (8 - ($bodyLen % 8)) % 8
        $fields = @((WS $n),(WS $e),(WS $d),(WS $iqmp),(WS $pp),(WS $qq),(WS $commentB))
    }
    else { throw "unsupported key type: $keytype" }
    $pad = New-Object byte[] $padLen; for($i=0; $i -lt $padLen; $i++){ $pad[$i] = $i+1 }
    $comment = [Text.Encoding]::UTF8.GetString($commentB)

    [byte[]]$privNew = $check + $check
    foreach($f in $fields){ $privNew = [byte[]]($privNew + $f) }
    $privNew = [byte[]]($privNew + $pad)
    [byte[]]$inner = $pubblob + [Text.Encoding]::ASCII.GetBytes('nsssh-key-v6') + [byte[]]@(0) +
        (WS ([Text.Encoding]::ASCII.GetBytes('none'))) + (WS ([Text.Encoding]::ASCII.GetBytes('none'))) +
        (WS ([byte[]]@())) + (WU32 1) + (WS $privNew)
    $b64 = [Convert]::ToBase64String($inner)
    $sb = New-Object Text.StringBuilder
    for($i=0; $i -lt $b64.Length; $i+=60){ [void]$sb.Append($b64.Substring($i, [Math]::Min(60, $b64.Length-$i))).Append("`r`n") }
    $content = "---- BEGIN NSSSH PRIVATE KEY ----`r`nComment: $comment`r`nKey: $keynum, $typeStr`r`n" + $sb.ToString() + "---- END NSSSH PRIVATE KEY ----`r`n"
    [IO.File]::WriteAllText($OutPath, $content, (New-Object System.Text.UTF8Encoding $false))
    return $typeStr
}

function Get-XshellDirs{
    $udPath = $null
    foreach($v in 9,8,7,6){
        $udPath = (Get-ItemProperty "HKCU:\Software\NetSarang\Common\$v\UserData" -ErrorAction SilentlyContinue).UserDataPath
        if($udPath){ break }
    }
    if(-not $udPath){
        $guess = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'NetSarang Computer\8'
        if(Test-Path (Join-Path $guess 'Xshell')){ $udPath = $guess }
    }
    if(-not $udPath){ return $null }
    return [pscustomobject]@{
        UserData = $udPath
        Sessions = Join-Path $udPath 'Xshell\Sessions'
        UserKeys = Join-Path $udPath 'SECSH\UserKeys'
    }
}

function New-XshellSessionFile([string]$Ip,[int]$Port,[string]$User,[string]$KeyName,[string]$SessionsDir){
    if(-not (Test-Path $SessionsDir)){ New-Item -ItemType Directory -Path $SessionsDir -Force | Out-Null }
    $template = Join-Path $SessionsDir 'default.xshf'
    $text = $null
    if(Test-Path $template){
        $bytes = [IO.File]::ReadAllBytes($template)
        if($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE){ $text = [Text.Encoding]::Unicode.GetString($bytes,2,$bytes.Length-2) }
        else { $text = [Text.Encoding]::UTF8.GetString($bytes) }
    } else {
        $text = "[CONNECTION:PROXY]`r`nProxy=`r`nStartUp=0`r`n[SessionInfo]`r`nVersion=8.1`r`n[CONNECTION:SSH]`r`n`r`n[CONNECTION]`r`nPort=22`r`nHost=`r`nProtocol=SSH`r`n[CONNECTION:AUTHENTICATION]`r`nAuthMethodList=10`r`nUserKey=`r`nUserName=`r`n"
    }
    $text = [regex]::Replace($text, '(?m)^Host=.*$', "Host=$Ip")
    $text = [regex]::Replace($text, '(?m)^Port=.*$', "Port=$Port")
    $text = [regex]::Replace($text, '(?m)^UserName=.*$', "UserName=$User")
    $text = [regex]::Replace($text, '(?m)^UserKey=.*$', "UserKey=$KeyName")
    $text = [regex]::Replace($text, '(?m)^AuthMethodList=.*$', 'AuthMethodList=10')
    $dst = Join-Path $SessionsDir "$Ip.xshf"
    [IO.File]::WriteAllText($dst, $text, [Text.Encoding]::Unicode)
    return $dst
}

function Ensure-Xagent{
    if(Get-Process Xagent -ErrorAction SilentlyContinue){ return $true }
    $cands = @()
    $xs = Get-Process Xshell -ErrorAction SilentlyContinue | Select-Object -First 1
    if($xs -and $xs.Path){ $cands += (Join-Path (Split-Path $xs.Path) 'Xagent.exe') }
    $cands += 'C:\Program Files (x86)\NetSarang\Xshell 8\Xagent.exe','C:\Program Files\NetSarang\Xshell 8\Xagent.exe'
    $cands += (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Xshell*' -and $_.InstallLocation } | ForEach-Object { Join-Path $_.InstallLocation 'Xagent.exe' })
    foreach($c in $cands){
        if($c -and (Test-Path $c)){
            Start-Process $c | Out-Null
            Start-Sleep -Seconds 3
            if(Get-Process Xagent -ErrorAction SilentlyContinue){ Ok "Xagent started: $c"; return $true }
        }
    }
    return $false
}

# ============================================ 7. 主流程 (CLI/GUI 共用) =====
<#
.SYNOPSIS
  免密登录配置主流程。交互点通过回调注入:
    -TargetSelector    param($candidates) -> string[]   候选为 @{Ip;Tool} 对象数组
    -PasswordPrompter  param($ip,$user) -> string|null
    -ConfirmPrompter   param($message) -> bool
    -MobaIniPrompter   param() -> string|null   自动定位 MobaXterm.ini 失败时让用户指定
  返回报告数组 (无有效目标/密钥失败时返回 $null)
#>
function Invoke-PasswordlessSetup{
    [CmdletBinding()]
    param(
        [string[]]$TargetIps,
        [string]$UserName,
        [switch]$All,
        [bool]$ForceCloseMoba = $false,
        [switch]$SkipServer,
        [switch]$SkipMoba,
        [switch]$SkipXshell,
        [string]$PrivateKey,
        [scriptblock]$TargetSelector,
        [scriptblock]$PasswordPrompter,
        [scriptblock]$ConfirmPrompter,
        [scriptblock]$MobaIniPrompter
    )

    Banner ""
    Banner "======== SSH 免密登录一键配置 (MobaXterm + Xshell) ========"
    Banner ""

    # --- 1. 发现 ---
    Info "scanning established SSH connections ..."
    $active = Get-ActiveSshTargets
    if($active.Count -gt 0){
        foreach($ip in $active.Keys){ Dim "active: $ip  (client: $($active[$ip]))" }
    } else {
        Warn "no established SSH connection found from MobaXterm/Xshell"
    }
    $mobaSource = Find-MobaConfig $MobaIniPrompter
    $mobaSessions = @()
    $mobaIniMap = $null
    if($mobaSource){
        if($mobaSource.Type -eq 'registry'){ Info "MobaXterm config: registry ($($mobaSource.RegBase)) [installed edition]" }
        else { Info "MobaXterm config: $($mobaSource.Path)" }
        $mobaSessions = Read-MobaSessions $mobaSource
        $mobaIniMap = Get-MobaDataMap $mobaSource
        foreach($s in $mobaSessions){ Dim "moba session: $($s.Host):$($s.Port)  login=$($s.Login)  key=$($s.KeyPath)" }
    } elseif(-not $SkipMoba){
        Warn "MobaXterm config not found (neither .ini nor registry) - MobaXterm sessions/credentials skipped"
    }
    Info "scanning Xshell sessions ..."
    $xshPw = Get-XshellStoredPasswords
    foreach($k in $xshPw.Keys){ Dim "xshell session: $k  user=$($xshPw[$k].User)" }

    # --- 2. 目标选择 ---
    # 候选 = 活跃连接 + MobaXterm 存储会话 + Xshell 存储会话 (未连接的也列出, 标注状态)
    $chosenIps = @()
    if($TargetIps){ $chosenIps = $TargetIps }
    else {
        $candMap = [ordered]@{}
        foreach($ip in $active.Keys){
            if(-not $candMap.Contains($ip)){ $candMap[$ip] = [pscustomobject]@{ Ip = $ip; Tool = $active[$ip]; Connected = $true } }
        }
        foreach($s in $mobaSessions){
            if($s.Host -and -not $candMap.Contains($s.Host)){ $candMap[$s.Host] = [pscustomobject]@{ Ip = $s.Host; Tool = 'MobaXterm'; Connected = $false } }
        }
        foreach($k in $xshPw.Keys){
            $ip = ($k -split ':')[0]
            if($ip -and -not $candMap.Contains($ip)){ $candMap[$ip] = [pscustomobject]@{ Ip = $ip; Tool = 'Xshell'; Connected = $false } }
        }
        $candidates = @($candMap.Values | Sort-Object -Property @{Expression={-not $_.Connected}}, @{Expression={$_.Ip}})
        if($candidates.Count -eq 0){ Err "no target found. use -Ip <addr> or open connections first"; return $null }
        if($All -or -not $TargetSelector){
            $chosenIps = @($candidates | ForEach-Object { $_.Ip })
            if($active.Count -eq 0){ Warn "no active connection; will process all stored sessions: $($chosenIps -join ', ')" }
        } else {
            $chosenIps = @(& $TargetSelector $candidates)
        }
    }
    $chosenIps = @($chosenIps | Where-Object { $_ -and $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Sort-Object -Unique)
    if(-not $chosenIps){ Err "no valid target IP"; return $null }
    Banner ""
    Ok "targets: $($chosenIps -join ', ')"

    # --- 3. 密钥 ---
    $key = Ensure-SshKey $PrivateKey
    if(-not $key){ return $null }
    Ok "private key: $($key.Pri)"
    Info "public  key: $($key.PubLine.Substring(0,40))..."

    # --- 4. 逐台处理 ---
    $report = @()
    $removeIps = @()
    foreach($ip in $chosenIps){
        Banner ""
        Banner "---- $ip ----"
        $moba = $mobaSessions | Where-Object { $_.Host -eq $ip } | Select-Object -First 1
        $port = 22
        if($moba -and $moba.Port){ $port = [int]$moba.Port }
        $user = $UserName
        if(-not $user -and $moba -and $moba.Login -and $moba.Login -notmatch '^\['){ $user = $moba.Login }
        if(-not $user -and $xshPw.ContainsKey("$ip`:$port")){ $user = $xshPw["$ip`:$port"].User }
        if(-not $user){ $user = 'root' }
        Info "user=$user port=$port"

        # 密码(尽力)
        $password = $null
        if($xshPw.ContainsKey("$ip`:$port") -and $xshPw["$ip`:$port"].EncPassword){
            $password = ConvertFrom-XshellPassword $xshPw["$ip`:$port"].EncPassword
            if($password){ Ok "Xshell stored password decrypted" } else { Info "Xshell password decrypt failed (unknown version?)" }
        }
        if(-not $password -and $mobaIniMap){
            $ct = $null
            if($moba -and $moba.Login -match '^\[(.+)\]$'){
                $credName = $Matches[1]
                if($mobaIniMap['Credentials'] -and $mobaIniMap['Credentials'][$credName]){ $ct = $mobaIniMap['Credentials'][$credName] }
            }
            if($ct){
                $parts = $ct.Split(':',2)
                if($parts.Count -eq 2){
                    if(-not $user){ $user = $parts[0] }
                    $ctVal = $parts[1]
                    $password = ConvertFrom-MobaPasswordV24 $ctVal $mobaIniMap
                    if(-not $password -and $mobaIniMap['Misc']['SessionP']){ $password = ConvertFrom-MobaPasswordLegacy $ctVal $mobaIniMap['Misc']['SessionP'] }
                    if($password){ Ok "MobaXterm stored password decrypted (legacy/v24 format)" }
                    elseif($ctVal -match '^_@'){ Info "MobaXterm v25+ credential format - not publicly decryptable yet" }
                }
            }
        }

        # 服务器端
        $keyOk = $false
        if(-not $SkipServer){
            $keyOk = Test-KeyAuth $ip $port $user $key.Pri
            if($keyOk){
                Ok "server: public-key auth already works (nothing to do)"
            } else {
                $pwUsed = $false
                if($password){
                    Info "deploying public key with stored password ..."
                    if(Install-PubKey $ip $port $user $password $key.PubLine){ $pwUsed = $true; Ok "public key deployed" }
                    else { Warn "deploy with stored password failed" }
                }
                if(-not $pwUsed){
                    $ans = $null
                    if($PasswordPrompter){ $ans = & $PasswordPrompter $ip $user }
                    else { $ans = Read-Host "  input password for $user@$ip to deploy key (Enter = skip)" }
                    if($ans -eq '__REMOVE_SESSION__'){
                        # 用户选择删除该服务器的客户端会话记录 (MobaXterm 书签 + Xshell 会话)
                        Warn "$ip marked for session removal (MobaXterm bookmark + Xshell session)"
                        $removeIps += $ip
                        $report += [pscustomobject]@{ Ip = $ip; Port = $port; User = $user; KeyAuth = $false; Status = 'REMOVED' }
                        continue
                    }
                    if($ans){
                        if(Install-PubKey $ip $port $user $ans $key.PubLine){ $pwUsed = $true; Ok "public key deployed" }
                        else { Err "password auth failed - key NOT deployed" }
                    } else {
                        Warn "skipped server-side deployment"
                    }
                }
                $keyOk = Test-KeyAuth $ip $port $user $key.Pri
                if($keyOk){ Ok "server: public-key auth verified" } else { Err "server: public-key auth still not working" }
            }
        } else { Info "server-side steps skipped"; $keyOk = Test-KeyAuth $ip $port $user $key.Pri }

        $report += [pscustomobject]@{ Ip = $ip; Port = $port; User = $user; KeyAuth = $keyOk; Status = 'DONE' }
    }

    # --- 5. MobaXterm 配置 (更新已有书签 + 删除标记的 + 创建缺失的) ---
    if(-not $SkipMoba -and ($mobaSessions -or $report)){
        Banner ""
        $running = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MobaXterm*' }
        if($running){
            if($ForceCloseMoba){
                Warn "closing MobaXterm (existing sessions will disconnect) ..."
                Stop-Process -Name 'MobaXterm*' -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            } else {
                Warn "MobaXterm is running - it will overwrite MobaXterm.ini on exit."
                $doClose = $false
                if($ConfirmPrompter){ $doClose = [bool](& $ConfirmPrompter 'MobaXterm 正在运行, 需要先关闭才能写入配置 (现有终端会断开). 现在关闭吗?') }
                else {
                    $ans = Read-Host "  close MobaXterm now and update its config? (y/N)"
                    $doClose = ($ans -match '^[Yy]')
                }
                if($doClose){
                    Stop-Process -Name 'MobaXterm*' -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                } else {
                    Warn "MobaXterm config update skipped (run again with -Force later)"
                }
            }
        }
        if(-not (Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MobaXterm*' })){
            $isRegistry = ($mobaSource -and $mobaSource.Type -eq 'registry')
            # 注册表模式: 修改前先导出备份
            if($isRegistry -and ($mobaSessions.Count -gt 0 -or $removeIps.Count -gt 0 -or @($report | Where-Object { $_.Status -ne 'REMOVED' }).Count -gt 0)){
                Backup-MobaRegistry | Out-Null
            }
            # 5a. 更新已有书签的私钥字段 (排除被删除的)
            $targets = @($mobaSessions | Where-Object { $chosenIps -contains $_.Host -and $removeIps -notcontains $_.Host })
            if($targets){
                if($isRegistry){ Update-MobaSessionsRegistry $targets $key.Pri | Out-Null }
                else { Update-MobaIni $targets $key.Pri | Out-Null }
            }
            # 5b. 删除被标记的会话书签
            if($removeIps.Count -gt 0){
                if($isRegistry){ Remove-MobaSessionsRegistry $removeIps | Out-Null }
                else { Remove-MobaBookmarks $mobaSource.Path $removeIps | Out-Null }
            }
            # 5c. 为 MobaXterm 中还没有书签的目标创建书签 (排除被删除的)
            $existingHosts = @($mobaSessions | ForEach-Object { $_.Host }) + @($removeIps)
            $missing = @($report | Where-Object { $_.Status -ne 'REMOVED' -and $existingHosts -notcontains $_.Ip })
            if($missing.Count -gt 0){
                foreach($m in $missing){ Dim "  ++ new session: $($m.Ip):$($m.Port) login=$($m.User)" }
                if($isRegistry){ Add-MobaSessionsRegistry $missing $key.Pri | Out-Null }
                else { Add-MobaBookmarks $mobaSource.Path $missing $key.Pri | Out-Null }
            }
        }
    } elseif(-not $SkipMoba -and -not $mobaSessions) {
        Banner ""
        Info "MobaXterm not detected - skipped"
    }

    # --- 6. Xshell 配置 ---
    if(-not $SkipXshell){
        Banner ""
        $xd = Get-XshellDirs
        if($xd){
            if(-not (Test-Path $xd.UserKeys)){ New-Item -ItemType Directory -Path $xd.UserKeys -Force | Out-Null }
            $priPath = Join-Path $xd.UserKeys 'id_ed25519.pri'
            try{
                $type = New-NssshPri $key.Pri $priPath
                Ok "Xshell user key written: $priPath ($type)"
            } catch { Err "failed to write Xshell user key: $($_.Exception.Message)" }
            $n = 0
            $removedXsh = 0
            foreach($t in $report){
                if($t.Status -eq 'REMOVED'){
                    $xf = Join-Path $xd.Sessions "$($t.Ip).xshf"
                    if(Test-Path $xf){ Remove-Item $xf -Force; $removedXsh++; Dim "  xx $xf removed" }
                } else {
                    $f = New-XshellSessionFile $t.Ip $t.Port $t.User 'id_ed25519' $xd.Sessions
                    $n++
                }
            }
            Ok "Xshell session files written: $n, removed: $removedXsh (in $($xd.Sessions))"
            if(Ensure-Xagent){ Ok "Xagent running (agent-based passwordless auth active)" }
            else { Warn "Xagent not started - start it from Xshell Tools menu for agent auth" }
        } else {
            Info "Xshell not detected - skipped"
        }
    }

    return $report
}

# ============================================ 8. 凭据清单 + MD 导出 ========
<#
.SYNOPSIS
  汇总本机所有 SSH 连接/会话的 IP、用户名、密码(尽力解密), 供生成凭据文档
  返回: @{Ip;Port;User;Password;PasswordStatus;Sources;Connected}[]
    PasswordStatus: decrypted | undecryptable | failed | none
#>
function Get-SshCredentialInventory([scriptblock]$MobaIniPrompter){
    Banner "scanning SSH connections and stored sessions ..."
    $active = Get-ActiveSshTargets
    $mobaSource = Find-MobaConfig $MobaIniPrompter
    $mobaSessions = @(); $mobaIniMap = $null
    if($mobaSource){
        if($mobaSource.Type -eq 'registry'){ Info "MobaXterm config: registry ($($mobaSource.RegBase)) [installed edition]" }
        else { Info "MobaXterm config: $($mobaSource.Path)" }
        $mobaSessions = Read-MobaSessions $mobaSource
        $mobaIniMap = Get-MobaDataMap $mobaSource
    } else {
        Warn "MobaXterm config not found (neither .ini nor registry) - MobaXterm sessions/credentials skipped"
    }
    $xshPw = Get-XshellStoredPasswords
    Info "found: $($active.Count) active connection(s), $($mobaSessions.Count) MobaXterm session(s), $($xshPw.Count) Xshell session(s)"

    $rows = [ordered]@{}     # "ip:port" -> row

    function Get-Row([string]$ip, [int]$port){
        $k = "$ip`:$port"
        if(-not $rows.Contains($k)){
            $rows[$k] = [pscustomobject]@{
                Ip = $ip; Port = $port; User = $null; Password = $null
                PasswordStatus = 'none'; Sources = New-Object System.Collections.Generic.List[string]
                Connected = $false
            }
        }
        return $rows[$k]
    }

    # MobaXterm 书签会话
    foreach($s in $mobaSessions){
        $row = Get-Row $s.Host ([int]($s.Port))
        if(-not $row.Sources.Contains('MobaXterm')){ $row.Sources.Add('MobaXterm') }
        $encPw = $null
        if($s.Login -match '^\[(.+)\]$'){
            # 凭据引用: [name] -> [Credentials] name=user:pass
            $credName = $Matches[1]
            if($mobaIniMap -and $mobaIniMap['Credentials'] -and $mobaIniMap['Credentials'][$credName]){
                $cred = $mobaIniMap['Credentials'][$credName]
                $parts = $cred.Split(':',2)
                if($parts.Count -eq 2){
                    if(-not $row.User){ $row.User = $parts[0] }
                    $encPw = $parts[1]
                }
            }
        } else {
            if(-not $row.User -and $s.Login){ $row.User = $s.Login }
            # 无凭据引用时, 尝试 [Passwords] 段的 user@host 条目
            if($mobaIniMap -and $mobaIniMap['Passwords'] -and $row.User){
                $pk = "$($row.User)@$($s.Host)"
                if($mobaIniMap['Passwords'].Contains($pk)){ $encPw = $mobaIniMap['Passwords'][$pk] }
            }
        }
        if($encPw -and -not $row.Password -and $row.PasswordStatus -ne 'decrypted'){
            $r = ConvertFrom-MobaPassword $encPw $mobaIniMap
            if($r.Status -eq 'decrypted'){ $row.Password = $r.Password; $row.PasswordStatus = 'decrypted' }
            elseif($row.PasswordStatus -eq 'none'){ $row.PasswordStatus = $r.Status }
        }
    }

    # MobaXterm [Passwords] 段 (user@host, 可能存在独立于书签的条目)
    if($mobaIniMap -and $mobaIniMap['Passwords']){
        foreach($k in @($mobaIniMap['Passwords'].Keys)){
            $encPw = $mobaIniMap['Passwords'][$k]
            $keyPart = "$k"
            if($keyPart -match '^(?:[a-z0-9]+:)?([^@]+)@(.+)$'){
                $pwUser = $Matches[1]; $pwHost = $Matches[2]
                # 合并到已有同 host 行, 否则新建
                $existing = @($rows.Values | Where-Object { $_.Ip -eq $pwHost })
                $row = if($existing){ ($existing | Where-Object { -not $_.User -or $_.User -eq $pwUser } | Select-Object -First 1) } else { $null }
                if(-not $row){ $row = Get-Row $pwHost 22 }
                if(-not $row.User){ $row.User = $pwUser }
                if(-not $row.Sources.Contains('MobaXterm')){ $row.Sources.Add('MobaXterm') }
                if($encPw -and -not $row.Password -and $row.PasswordStatus -ne 'decrypted'){
                    $r = ConvertFrom-MobaPassword $encPw $mobaIniMap
                    if($r.Status -eq 'decrypted'){ $row.Password = $r.Password; $row.PasswordStatus = 'decrypted' }
                    elseif($row.PasswordStatus -eq 'none'){ $row.PasswordStatus = $r.Status }
                }
            }
        }
    }

    # Xshell 会话
    foreach($k in @($xshPw.Keys)){
        $ip = ($k -split ':')[0]; $port = 22
        if($k -match '^(.+):(\d+)$'){ $ip = $Matches[1]; $port = [int]$Matches[2] }
        $row = Get-Row $ip $port
        if(-not $row.Sources.Contains('Xshell')){ $row.Sources.Add('Xshell') }
        if(-not $row.User){ $row.User = $xshPw[$k].User }
        if($xshPw[$k].EncPassword -and -not $row.Password -and $row.PasswordStatus -ne 'decrypted'){
            $pw = ConvertFrom-XshellPassword $xshPw[$k].EncPassword
            if($pw){ $row.Password = $pw; $row.PasswordStatus = 'decrypted' }
            elseif($row.PasswordStatus -eq 'none'){ $row.PasswordStatus = 'failed' }
        }
    }

    # 活跃连接标记 (已连接但无会话记录的也建行)
    foreach($ip in $active.Keys){
        $existing = @($rows.Values | Where-Object { $_.Ip -eq $ip })
        if($existing){ foreach($r in $existing){ $r.Connected = $true; if(-not $r.Sources.Contains($active[$ip])){ $r.Sources.Add($active[$ip]) } } }
        else {
            $row = Get-Row $ip 22
            $row.Connected = $true
            $row.Sources.Add($active[$ip])
        }
    }

    $list = @($rows.Values | Sort-Object -Property @{Expression={-not $_.Connected}}, @{Expression={$_.Ip}})
    $dec = @($list | Where-Object { $_.PasswordStatus -eq 'decrypted' }).Count
    Info "inventory: $($list.Count) host(s), $dec password(s) decrypted"
    return $list
}

function Export-CredentialMarkdown([object[]]$Inventory, [string]$Path){
    function Esc([string]$s){ if($null -eq $s){ return '' } else { return ($s -replace '\|','\|') } }
    $dec = @($Inventory | Where-Object { $_.PasswordStatus -eq 'decrypted' }).Count
    $conn = @($Inventory | Where-Object { $_.Connected }).Count
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# SSH 连接凭据')
    $lines.Add('')
    $lines.Add("- 生成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add('- 生成工具: Setup-SSHKeyAuth (数据来源: 本机 SSH 客户端的连接与会话存储)')
    $lines.Add("- 共 **$($Inventory.Count)** 台主机, 已解密密码 **$dec** 个, 当前已连接 **$conn** 台")
    $lines.Add('')
    $lines.Add('> **安全警告: 本文件包含明文密码, 请妥善保管!**')
    $lines.Add('> 严禁提交到代码仓库 / 网盘 / 聊天工具; 建议存放在加密分区或密码管理器中, 用完即删。')
    $lines.Add('')
    $lines.Add('| IP | 端口 | 用户名 | 密码 | 来源 | 状态 |')
    $lines.Add('|----|------|--------|------|------|------|')
    foreach($r in $Inventory){
        $pwCell = '-'
        switch($r.PasswordStatus){
            'decrypted'     { $pwCell = '`' + (Esc $r.Password) + '`' }
            'undecryptable' { $pwCell = '⚠ 无法自动解密 (MobaXterm v25+ 新格式)' }
            'failed'        { $pwCell = '⚠ 解密失败' }
            default         { $pwCell = '- (未存储)' }
        }
        $src = ($r.Sources -join ' / ')
        $st = if($r.Connected){ '已连接' } else { '未连接' }
        $lines.Add('| ' + (Esc $r.Ip) + ' | ' + $r.Port + ' | ' + (Esc $r.User) + ' | ' + $pwCell + ' | ' + (Esc $src) + ' | ' + $st + ' |')
    }
    $lines.Add('')
    [IO.File]::WriteAllLines($Path, $lines, (New-Object System.Text.UTF8Encoding $false))
    return $Path
}
