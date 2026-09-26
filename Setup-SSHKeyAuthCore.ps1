#Requires -Version 5.1
<#
.SYNOPSIS
  Setup-SSHKeyAuth 核心函数库 (被 CLI / GUI 入口点源使用, 也可单独点源二次开发)

.DESCRIPTION
  - 日志: Info/Ok/Warn/Err/Banner/Dim, 默认输出到控制台; GUI 可用 Set-LogSink 重定向
  - 发现: Get-ActiveSshTargets / Find-MobaXtermIni / Read-MobaSessions / Get-XshellStoredPasswords
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
    $enc = [Text.Encoding]::UTF8
    $bytes = [IO.File]::ReadAllBytes($Path)
    if($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE){ $enc = [Text.Encoding]::Unicode }
    $map = [ordered]@{}
    $section = ''
    foreach($line in [IO.File]::ReadAllLines($Path, $enc)){
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
function Find-MobaXtermIni{
    $p = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MobaXterm*' } | Select-Object -First 1
    if($p -and $p.Path){
        $ini = Join-Path (Split-Path $p.Path) 'MobaXterm.ini'
        if(Test-Path $ini){ return $ini }
    }
    $ini = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'MobaXterm\MobaXterm.ini'
    if(Test-Path $ini){ return $ini }
    return $null
}

# 解析 [Bookmarks*] 段: 会话行 = "名称=#109#0%host%port%user%...%keyPath%..."
function Read-MobaSessions([string]$IniPath){
    $result = @()
    if(-not $IniPath){ return $result }
    $enc = [Text.Encoding]::UTF8
    $b = [IO.File]::ReadAllBytes($IniPath)
    if($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE){ $enc = [Text.Encoding]::Unicode }
    $lines = [IO.File]::ReadAllLines($IniPath, $enc)
    $section = ''
    for($i=0; $i -lt $lines.Count; $i++){
        $line = $lines[$i]
        if($line -match '^\s*\[(.+)\]\s*$'){ $section = $Matches[1]; continue }
        if($section -like 'Bookmarks*' -and $line -match '^([^=]+)=(.*)$'){
            $name = $Matches[1]; $val = $Matches[2]
            if($name -in @('SubRep','ImgNum')){ continue }
            $f = ($val.Trim()) -split '%'
            if($f.Count -gt 14 -and $f[0] -match '^#109#0$'){
                $result += [pscustomobject]@{
                    Name = $name; Host = $f[1]; Port = $f[2]; Login = $f[3]
                    KeyPath = $f[14]; Section = $section; IniPath = $IniPath; LineNo = $i
                }
            }
        }
    }
    return $result
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
                if($host_ -and $user_){
                    $result["$host_`:$port"] = [pscustomobject]@{ User = $user_; EncPassword = $pw; Path = $f.FullName }
                }
            } catch { }
        }
    }
    return $result
}

# ======================================================= 4. 密钥管理 =======
function Ensure-SshKey{
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
function Update-MobaIni([object[]]$Sessions, [string]$KeyRel){
    $iniPath = $Sessions[0].IniPath
    $bak = "$iniPath.toolbak-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item $iniPath $bak -Force
    Ok "MobaXterm.ini backed up -> $bak"
    $enc = [Text.Encoding]::UTF8
    $b = [IO.File]::ReadAllBytes($iniPath)
    if($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE){ $enc = [Text.Encoding]::Unicode }
    $lines = [IO.File]::ReadAllLines($iniPath, $enc)
    $changed = 0
    foreach($s in $Sessions){
        $line = $lines[$s.LineNo]
        if($line -notmatch "^$([regex]::Escape($s.Name))="){ continue }
        $val = ($line -split '=',2)[1]
        $prefix = if($val -match '^\s'){ ' ' } else { '' }
        $f = ($val.Trim()) -split '%'
        if($f.Count -le 14){ continue }
        if($f[14] -eq $KeyRel){ continue }
        $f[14] = $KeyRel
        $lines[$s.LineNo] = $s.Name + '=' + $prefix + ($f -join '%')
        $changed++
    }
    if($changed -gt 0){
        [IO.File]::WriteAllLines($iniPath, $lines, $enc)
        Ok "MobaXterm.ini updated ($changed session(s) -> private key: $KeyRel)"
    } else {
        Info "MobaXterm.ini: all target sessions already configured"
    }
    return $changed
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
        [scriptblock]$TargetSelector,
        [scriptblock]$PasswordPrompter,
        [scriptblock]$ConfirmPrompter
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
    $mobaIni = Find-MobaXtermIni
    $mobaSessions = @()
    $mobaIniMap = $null
    if($mobaIni){
        Info "MobaXterm config: $mobaIni"
        $mobaSessions = Read-MobaSessions $mobaIni
        $mobaIniMap = Read-IniFile $mobaIni
        foreach($s in $mobaSessions){ Dim "moba session: $($s.Host):$($s.Port)  login=$($s.Login)  key=$($s.KeyPath)" }
    }
    Info "scanning Xshell sessions ..."
    $xshPw = Get-XshellStoredPasswords
    foreach($k in $xshPw.Keys){ Dim "xshell session: $k  user=$($xshPw[$k].User)" }

    # --- 2. 目标选择 ---
    $chosenIps = @()
    if($TargetIps){ $chosenIps = $TargetIps }
    elseif($All){ $chosenIps = @($active.Keys) + @($mobaSessions | ForEach-Object { $_.Host }) + @($xshPw.Keys | ForEach-Object { ($_ -split ':')[0] }) | Sort-Object -Unique }
    elseif($active.Count -gt 0){
        $candidates = @($active.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ Ip = $_; Tool = $active[$_] } })
        if($TargetSelector){ $chosenIps = @(& $TargetSelector $candidates) }
        else { $chosenIps = @($candidates | ForEach-Object { $_.Ip }) }
    }
    else {
        $cand = @($mobaSessions | ForEach-Object { $_.Host }) + @($xshPw.Keys | ForEach-Object { ($_ -split ':')[0] })
        $cand = $cand | Sort-Object -Unique
        if($cand.Count -eq 0){ Err "no target found. use -Ip <addr> or open connections first"; return $null }
        $chosenIps = $cand
        Warn "no active connection; will process all stored sessions: $($chosenIps -join ', ')"
    }
    $chosenIps = @($chosenIps | Where-Object { $_ -and $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Sort-Object -Unique)
    if(-not $chosenIps){ Err "no valid target IP"; return $null }
    Banner ""
    Ok "targets: $($chosenIps -join ', ')"

    # --- 3. 密钥 ---
    $key = Ensure-SshKey
    if(-not $key){ return $null }
    Ok "private key: $($key.Pri)"
    Info "public  key: $($key.PubLine.Substring(0,40))..."

    # --- 4. 逐台处理 ---
    $report = @()
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

        $report += [pscustomobject]@{ Ip = $ip; Port = $port; User = $user; KeyAuth = $keyOk }
    }

    # --- 5. MobaXterm 配置 ---
    if(-not $SkipMoba -and $mobaSessions){
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
            $targets = @($mobaSessions | Where-Object { $chosenIps -contains $_.Host })
            if($targets){ Update-MobaIni $targets '_ProfileDir_\.ssh\id_ed25519' | Out-Null }
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
            foreach($t in $report){
                $f = New-XshellSessionFile $t.Ip $t.Port $t.User 'id_ed25519' $xd.Sessions
                $n++
            }
            Ok "Xshell session files written: $n (in $($xd.Sessions))"
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
function Get-SshCredentialInventory{
    Banner "scanning SSH connections and stored sessions ..."
    $active = Get-ActiveSshTargets
    $mobaIni = Find-MobaXtermIni
    $mobaSessions = @(); $mobaIniMap = $null
    if($mobaIni){
        Info "MobaXterm config: $mobaIni"
        $mobaSessions = Read-MobaSessions $mobaIni
        $mobaIniMap = Read-IniFile $mobaIni
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
