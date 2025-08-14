<# 
.SYNOPSIS
  Test connectivity to a CrowdStrike cloud URL via WinINET and WinHTTP,
  both with a defined proxy and direct.

.DESCRIPTION
  - Runs 4 tests: WinINET(Proxy), WinINET(Direct), WinHTTP(Proxy), WinHTTP(Direct)
  - Emits a single-line summary to stdout
  - Saves detailed JSON results under C:\ProgramData\CrowdStrikeConnectivity\
  - Compatible with Windows Server 2012–2022 (PowerShell 3.0+)

.PARAMETER Url
  The CrowdStrike endpoint URL to test, e.g. https://sensor.cloud.crowdstrike.com

.PARAMETER Proxy
  The proxy endpoint to use for the “proxy” tests, e.g. proxy.mycorp.local:8080 or http://10.0.0.5:3128

.PARAMETER ProxyCredential
  Optional PSCredential for authenticating to the proxy (if required). 
  Note: CrowdStrike sensors don’t support proxy auth, but this can help diagnose environments.

.PARAMETER TimeoutSeconds
  Per-request timeout (default: 10)

.EXAMPLE
  .\Test-CrowdStrikeConnectivity.ps1 -Url https://sensor.cloud.crowdstrike.com -Proxy proxy01:8080

.EXAMPLE
  $cred = Get-Credential
  .\Test-CrowdStrikeConnectivity.ps1 -Url https://sensor.cloud.crowdstrike.com -Proxy http://proxy01:8080 -ProxyCredential $cred
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$Url,

  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$Proxy,

  [Parameter(Mandatory=$false)]
  [System.Management.Automation.PSCredential]$ProxyCredential,

  [int]$TimeoutSeconds = 10
)

# --- Prep ---------------------------------------------------------------------

# Ensure TLS1.2 (older OS default to TLS1.0)
try {
  [System.Net.ServicePointManager]::SecurityProtocol = `
    ([System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12)
} catch { }

$OutputDir = 'C:\ProgramData\CrowdStrikeConnectivity'
$null = New-Item -Path $OutputDir -ItemType Directory -Force -ErrorAction SilentlyContinue
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$detailPath = Join-Path $OutputDir "CS-WebTest_$($env:COMPUTERNAME)_$timestamp.json"

function New-Result {
  param(
    [string]$Stack,  # WinINET or WinHTTP
    [string]$Mode,   # Proxy or Direct
    [bool]$Success,
    [int]$StatusCode = 0,
    [string]$FinalUrl = $null,
    [string]$Error   = $null,
    [int]$ElapsedMs  = 0
  )
  [pscustomobject]@{
    Timestamp   = (Get-Date).ToString('o')
    Computer    = $env:COMPUTERNAME
    Url         = $Url
    Stack       = $Stack
    Mode        = $Mode
    Success     = $Success
    StatusCode  = $StatusCode
    FinalUrl    = $FinalUrl
    Error       = $Error
    ElapsedMs   = $ElapsedMs
  }
}

# --- WinINET tests (HttpWebRequest / .NET) ------------------------------------

function Test-WinInet {
  param(
    [string]$Mode # 'Proxy' or 'Direct'
  )
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Method = 'GET'
    $req.AllowAutoRedirect = $true
    $req.UserAgent = "CS-ConnTest/1.0 (WinINET;$env:COMPUTERNAME)"
    $req.Timeout   = $TimeoutSeconds * 1000
    $req.ReadWriteTimeout = $TimeoutSeconds * 1000
    switch ($Mode) {
      'Proxy' {
        $wp = New-Object System.Net.WebProxy($Proxy, $true)
        if ($ProxyCredential) {
          $netcred = $ProxyCredential.GetNetworkCredential()
          $wp.Credentials = New-Object System.Net.NetworkCredential($netcred.UserName, $netcred.Password, $netcred.Domain)
        }
        $req.Proxy = $wp
      }
      'Direct' {
        # Explicitly bypass any system/default proxy
        $req.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
      }
    }
    $resp = $req.GetResponse()
    $sw.Stop()
    $status = [int]$resp.StatusCode
    $final  = $resp.ResponseUri.AbsoluteUri
    $resp.Close()
    return New-Result -Stack 'WinINET' -Mode $Mode -Success $true -StatusCode $status -FinalUrl $final -ElapsedMs $sw.ElapsedMilliseconds
  }
  catch {
    $sw.Stop()
    $code = 0
    $msg  = $_.Exception.Message
    # Try to extract status code if present
    if ($_.Exception.Response -and ($_.Exception.Response -is [System.Net.HttpWebResponse])) {
      $code = [int]$_.Exception.Response.StatusCode
    }
    return New-Result -Stack 'WinINET' -Mode $Mode -Success $false -StatusCode $code -Error $msg -ElapsedMs $sw.ElapsedMilliseconds
  }
}

# --- WinHTTP tests (WinHttpRequest COM) ---------------------------------------

function Test-WinHttp {
  param(
    [string]$Mode # 'Proxy' or 'Direct'
  )
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $http = New-Object -ComObject 'WinHttp.WinHttpRequest.5.1'
    $http.Open('GET', $Url, $false)
    # Set timeouts: Resolve, Connect, Send, Receive (ms)
    $http.SetTimeouts(3000, $TimeoutSeconds * 1000, $TimeoutSeconds * 1000, $TimeoutSeconds * 1000)

    switch ($Mode) {
      'Proxy' {
        # 2 = WINHTTP_ACCESS_TYPE_NAMED_PROXY
        $http.SetProxy(2, $Proxy)
        if ($ProxyCredential) {
          $netcred = $ProxyCredential.GetNetworkCredential()
          # 1 = WINHTTP_AUTH_TARGET_PROXY
          $http.SetCredentials($netcred.UserName, $netcred.Password, 1)
        }
      }
      'Direct' {
        # 0 = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY (will use WinHTTP config)
        # 3 = WINHTTP_ACCESS_TYPE_NO_PROXY (force direct)
        $http.SetProxy(3)
      }
    }

    $http.Send()
    $sw.Stop()
    $status = [int]$http.Status
    $final  = $http.Option(0x00000030) # WINHTTP_OPTION_URL
    return New-Result -Stack 'WinHTTP' -Mode $Mode -Success $true -StatusCode $status -FinalUrl $final -ElapsedMs $sw.ElapsedMilliseconds
  }
  catch {
    $sw.Stop()
    $code = 0
    $msg  = $_.Exception.Message
    try {
      if ($http.Status) { $code = [int]$http.Status }
    } catch { }
    return New-Result -Stack 'WinHTTP' -Mode $Mode -Success $false -StatusCode $code -Error $msg -ElapsedMs $sw.ElapsedMilliseconds
  }
}

# --- Execute tests ------------------------------------------------------------

$results = New-Object System.Collections.Generic.List[object]

$results.Add( (Test-WinInet -Mode 'Proxy') )
$results.Add( (Test-WinInet -Mode 'Direct') )
$results.Add( (Test-WinHttp -Mode 'Proxy') )
$results.Add( (Test-WinHttp -Mode 'Direct') )

# Save detailed JSON
try {
  $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $detailPath -Encoding UTF8 -Force
} catch {
  Write-Warning "Failed to write JSON results: $($_.Exception.Message)"
}

# Build single-line summary
function Summarize {
  param([object]$r)
  $tag = "{0}-{1}" -f $r.Stack, $r.Mode
  if ($r.Success) {
    return "$tag=Success($($r.StatusCode),${($r.ElapsedMs)}ms)"
  } else {
    # trim noisy errors for the one-liner
    $erm = $r.Error
    if ($erm.Length -gt 60) { $erm = $erm.Substring(0,57) + '…' }
    return "$tag=Fail($($r.StatusCode),${($r.ElapsedMs)}ms,$erm)"
  }
}

$oneLine = '{0},{1},{2}' -f $env:COMPUTERNAME, $Url, ($results | ForEach-Object { Summarize $_ } -join ',')
Write-Output $oneLine

Write-Verbose "Detailed results saved to $detailPath"
