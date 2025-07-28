<#
.SYNOPSIS
    PSADT Pre‑Installation/Installation script to download the latest Office Deployment Toolkit and a configuration XML (faculty.xml) from GitHub, then run setup.exe with that XML.
#>

# =======================
# Pre‑Installation Tasks
# Add the code below in the Pre-Installation tasks section:
# =======================
try {
    ## -------- Variables --------
    $ODTEverGreenURL = "https://officecdn.microsoft.com/pr/wsus/setup.exe"
    $FacultyXMLUrl   = "https://raw.githubusercontent.com/rbond6002/Office365/refs/heads/main/pupil.xml"

    ## -------- Prepare WebClient --------
    $WebClient = New-Object -TypeName System.Net.WebClient

    ## -------- Download ODT --------
    Write-ADTLogEntry -Message "Downloading the latest Office Deployment Toolkit executable from '$ODTEverGreenURL'" -Source "WebClient"
    $ODTLocalPath = Join-Path -Path $($adtSession.DirFiles) -ChildPath "setup.exe"
    $WebClient.DownloadFile($ODTEverGreenURL, $ODTLocalPath)
    Write-ADTLogEntry -Message "Download of setup.exe complete" -Source "WebClient"

    ## -------- Download configuration XML --------
    Write-ADTLogEntry -Message "Downloading configuration XML from '$FacultyXMLUrl'" -Source "WebClient"
    $FacultyXMLPath = Join-Path -Path $($adtSession.DirSupportFiles) -ChildPath "faculty.xml"
    $WebClient.DownloadFile($FacultyXMLUrl, $FacultyXMLPath)
    Write-ADTLogEntry -Message "Download of faculty.xml complete" -Source "WebClient"

    ## -------- Validate ODT signing certificate --------
    Write-ADTLogEntry -Message "Validating the Office Deployment Toolkit executable code sign certificate" -Source "CodeSignValidation"
    $ODTFile       = Get-Item -Path $ODTLocalPath
    $ODFileCert    = (Get-AuthenticodeSignature -FilePath $ODTFile).SignerCertificate
    $ODFileCertStatus = (Get-AuthenticodeSignature -FilePath $ODTFile).Status

    if ($ODFileCert) {
        if ($ODFileCert.Subject -match "O=Microsoft Corporation" -and $ODFileCertStatus -eq "Valid") {
            $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
            $chain.Build($ODFileCert) | Out-Null
            $RootCert = $chain.ChainElements | ForEach-Object { $_.Certificate } | Where-Object { $_.Subject -match "CN=Microsoft Root" }
            if (-not [string]::IsNullOrEmpty($RootCert)) {
                $TrustedRoot = Get-ChildItem -Path "Cert:\\LocalMachine\\Root" -Recurse | Where-Object { $_.Thumbprint -eq $RootCert.Thumbprint }
                if (-not [string]::IsNullOrEmpty($TrustedRoot)) {
                    Write-ADTLogEntry -Message "Office Deployment Toolkit file signed by '$($ODFileCert.Issuer)'. Installation will proceed." -Source "CodeSignValidation"
                }
                else {
                    Write-ADTLogEntry -Message "No trust found to Root Certificate. Installation will NOT proceed." -Source "CodeSignValidation"
                    exit 80000
                }
            }
            else {
                Write-ADTLogEntry -Message "Certificate chain not verified to Microsoft. Installation will NOT proceed." -Source "CodeSignValidation"
                exit 80001
            }
        }
        else {
            Write-ADTLogEntry -Message "Certificate NOT valid or NOT signed by Microsoft. Installation will NOT proceed." -Source "CodeSignValidation"
            exit 80002
        }
    }
    else {
        Write-ADTLogEntry -Message "Office Deployment toolkit downloaded file not signed. Installation will NOT proceed." -Source "CodeSignValidation"
        exit 80003
    }
}
catch [System.Exception] {
    Write-ADTLogEntry -Message "An error occurred in the Pre‑Installation phase: $($_.Exception.Message)" -Source "ErrorHandler"
    throw
}
finally {
    Write-ADTLogEntry -Message "Disposing of the WebClient" -Source "WebClient"
    if ($null -ne $WebClient) { $WebClient.Dispose() }
}

# =======================
# Installation Tasks
# =======================
# Run the Office Deployment Tool with the downloaded configuration XML
# Add the this next snippet in the Installation Task Section
Start-ADTProcess -FilePath "$ODTFile" -ArgumentList "/configure `"$FacultyXMLPath`""
