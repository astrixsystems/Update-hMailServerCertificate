<#
.SYNOPSIS
	Name: Update-hMailServerCertificate.ps1
	The purpose of this script is to automatically update hMailServer's certificate and port bindings.
	
.DESCRIPTION
	ONCE INITIAL INTERACTIVE SETUP HAS BEEN COMPLETED, this script will:
		1. Obtain the latest SSL / TLS certificate installed in the local computer account's personal store.
		2. Export the certificate to PFX, KEY, and CRT files.
		3. For hMailServer:
			3a. Authenticate.
			3b. Add the SSL / TLS certificate and set the paths to the private and public key files.
			3c. Update the SSL / TLS certificate for all TCP/IP ports.

.NOTES
	Author:								Ben Hooper at Astrix
	Tested on:							Certify the Web v4.0.8 to v4.1.6 (latest), OpenSSL v1.1.0h to v1.1.1c (latest), and hMailServer v5.6.7 (latest) on Windows Server 2016 and Windows Server 2019 v1809
	Version:							1.6
	Changes in v1.6 (2019/08/13):		Code-signed, renamed removing "SSL", and restructured "Changes in vX" to include dates.
	Changes in v1.5 (2019/08/06 13:28):	Added tweaks to make this more user-friendly (option to auto re-run after initial setup, auto strip out quotation marks from paths, etc).
	Changes in v1.4 (2019/08/06 09:21):	Added logging by default for auto mode.
	Changes in v1.3 (2019/08/06 09:26):	Added path validation.
	Changes in v1.2 (2019/08/05):		Added proper setup process for credentials, paths, etc.
	Changes in v1.1 (2019/04/23):		Formalised script with a proper structure.
	Changes in v1.0 (2018/09/17):		Created.
	
.PARAMETER LogOutput
	Logs the output to the default file path "C:\<hostname>.Update-hMailServerCertificate.log".
	
.PARAMETER LogFile
	When used in combination with -LogOutput, logs the output to the custom specified file path.

.EXAMPLE
	Run with the default settings:
		Update-hMailServerCertificate
		
.EXAMPLE 
	Run with the default settings AND logging to the default path:
		Update-hMailServerCertificate -LogOutput
	
.EXAMPLE 
	Run with the default settings AND logging to a custom local path:
		Update-hMailServerCertificate -LogOutput -LogPath "C:\$env:computername.Update-hMailServerCertificate.log"
	
.EXAMPLE 
	Run with the default settings AND logging to a custom network path:
		Update-hMailServerCertificate -LogOutput -LogPath "\\servername\filesharename\$env:computername.Update-hMailServerCertificate.log"
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Param(
	[switch]$LogOutput,
	[string]$LogPath
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$RunAsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);

$global:FirstRun = $null;
$global:Script_Root = $PSScriptRoot;
$global:Script_PS1File_Name = Split-Path $PSCommandPath -Leaf;
$global:Script_PS1File_FullPath = $PSCommandPath;
$global:Script_ConfigFile_Extension = "config";
$global:Script_ConfigFile_Name = $global:Script_PS1File_Name + "." + $global:Script_ConfigFile_Extension;
$global:Script_ConfigFile_FullPath = "$global:Script_Root\$global:Script_ConfigFile_Name";
$global:Script_KeyFile_Extension = "password.key";
$global:Script_KeyFile_Name = $global:Script_PS1File_Name + "." + $global:Script_KeyFile_Extension;
$global:Script_KeyFile_FullPath = "$global:Script_Root\$global:Script_KeyFile_Name";
$global:Script_PasswordFile_Extension = "password";
$global:Script_PasswordFile_Name = $global:Script_PS1File_Name + "." + $global:Script_PasswordFile_Extension;
$global:Script_PasswordFile_FullPath = "$global:Script_Root\$global:Script_PasswordFile_Name";

$LogPath_Default = "$global:Script_Root\$env:computername`_$global:Script_PS1File_Name.log";

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Run-Checks {
	Param()
	
	Begin {
		Write-Output "Starting prerequisite checks...";
	}
	
	Process {
		Try {
			Write-Output "`t Administrative permissions required. Checking...";
			If ($RunAsAdministrator -Eq $False) {
				Write-Output "`t`t This script was not run as administrator. Exiting...";
				
				Break;
			} ElseIf ($RunAsAdministrator -Eq $True) {
				Write-Output "`t`t This script was run as administrator.";
			}
			
			Write-Output "";
			
			Write-Output "`t Existing configuration required. Checking...";
			
			If ((Test-Path -Path $global:Script_ConfigFile_FullPath) -And (Test-Path -Path $global:Script_PasswordFile_FullPath) -And (Test-Path -Path $global:Script_KeyFile_FullPath)) {
				Write-Output "`t`t Configuration files found.";
				
				$global:FirstRun = $False;
			} Else {
				Write-Output "`t`t Configuration files not found.";
				
				$global:FirstRun = $True;
			}
			
			Write-Output "";
		}
		
		Catch {
			Write-Output "...FAILURE. Prerequisite checking failed.";
			$_.Exception.Message;
			$_.Exception.ItemName;
			Break;
		}
	}
	
	End {
		If($?){
			Write-Output "...Success. Prerequisite checking complete.";
		}
	}
}

Function Run-FirstSetup {
	Param()
	
	Begin {
		Write-Output "Starting initial setup...";
	}
	
	Process {
		Try {
			Write-Output "`t This script requires initial configuration which has not yet been completed. This will be stored in files next to this script.";
			Write-Output "";
			
			Write-Output "`t (1/3) hMailServer's administrator password is required to use its COM API as it only supports plaintext authentication. Please enter this in the popup window. This will be encrypted.";
			$hMailServer_AdminPassword = (Get-Credential -Credential "Administrator").Password;
			
			Write-Output "`t`t Generating 256-bit AES key and storing in file '$global:Script_KeyFile_FullPath'...";
			Write-Output "";
			$AESKey = New-Object Byte[] 32;
			[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey);
			$AESKey | Out-File $global:Script_KeyFile_FullPath;
			
			Write-Output "`t`t Encrypting password and storing in file '$global:Script_PasswordFile_FullPath'...";
			Write-Output "";
			$hMailServer_AdminPassword | ConvertFrom-SecureString -key (Get-Content $global:Script_KeyFile_FullPath) | Set-Content $global:Script_PasswordFile_FullPath;
			
			# $hMailServer_AdminCredentials | Export-CliXml -Path $global:Script_PasswordFile_FullPath;
			
			Write-Output "`t (2/3) A folder is required to store hMailServer's SSL / TLS certificates. Please enter the path below:";
			
			$hMailServer_SSLCert_Path_Validity = $False;
			While ($hMailServer_SSLCert_Path_Validity -Eq $False){
				$hMailServer_SSLCert_Path = Read-Host "`t`t Path";
				
				Write-Output "`t`t`t Checking path validity...";
				
				# Remove quotation marks, if any
				$hMailServer_SSLCert_Path = $hMailServer_SSLCert_Path -Replace '"','';
				$hMailServer_SSLCert_Path = $hMailServer_SSLCert_Path -Replace "'","";
				
				If (Test-Path -Path $hMailServer_SSLCert_Path -PathType Container) {
					Write-Output "`t`t`t ...Success. Folder path is valid.";
					
					$hMailServer_SSLCert_Path_Validity = $True;
				} Else {
					Write-Output "`t`t`t ...ERROR. Folder path is invalid. Please ensure that the path points to a folder that exists, the path is syntactically valid, and this script has access to the folder.";
					Write-Output "";
				}
			}
			
			Write-Output "";
			
			Write-Output "`t (3/3) OpenSSL's EXE file is required to make changes to the installed certificate. Please enter the path below:";
			
			$OpenSSL_PathAndName_Validity = $False;
			While ($OpenSSL_PathAndName_Validity -Eq $False){
				$OpenSSL_PathAndName = Read-Host "`t`t Path";
				
				Write-Output "`t`t`t Checking path validity...";
				
				# Remove quotation marks, if any
				$OpenSSL_PathAndName = $OpenSSL_PathAndName -Replace '"','';
				$OpenSSL_PathAndName = $OpenSSL_PathAndName -Replace "'","";
				
				If (Test-Path -Path $OpenSSL_PathAndName -PathType Leaf) {
					Write-Output "`t`t`t ...Success. File path is valid.";
					
					$OpenSSL_PathAndName_Validity = $True;
				} Else {
					Write-Output "`t`t`t ...ERROR. File path is invalid. Please ensure that the path points to a file that exists, the path is syntactically valid, and this script has access to the folder.";
					Write-Output "";
				}
			}
			
			Write-Output "";
			
			$global:Script_ConfigFile_Content = @"
<?xml version="1.0"?>
<ScriptSettings>
	<hMailServerSettings>
		<CertificateFolderPath>$hMailServer_SSLCert_Path</CertificateFolderPath>
	</hMailServerSettings>
	<OpenSSLSettings>
		<OpenSSLFullPath>$OpenSSL_PathAndName</OpenSSLFullPath>
	</OpenSSLSettings>
</ScriptSettings>
"@
# The above here-string terminator cannot be indented for some reason;
			
			Write-Output "`t Storing generic configuration in file '$global:Script_ConfigFile_FullPath'...";
			
			New-Item -Path $global:Script_ConfigFile_FullPath -ItemType File -Force | Out-Null;
			Set-Content -Path $global:Script_ConfigFile_FullPath -Value $global:Script_ConfigFile_Content;
			
			Write-Output "";
		}
		
		Catch {
			Write-Output "...FAILURE. Initial setup failed.";
			$_.Exception.Message;
			$_.Exception.ItemName;
			Break;
		}
	}
	
	End {
		If($?){
			Write-Output "...Success. Initial setup complete.";
		}
	}
}

Function Update-hMailServerCertificate {
	Param()
	
	Begin {
		Write-Output "Updating hMailServer's SSL / TLS certificate...";
	}
	
	Process {
		Try {
			Write-Output "`t`t Loading existing settings...";
			Write-Output "";
			
			# $hMailServer_AdminCredentials = Import-CliXml -Path $global:Script_PasswordFile_FullPath;
			# $hMailServer_Admin_Username = $hMailServer_AdminCredentials.GetNetworkCredential().UserName;
			# $hMailServer_Admin_Password = $hMailServer_AdminCredentials.GetNetworkCredential().Password;
			$hMailServer_Admin_Username = "Administrator";
			$hMailServer_Admin_Password_Secure = Get-Content $global:Script_PasswordFile_FullPath | ConvertTo-SecureString -Key (Get-Content $global:Script_KeyFile_FullPath);
			$hMailServer_Admin_Password_BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($hMailServer_Admin_Password_Secure);
			$hMailServer_Admin_Password_Plaintext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($hMailServer_Admin_Password_BSTR);
			
			[xml]$Script_ConfigFile_Content = Get-Content $global:Script_ConfigFile_FullPath;

			$hMailServer_SSLCert_Path = $Script_ConfigFile_Content.ScriptSettings.hMailServerSettings.CertificateFolderPath;

			$OpenSSL_PathAndName = $Script_ConfigFile_Content.ScriptSettings.OpenSSLSettings.OpenSSLFullPath;
			
			Write-Output "`t`t Getting newest certificate from store Local Computer | Personal | Certificates...";
			Write-Output "";
			
			$Windows_SSLCert_Newest = Get-ChildItem -Path "Cert:\LocalMachine\My" | Sort-Object -Property NotAfter -Descending | Select-Object -First 1;

			# Set variables for certificate name and paths to be reused in commands
			$Windows_SSLCert_Newest_IssuedDate = $Windows_SSLCert_Newest.NotBefore.ToString("yyyy-MM-dd");
			$Windows_SSLCert_Newest_Subject = $Windows_SSLCert_Newest.Subject.Replace("CN=","");
			$Windows_SSLCert_Newest_Name = "$Windows_SSLCert_Newest_IssuedDate - $Windows_SSLCert_Newest_Subject";
			$Windows_SSLCert_Newest_File_PathAndName = "$hMailServer_SSLCert_Path\$Windows_SSLCert_Newest_Name";
			$Windows_SSLCert_Newest_File_PFX = "$Windows_SSLCert_Newest_File_PathAndName.pfx";
			$Windows_SSLCert_Newest_File_KEY_Private = "$Windows_SSLCert_Newest_File_PathAndName - private.key";
			$Windows_SSLCert_Newest_File_CRT_Public = "$Windows_SSLCert_Newest_File_PathAndName - public.crt";

			# Generate a random, 30-character password required for the PFX file and store it in a variable to be reused in OpenSSL commands
			Add-Type -AssemblyName System.Web;
			$Windows_SSLCert_Newest_Password_Plaintext = [System.Web.Security.Membership]::GeneratePassword(30, 5);
			
			# Convert the password to a format accepted by the export command
			$Windows_SSLCert_Newest_Password_Secure = ConvertTo-SecureString -String $Windows_SSLCert_Newest_Password_Plaintext -Force -AsPlainText;
			
			Write-Output "`t`t Exporting files...";
			
			Write-Output "`t`t`t Exporting certificate with private key to randomly-generated password-protected file '$Windows_SSLCert_Newest_File_PFX'...";
			Write-Output "";
			Export-PfxCertificate -Cert $Windows_SSLCert_Newest -FilePath $Windows_SSLCert_Newest_File_PFX -Password $Windows_SSLCert_Newest_Password_Secure | Out-Null;
			
			Write-Output "`t`t`t Extracting private key and certificate to passwordless file '$Windows_SSLCert_Newest_File_KEY_Private'...";
			Write-Output "";
			& $OpenSSL_PathAndName pkcs12 -in $Windows_SSLCert_Newest_File_PFX -passin pass:$Windows_SSLCert_Newest_Password_Plaintext -nocerts -nodes -out $Windows_SSLCert_Newest_File_KEY_Private;
			
			Write-Output "`t`t`t Extracting public key and certificate to file '$Windows_SSLCert_Newest_File_CRT_Public'...";
			Write-Output "";
			& $OpenSSL_PathAndName pkcs12 -in $Windows_SSLCert_Newest_File_PFX -passin pass:$Windows_SSLCert_Newest_Password_Plaintext -clcerts -nokeys -out $Windows_SSLCert_Newest_File_CRT_Public;
			
			Write-Output "`t`t Connecting and authenticating to hMailServer...";
			
			$hMailServer_SSLCert_New_Name = $Windows_SSLCert_Newest_Name;
			$hMailServer_SSLCert_New_ID = $null;
			# Connect and authenticate to hMailServer's COM API. It must be done this way according to https://www.hmailserver.com/documentation/latest/?page=com_objects
			$hMailServer = New-Object -ComObject hMailServer.Application;
			$hMailServer.Authenticate($hMailServer_Admin_Username, $hMailServer_Admin_Password_Plaintext) | Out-Null;
			
			Write-Output "`t`t`t Adding certificate '$hMailServer_SSLCert_New_Name' and setting paths...";
			Write-Output "";
			
			$hMailServer_SSLCert_New = $hMailServer.Settings.SSLCertificates.Add();
			$hMailServer_SSLCert_New.Name = $hMailServer_SSLCert_New_Name;
			$hMailServer_SSLCert_New.PrivateKeyFile = $Windows_SSLCert_Newest_File_KEY_Private;
			$hMailServer_SSLCert_New.CertificateFile = $Windows_SSLCert_Newest_File_CRT_Public;
			$hMailServer_SSLCert_New.Save();
			$hMailServer_SSLCert_New_ID = $hMailServer_SSLCert_New.ID;

			Write-Output "`t`t`t Updating TCP/IP ports' certificates...";
			Write-Output "";
			
			$hMailServer_TCPIPPort_All = $hMailServer.Settings.TCPIPPorts;
			For ($i = 0; $i -NE $hMailServer_TCPIPPort_All.Count; $i++){
				$hMailServer_TCPIPPort_Current = $hMailServer_TCPIPPort_All.Item($i);
				$hMailServer_TCPIPPort_Current.SSLCertificateID = $hMailServer_SSLCert_New_ID;
				$hMailServer_TCPIPPort_Current.Save();
			}
		}
		
		Catch {
			Write-Output "...FAILURE updating hMailServer's SSL / TLS certificate.";
			$_.Exception.Message;
			$_.Exception.ItemName;
			Break;
		}
	}
	
	End {
		If($?){
			Write-Output "...Success updating hMailServer's SSL / TLS certificate.";
		}
	}
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ($LogOutput -Eq $True) {
	If (-Not $LogPath) {
		$LogPath = $LogPath_Default;
	}
	Start-Transcript -Path $LogPath -Append | Out-Null;
	
	Write-Output "Logging output to file ""$LogPath""...";
	
	Write-Output "";
	Write-Output "----------------------------------------------------------------";
	Write-Output "";
}

Run-Checks;

Write-Output "";
Write-Output "----------------------------------------------------------------";
Write-Output "";

If ($global:FirstRun -Eq $False) {
	$LogOutput = $True;
	
	If (-Not $LogPath) {
		$LogPath = $LogPath_Default;
	}
	Start-Transcript -Path $LogPath -Append | Out-Null;
	
	Write-Output "This script has already been setup so assuming automatic mode and logging output to file ""$LogPath""...";
	
	Write-Output "";
	Write-Output "----------------------------------------------------------------";
	Write-Output "";
}

If ($global:FirstRun -Eq $True) {
	Run-FirstSetup;
} Else {
	Update-hMailServerCertificate;
}

If ($global:FirstRun -Eq $True) {
	Write-Output "";
	
	$ReRun = Read-Host "Re-run this script to actually update hMailServer? (y/n)";
	
	If (($ReRun -Like "y") -Or ($ReRun -Like "yes")){
		Write-Output "";
		Write-Output "----------------------------------------------------------------";
		Write-Output "";
		Write-Output "                      ...RESTARTING...";
		Write-Output "";
		Write-Output "----------------------------------------------------------------";
		Write-Output "";
		
		& $global:Script_PS1File_FullPath;
		Break;
	}
}

Write-Output "";
Write-Output "----------------------------------------------------------------";
Write-Output "";

Write-Output "Script complete. Exiting...";

If ($LogOutput -Eq $True) {
	Stop-Transcript | Out-Null;
}
# SIG # Begin signature block
# MIIe7AYJKoZIhvcNAQcCoIIe3TCCHtkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwwdbd2cnEY/fhPHMVgZ41Ya0
# V6Ogghn2MIIEhDCCA2ygAwIBAgIQQhrylAmEGR9SCkvGJCanSzANBgkqhkiG9w0B
# AQUFADBvMQswCQYDVQQGEwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNV
# BAsTHUFkZFRydXN0IEV4dGVybmFsIFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRU
# cnVzdCBFeHRlcm5hbCBDQSBSb290MB4XDTA1MDYwNzA4MDkxMFoXDTIwMDUzMDEw
# NDgzOFowgZUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJVVDEXMBUGA1UEBxMOU2Fs
# dCBMYWtlIENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEhMB8G
# A1UECxMYaHR0cDovL3d3dy51c2VydHJ1c3QuY29tMR0wGwYDVQQDExRVVE4tVVNF
# UkZpcnN0LU9iamVjdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM6q
# gT+jo2F4qjEAVZURnicPHxzfOpuCaDDASmEd8S8O+r5596Uj71VRloTN2+O5bj4x
# 2AogZ8f02b+U60cEPgLOKqJdhwQJ9jCdGIqXsqoc/EHSoTbL+z2RuufZcDX65OeQ
# w5ujm9M89RKZd7G3CeBo5hy485RjiGpq/gt2yb70IuRnuasaXnfBhQfdDWy/7gbH
# d2pBnqcP1/vulBe3/IW+pKvEHDHd17bR5PDv3xaPslKT16HUiaEHLr/hARJCHhrh
# 2JU022R5KP+6LhHC5ehbkkj7RwvCbNqtMoNB86XlQXD9ZZBt+vpRxPm9lisZBCzT
# bafc8H9vg2XiaquHhnUCAwEAAaOB9DCB8TAfBgNVHSMEGDAWgBStvZh6NLQm9/rE
# JlTvA73gJMtUGjAdBgNVHQ4EFgQU2u1kdBScFDyr3ZmpvVsoTYs8ydgwDgYDVR0P
# AQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAGBgRVHSAAMEQG
# A1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9BZGRUcnVz
# dEV4dGVybmFsQ0FSb290LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGG
# GWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEFBQADggEBAE1C
# L6bBiusHgJBYRoz4GTlmKjxaLG3P1NmHVY15CxKIe0CP1cf4S41VFmOtt1fcOyu9
# 08FPHgOHS0Sb4+JARSbzJkkraoTxVHrUQtr802q7Zn7Knurpu9wHx8OSToM8gUmf
# ktUyCepJLqERcZo20sVOaLbLDhslFq9s3l122B9ysZMmhhfbGN6vRenf+5ivFBjt
# pF72iZRF8FUESt3/J90GSkD2tLzx5A+ZArv9XQ4uKMG+O18aP5cQhLwWPtijnGMd
# ZstcX9o+8w8KCTUi29vAPwD55g1dZ9H9oB4DK9lA977Mh2ZUgKajuPUZYtXSJrGY
# Ju6ay0SnRVqBlRUa9VEwggTmMIIDzqADAgECAhBiXE2QjNVC+6supXM/8VQZMA0G
# CSqGSIb3DQEBBQUAMIGVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCVVQxFzAVBgNV
# BAcTDlNhbHQgTGFrZSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdv
# cmsxITAfBgNVBAsTGGh0dHA6Ly93d3cudXNlcnRydXN0LmNvbTEdMBsGA1UEAxMU
# VVROLVVTRVJGaXJzdC1PYmplY3QwHhcNMTEwNDI3MDAwMDAwWhcNMjAwNTMwMTA0
# ODM4WjB6MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDEg
# MB4GA1UEAxMXQ09NT0RPIFRpbWUgU3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCqgvGEqVvYcbXSXSvt9BMgDPmb6dGPdF5u7uspSNjI
# vizrCmFgzL2SjXzddLsKnmhOqnUkcyeuN/MagqVtuMgJRkx+oYPp4gNgpCEQJ0Ca
# WeFtrz6CryFpWW1jzM6x9haaeYOXOh0Mr8l90U7Yw0ahpZiqYM5V1BIR8zsLbMaI
# upUu76BGRTl8rOnjrehXl1/++8IJjf6OmqU/WUb8xy1dhIfwb1gmw/BC/FXeZb5n
# OGOzEbGhJe2pm75I30x3wKoZC7b9So8seVWx/llaWm1VixxD9rFVcimJTUA/vn9J
# AV08m1wI+8ridRUFk50IYv+6Dduq+LW/EDLKcuoIJs0ZAgMBAAGjggFKMIIBRjAf
# BgNVHSMEGDAWgBTa7WR0FJwUPKvdmam9WyhNizzJ2DAdBgNVHQ4EFgQUZCKGtkqJ
# yQQP0ARYkiuzbj0eJ2wwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8C
# AQAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMEIGA1Ud
# HwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VVE4tVVNFUkZp
# cnN0LU9iamVjdC5jcmwwdAYIKwYBBQUHAQEEaDBmMD0GCCsGAQUFBzAChjFodHRw
# Oi8vY3J0LnVzZXJ0cnVzdC5jb20vVVROQWRkVHJ1c3RPYmplY3RfQ0EuY3J0MCUG
# CCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEB
# BQUAA4IBAQARyT3hBeg7ZazJdDEDt9qDOMaSuv3N+Ntjm30ekKSYyNlYaDS18Ash
# U55ZRv1jhd/+R6pw5D9eCJUoXxTx/SKucOS38bC2Vp+xZ7hog16oYNuYOfbcSV4T
# p5BnS+Nu5+vwQ8fQL33/llqnA9abVKAj06XCoI75T9GyBiH+IV0njKCv2bBS7vzI
# 7bec8ckmONalMu1Il5RePeA9NbSwyVivx1j/YnQWkmRB2sqo64sDvcFOrh+RMrjh
# JDt77RRoCYaWKMk7yWwowiVp9UphreAn+FOndRWwUTGw8UH/PlomHmB+4uNqOZrE
# 6u4/5rITP1UDBE0LkHLU6/u8h5BRsjgZMIIE/jCCA+agAwIBAgIQK3PbdGMRTFpb
# MkryMFdySTANBgkqhkiG9w0BAQUFADB6MQswCQYDVQQGEwJHQjEbMBkGA1UECBMS
# R3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFD
# T01PRE8gQ0EgTGltaXRlZDEgMB4GA1UEAxMXQ09NT0RPIFRpbWUgU3RhbXBpbmcg
# Q0EwHhcNMTkwNTAyMDAwMDAwWhcNMjAwNTMwMTA0ODM4WjCBgzELMAkGA1UEBhMC
# R0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9y
# ZDEYMBYGA1UECgwPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDDCJTZWN0aWdvIFNI
# QS0xIFRpbWUgU3RhbXBpbmcgU2lnbmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAv1I2gjrcdDcNeNV/FlAZZu26GpnRYziaDGayQNungFC/aS42Lwpn
# P0ChSopjNZvQGcx0qhcZkSu1VSAZ+8AaOm3KOZuC8rqVoRrYNMe4iXtwiHBRZmns
# d/7GlHJ6zyWB7TSCmt8IFTcxtG2uHL8Y1Q3P/rXhxPuxR3Hp+u5jkezx7M5ZBBF8
# rgtgU+oq874vAg/QTF0xEy8eaQ+Fm0WWwo0Si2euH69pqwaWgQDfkXyVHOaeGWTf
# dshgRC9J449/YGpFORNEIaW6+5H6QUDtTQK0S3/f4uA9uKrzGthBg49/M+1BBuJ9
# nj9ThI0o2t12xr33jh44zcDLYCQD3npMqwIDAQABo4IBdDCCAXAwHwYDVR0jBBgw
# FoAUZCKGtkqJyQQP0ARYkiuzbj0eJ2wwHQYDVR0OBBYEFK7u2WC6XvUsARL9jo2y
# VXI1Rm/xMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMEAGA1UdIAQ5MDcwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYB
# BQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMEIGA1UdHwQ7MDkwN6A1oDOG
# MWh0dHA6Ly9jcmwuc2VjdGlnby5jb20vQ09NT0RPVGltZVN0YW1waW5nQ0FfMi5j
# cmwwcgYIKwYBBQUHAQEEZjBkMD0GCCsGAQUFBzAChjFodHRwOi8vY3J0LnNlY3Rp
# Z28uY29tL0NPTU9ET1RpbWVTdGFtcGluZ0NBXzIuY3J0MCMGCCsGAQUFBzABhhdo
# dHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQUFAAOCAQEAen+pStKw
# pBwdDZ0tXMauWt2PRR3wnlyQ9l6scP7T2c3kGaQKQ3VgaoOkw5mEIDG61v5MzxP4
# EPdUCX7q3NIuedcHTFS3tcmdsvDyHiQU0JzHyGeqC2K3tPEG5OfkIUsZMpk0uRlh
# dwozkGdswIhKkvWhQwHzrqJvyZW9ljj3g/etfCgf8zjfjiHIcWhTLcuuquIwF4Mi
# KRi14YyJ6274fji7kE+5Xwc0EmuX1eY7kb4AFyFu4m38UnnvgSW6zxPQ+90rzYG2
# V4lO8N3zC0o0yoX/CLmWX+sRE+DhxQOtVxzhXZIGvhvIPD+lIJ9p0GnBxcLJPufF
# cvfqG5bilK+GLjCCBZowggSCoAMCAQICEQDn707xyENfZNmlutMrdM37MA0GCSqG
# SIb3DQEBCwUAMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNo
# ZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1p
# dGVkMSMwIQYDVQQDExpDT01PRE8gUlNBIENvZGUgU2lnbmluZyBDQTAeFw0xODA5
# MjUwMDAwMDBaFw0xOTA5MjUyMzU5NTlaMIHeMQswCQYDVQQGEwJHQjERMA8GA1UE
# EQwIQ0Y0NSA0U04xGjAYBgNVBAgMEVJob25kZGEgQ3lub24gVGFmMRIwEAYDVQQH
# DAlBYmVyY3lub24xJzAlBgNVBAkMHlZlbnR1cmUgSG91c2UsIE5hdmlnYXRpb24g
# UGFyazEqMCgGA1UECgwhQXN0cml4IEludGVncmF0ZWQgU3lzdGVtcyBMaW1pdGVk
# MQswCQYDVQQLDAJJVDEqMCgGA1UEAwwhQXN0cml4IEludGVncmF0ZWQgU3lzdGVt
# cyBMaW1pdGVkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7SaJPW8+
# B3gcjzBkVBl5f9aRGEZbi0luJ0zFVSt0TOOiGaIBPxTWKBSGW0BrKlR3Z6bk5az3
# SXKk0RXzleD1299kD5TPwmDZh6fJXqRi99zPpyTOHYDdS51thWh4uWGPkfla+8+i
# JUHRr6k/mn/ARnx2LPXbkOKLt+mxA1eeITV0gH7oFgIOQGzY0b7muITKMrZuLM75
# UTcQGzQfhcC2gA6iYWGF3hi5kJNkW/CYbIJaqphEegST2DiImGlqKppp+M1u250N
# QLGXDP4lRfbdUyaVkd8zYxwiJ0oYEXl5TOmeVdkFdvcbDZMjldduochHpdsge+js
# +2GqimYvWeatKQIDAQABo4IBsTCCAa0wHwYDVR0jBBgwFoAUKZFg/4pN+uv5pmq4
# z/nmS71JzhIwHQYDVR0OBBYEFD/1KzrRrpRlp4rn2kkfuGSzXM3LMA4GA1UdDwEB
# /wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMBEGCWCG
# SAGG+EIBAQQEAwIEEDBGBgNVHSAEPzA9MDsGDCsGAQQBsjEBAgEDAjArMCkGCCsG
# AQUFBwIBFh1odHRwczovL3NlY3VyZS5jb21vZG8ubmV0L0NQUzBDBgNVHR8EPDA6
# MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9SU0FDb2RlU2ln
# bmluZ0NBLmNybDB0BggrBgEFBQcBAQRoMGYwPgYIKwYBBQUHMAKGMmh0dHA6Ly9j
# cnQuY29tb2RvY2EuY29tL0NPTU9ET1JTQUNvZGVTaWduaW5nQ0EuY3J0MCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wIgYDVR0RBBswGYEXYmVu
# Lmhvb3BlckBhc3RyaXguY28udWswDQYJKoZIhvcNAQELBQADggEBACj+LqqgNA4t
# 565FPWM9FrgXESB5UjAjEwQ4YGFhirgMauBwh6LXNY3Lv/qACEbTtMvF5hRrKQwL
# +JCbDN9cDJ8VLJmbo6Ydgpm9OK48TzS/4D0VkbXtDZCkChikJueqVRZb9TtAwwjH
# mz1ZeaoJcbPM1flGA9ng/n4R3IvK0XYtxo6gzCbogxtqUEdlcLGhwObDQLRpTcKJ
# omndOGc3DOSuvEHb7wCX42CKVWE3fuwOSRndQBh6wUCanNOg8DF5MKighEWoJVsp
# UYUkCjAv4YrBRAg8T1K3/4yepwsTCYAEUD/+vemlYgKYDswOT2NH2vPiZv8Suu8w
# KhxxwDvALCwwggXgMIIDyKADAgECAhAufIfMDpNKUv6U/Ry3zTSvMA0GCSqGSIb3
# DQEBDAUAMIGFMQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVz
# dGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8gQ0EgTGltaXRl
# ZDErMCkGA1UEAxMiQ09NT0RPIFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAe
# Fw0xMzA1MDkwMDAwMDBaFw0yODA1MDgyMzU5NTlaMH0xCzAJBgNVBAYTAkdCMRsw
# GQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAY
# BgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSMwIQYDVQQDExpDT01PRE8gUlNBIENv
# ZGUgU2lnbmluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKaY
# kGN3kTR/itHd6WcxEevMHv0xHbO5Ylc/k7xb458eJDIRJ2u8UZGnz56eJbNfgagY
# Dx0eIDAO+2F7hgmz4/2iaJ0cLJ2/cuPkdaDlNSOOyYruGgxkx9hCoXu1UgNLOrCO
# I0tLY+AilDd71XmQChQYUSzm/sES8Bw/YWEKjKLc9sMwqs0oGHVIwXlaCM27jFWM
# 99R2kDozRlBzmFz0hUprD4DdXta9/akvwCX1+XjXjV8QwkRVPJA8MUbLcK4HqQrj
# r8EBb5AaI+JfONvGCF1Hs4NB8C4ANxS5Eqp5klLNhw972GIppH4wvRu1jHK0SPLj
# 6CH5XkxieYsCBp9/1QsCAwEAAaOCAVEwggFNMB8GA1UdIwQYMBaAFLuvfgI9+qbx
# PISOre44mOzZMjLUMB0GA1UdDgQWBBQpkWD/ik366/mmarjP+eZLvUnOEjAOBgNV
# HQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEF
# BQcDAzARBgNVHSAECjAIMAYGBFUdIAAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDov
# L2NybC5jb21vZG9jYS5jb20vQ09NT0RPUlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0
# eS5jcmwwcQYIKwYBBQUHAQEEZTBjMDsGCCsGAQUFBzAChi9odHRwOi8vY3J0LmNv
# bW9kb2NhLmNvbS9DT01PRE9SU0FBZGRUcnVzdENBLmNydDAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQACPwI5
# w+74yjuJ3gxtTbHxTpJPr8I4LATMxWMRqwljr6ui1wI/zG8Zwz3WGgiU/yXYqYin
# KxAa4JuxByIaURw61OHpCb/mJHSvHnsWMW4j71RRLVIC4nUIBUzxt1HhUQDGh/Zs
# 7hBEdldq8d9YayGqSdR8N069/7Z1VEAYNldnEc1PAuT+89r8dRfb7Lf3ZQkjSR9D
# V4PqfiB3YchN8rtlTaj3hUUHr3ppJ2WQKUCL33s6UTmMqB9wea1tQiCizwxsA4xM
# zXMHlOdajjoEuqKhfB/LYzoVp9QVG6dSRzKp9L9kR9GqH1NOMjBzwm+3eIKdXP9G
# u2siHYgL+BuqNKb8jPXdf2WMjDFXMdA27Eehz8uLqO8cGFjFBnfKS5tRr0wISnqP
# 4qNS4o6OzCbkstjlOMKo7caBnDVrqVhhSgqXtEtCtlWdvpnncG1Z+G0qDH8ZYF8M
# mohsMKxSCZAWG/8rndvQIMqJ6ih+Mo4Z33tIMx7XZfiuyfiDFJN2fWTQjs6+NX3/
# cjFNn569HmwvqI8MBlD7jCezdsn05tfDNOKMhyGGYf6/VXThIXcDCmhsu+TJqebP
# WSXrfOxFDnlmaOgizbjvmIVNlhE8CYrQf7woKBP7aspUjZJczcJlmAaezkhb1LU3
# k0ZBfAfdz/pD77pnYf99SeC7MH1cgOPmFjlLpzGCBGAwggRcAgEBMIGSMH0xCzAJ
# BgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcT
# B1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSMwIQYDVQQDExpD
# T01PRE8gUlNBIENvZGUgU2lnbmluZyBDQQIRAOfvTvHIQ19k2aW60yt0zfswCQYF
# Kw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJ
# KoZIhvcNAQkEMRYEFKC/aeeOBvoMcOA7YfL9H1sIzeV0MA0GCSqGSIb3DQEBAQUA
# BIIBAD2jEGc1+fFovXxJ+iSnpq+OyXG67xOyPjew4dhZtM4YzSKx5IUhOlO26yUH
# /VQj4lZihwBUNu8mChiEeFKsyPNzl73DCVXxTAbcJ1twbMSmgLzd3Fsf/O9N0mja
# 9bqVz6dR1467EeX3SqkSz9qQtyFWr2X2SRvaeuYbfY7+Nm+fsxlYAOX7x7NSp9iT
# LYpGYm6McAllq1HCdJjBu5JKCAODnLnTjwDGL1Wt7J88GDuDcm44OPX/M9aec45M
# B7MWFf6wz1Iv5LGBrE654ALl0lg+4h+At0wOxJzEX1sh28/O2Q1kURppePPiUSEU
# QXjIL3/g9C/vDquZGaMTmQ1h9YGhggIoMIICJAYJKoZIhvcNAQkGMYICFTCCAhEC
# AQEwgY4wejELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3Rl
# cjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQx
# IDAeBgNVBAMTF0NPTU9ETyBUaW1lIFN0YW1waW5nIENBAhArc9t0YxFMWlsySvIw
# V3JJMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqG
# SIb3DQEJBTEPFw0xOTA4MTMxMjQ1NTBaMCMGCSqGSIb3DQEJBDEWBBRbdLJt9+BP
# PM4KDE3SXUQkkIFgZjANBgkqhkiG9w0BAQEFAASCAQBOP2gXW5a1dUA8QuFq+/wl
# HvAKVMw875aYSET1oV2YTaD+MFTQG3ahbBvFdAyPbuGMRu5fpeMlQtXFCVQJwjZD
# ycB1i/EsO1Bg/+CjtjkAcsjloxLyvP9momJGDR7Jq2AIYOhxtMm3B13kEbRTSy3i
# ag9ovCPmSTMJSYBhklztKsCSH30dV1iLthex/UbBb418yjSnVvlpZKhUMdJB5O7X
# wyrj6fvQBa3Cklhdi92FmuO1hfi5YOIQJ/RbTSHUQXDxdVSC9+Fhu8xI2/8ifgyv
# jsucl9Jj6IVwHFT7z+9JeilZttzonWLnOM6VIG7iLE4Oh9nl406x0n/lFtQNqbK+
# SIG # End signature block
