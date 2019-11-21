<#
.SYNOPSIS
	Name: Update-hMailServerCertificate.ps1
	The purpose of this script is to automate the process of updating hMailServer's certificate and port bindings.
	
.DESCRIPTION
	ONCE INITIAL INTERACTIVE SETUP HAS BEEN COMPLETED, this script will:
		1. Obtain the specified or latest SSL / TLS certificate installed in the local computer account's personal store.
		2. Export the certificate to PFX, KEY, and CRT files.
		3. For hMailServer:
			3a. Authenticate.
			3b. Add the SSL / TLS certificate and set the paths to the private and public key files.
			3c. Update the SSL / TLS certificate for all TCP/IP ports.
			
	The hMailServer administrator password is required to be:
		1. Entered by the user because:
			1a. The documentation says that the only API is a COM one which says "you must call Application.Authenticate with valid credentials" and there are no options for keys. Refer to https://www.hmailserver.com/documentation/latest/?page=overview
			1b. The only alternative is directly modifying hMailServer's database (file "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf") but it's encrypted using a key derived from the administrator password so it'd still be needed anyway. Refer to https://www.hmailserver.com/documentation/v5.4/?page=howto_connect_to_mssql
		2. Stored locally because it need to be periodically and automatically / programmatically used.
		3. Encrypted and stored alongside the keyfile because the only real alternative is using the encryption offered by DPAPI (used in [Export|Import]-CliXml, etc) which was the first method we used but, as it uses keys derived from the users on the computer / system, we found that it's incompatible with the model of the script being setup by a user and executed as the system such as via a Windows service with Certify The Web.

.NOTES
	Author:					Ben Hooper at Astrix
	Tested on:				Certify the Web v4.0.8 to v4.1.6 (latest), OpenSSL v1.1.0h to v1.1.1c (latest), and hMailServer v5.6.7 (latest) on Windows Server 2016 and Windows Server 2019 v1809
	Version:				1.14
	Changes in v1.14 (2019/11/21):		Upgraded digital signature / hash algorithm from SHA-1 to SHA-256.
	Changes in v1.13 (2019/10/01):		Added support for wildcard certificates (as requested / reported by @D4rkiii at https://github.com/astrixsystems/Update-hMailServerCertificate/issues/1)
	Changes in v1.12 (2019/08/29):		Changed OpenSSL prerequisite by (1) moving it to #1 as it's the one that the user is least likely to be prepared for, (2) offering sources to obtain OpenSSL, and (3) requiring that the EXE has content.
	Changes in v1.11 (2019/08/27):		Changed OpenSSL switch for exporting public certificate from "-clcerts" to "-chain", as reported by mflorezm and jljtgr at https://community.certifytheweb.com/t/powershell-script-for-hmailserver/585/5
	Changes in v1.10 (2019/08/23):		Added thumbprint validation, added option to auto-restart hMailServer, changed default preferences to "No" to fail safe, enhanced output of "Obtained matching certificate" by including what store it was obtained from, added additional validation check for the OpenSSL path requiring that it's an EXE file.
	Changes in v1.9 (2019/08/22):		Fixed problem where auto-elevation would lose parameters; added checking of write access to log file; fixed problem with write access to log file when starting new sessions; enhanced output by (1) changing output type from "performing action-action result" with just "action result" which makes it easier to read, (2) adding tags ("[Success]:", "[ERROR]:") for quick checking of results, and (3) using colours; and fixed issue where Read-Host output wasn't included in logs.
	Changes in v1.8 (2019/08/20):		Added checking of hMailServer credentials, added notification of storing sensitive data, enhanced port updating logic and output, added handling of empty paths, added status checks for most actions.
	Changes in v1.7 (2019/08/19):		Added option to specify thumbprint, added automatic administrator elevation option, added checking of whether the private key exists, added removal of credential variables from memory, fixed issue of log parameters not being preserved when auto-restarting, added trimming of the non-subject DN, rephrased output for prerequisite checks, added to description explaining reasons around admin password, and tidied up logic around handling of first run or not.
	Changes in v1.6 (2019/08/13):		Code-signed, renamed removing "SSL", and restructured "Changes in vX" to include dates.
	Changes in v1.5 (2019/08/06 13:28):	Added tweaks to make this more user-friendly (option to auto re-run after initial setup, auto strip out quotation marks from paths, etc).
	Changes in v1.4 (2019/08/06 09:21):	Added logging by default for auto mode.
	Changes in v1.3 (2019/08/06 09:26):	Added path validation.
	Changes in v1.2 (2019/08/05):		Added proper setup process for credentials, paths, etc.
	Changes in v1.1 (2019/04/23):		Formalised script with a proper structure.
	Changes in v1.0 (2018/09/17):		Created.
	
.PARAMETER Thumbprint
	Uses the certificate that has the specified thumbprint / hash instead of the default which is the most recent one installed in the local computer account's personal store.

.PARAMETER LogOutput
	Logs the output to the default file path "C:\<hostname>.Update-hMailServerCertificate.log".
	
.PARAMETER LogFile
	When used in combination with -LogOutput, logs the output to the custom specified file path.

.EXAMPLE
	Run with the default settings:
		Update-hMailServerCertificate
		
.EXAMPLE
	Run with specified certificate thumbprint:
		Update-hMailServerCertificate -Thumbprint 0000000000000000000000000000000000000000
		
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
	[string]$Thumbprint,
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
$global:hMailServer_Admin_Username = "Administrator";

$LogPath_Default = "$global:Script_Root\$env:computername`_$global:Script_PS1File_Name.log";

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Run-FirstSetup {
	Param()
	
	Begin {
		Write-Host "Configuration files not found. Starting initial setup...";
	}
	
	Process {
		Try {
			Write-Host "`tDue to technical restrictions, this script must store 1 password and 2 private keys in local files. Would you still like to proceed? (y/n)";
			$Proceed_General = Read-Host "`t[Input]";
	
			If (($Proceed_General -Like "y") -Or ($Proceed_General -Like "yes")){
				Write-Host "`t'Yes' selected. Proceeding...";
				Write-Host "";
			} Else {
				Write-Host "`t'No' selected. Exiting...";
				
				Break;
			}
			
			Write-Host "`t(1/4) OpenSSL's EXE file is required to create certain certificate files. Please enter the path below:";
			Write-Host "`tThe source can be obtained from https://github.com/openssl/openssl/releases and EXE files can be obtained from https://wiki.openssl.org/index.php/Binaries.";
			
			$OpenSSL_FullPath_Validity = $False;
			While ($OpenSSL_FullPath_Validity -Eq $False){
				$OpenSSL_FullPath = Read-Host "`t`t[Input]";
				
				# Remove quotation marks, if any
				$OpenSSL_FullPath = $OpenSSL_FullPath -Replace '"','';
				$OpenSSL_FullPath = $OpenSSL_FullPath -Replace "'","";
				
				$OpenSSL_Extension = [IO.Path]::GetExtension($OpenSSL_FullPath);
				
				If (($OpenSSL_FullPath) -And (Test-Path -Path $OpenSSL_FullPath -PathType Leaf) -And ($OpenSSL_Extension -Like ".exe") -And (Get-Content $OpenSSL_FullPath) -Ne $Null) {
					Write-Host -ForegroundColor Green "`t`t[Success]: EXE file path validated.";
					
					$OpenSSL_FullPath_Validity = $True;
				} Else {
					Write-Host -ForegroundColor Red "`t`t[ERROR]: EXE file path is invalid. Please ensure that the file and path are valid and accessible by this script.";
					
				}
				
				Write-Host "";
			}
			
			Write-Host "`t(2/4) hMailServer can only be modified using the administrator password. Please enter this in the popup window. This will be encrypted.";
			
			$hMailServer_AdminPassword_Validity = $False;
			While ($hMailServer_AdminPassword_Validity -Eq $False){
				$hMailServer_AdminPassword_Secure = (Get-Credential -Credential "Administrator").Password;
				$hMailServer_AdminPassword_BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($hMailServer_AdminPassword_Secure);
				$hMailServer_AdminPassword_Plaintext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($hMailServer_AdminPassword_BSTR);
				
				$hMailServer = New-Object -ComObject hMailServer.Application;
				$hMailServer_AuthResults = $hMailServer.Authenticate($global:hMailServer_Admin_Username, $hMailServer_AdminPassword_Plaintext);
				
				If ($hMailServer_AuthResults -Eq $Null){
					Write-Host -ForegroundColor Red "`t`t[ERROR]: Credentials are invalid. Please ensure that they are correct and try entering them again.";
				} Else {
					Write-Host -ForegroundColor Green "`t`t[Success]: Credentials validated.";
					
					$hMailServer_AdminPassword_Validity = $True;
				}
			}
			
			Write-Host "";
			
			# "32" = 32 bytes = 256 bits
			$AESKey = New-Object Byte[] 32;
			[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey);
			
			If ($AESKey){
				Write-Host -ForegroundColor Green "`t`t[Success]: Generated 256-bit AES key.";
				Write-Host "";
			} Else {
				Write-Host -ForegroundColor Red "`t`t[ERROR]: Could not generate 256-bit AES key. Exiting...";
				
				Break;
			}
			
			
			$AESKey | Out-File $global:Script_KeyFile_FullPath;
			
			If ((Get-Content $global:Script_KeyFile_FullPath) -Eq $Null) {
				Write-Host -ForegroundColor Red "`t`t[ERROR]: Could not store 256-bit AES key in file '$global:Script_KeyFile_FullPath'. Exiting...";
				
				Break;
			} Else {
				Write-Host -ForegroundColor Green "`t`t[Success]: Stored 256-bit AES key in file.";
				Write-Host "`t`tPath: '$global:Script_KeyFile_FullPath'";
				Write-Host "";
			}
			
			$hMailServer_AdminPassword_Secure | ConvertFrom-SecureString -Key (Get-Content $global:Script_KeyFile_FullPath) | Set-Content $global:Script_PasswordFile_FullPath;
			If ((Get-Content $global:Script_PasswordFile_FullPath) -Eq $Null) {
				Write-Host -ForegroundColor Red "`t`t[ERROR]: Could not encrypt password using 256-bit AES key and store in file '$global:Script_PasswordFile_FullPath'. Exiting...";
				
				Break;
			} Else {
				Write-Host -ForegroundColor Green "`t`t[Success]: Encrypted password using 256-bit AES key and stored in file.";
				Write-Host "`t`tPath: '$global:Script_PasswordFile_FullPath'";
				Write-Host "";
			}
			
			Write-Host "`t(3/4) A folder is required to store hMailServer's SSL / TLS certificates. Please enter the path below:";
			
			$hMailServer_SSLCert_Path_Validity = $False;
			While ($hMailServer_SSLCert_Path_Validity -Eq $False){
				$hMailServer_SSLCert_Path = Read-Host "`t`t[Input]";
				
				# Remove quotation marks, if any
				$hMailServer_SSLCert_Path = $hMailServer_SSLCert_Path -Replace '"','';
				$hMailServer_SSLCert_Path = $hMailServer_SSLCert_Path -Replace "'","";
				
				If (($hMailServer_SSLCert_Path) -And (Test-Path -Path $hMailServer_SSLCert_Path -PathType Container)) {
					Write-Host -ForegroundColor Green "`t`t[Success]: Folder path validated.";
					
					$hMailServer_SSLCert_Path_Validity = $True;
				} Else {
					Write-Host -ForegroundColor Red "`t`t[ERROR]: Folder path is invalid. Please ensure that the path is valid and accessible by this script.";
				}
				
				Write-Host "";
			}
			
			Write-Host "`t(4/4) hMailServer must be restarted for certificate and port changes to take effect. Would you like this to be done automatically? (y/n)";
			$Proceed_hMailServer_Restart = Read-Host "`t`t[Input]";
	
			If (($Proceed_hMailServer_Restart -Like "y") -Or ($Proceed_hMailServer_Restart -Like "yes")){
				Write-Host "`t`t'Yes' selected.";
				
				$hMailServer_Restart = $True;
			} Else {
				Write-Host "`t`t'No' selected.";
				
				$hMailServer_Restart = $False;
			}
			
			Write-Host "";
			
			$global:Script_ConfigFile_Content = @"
<?xml version="1.0"?>
<ScriptSettings>
	<hMailServerSettings>
		<CertificateFolderPath>$hMailServer_SSLCert_Path</CertificateFolderPath>
		<RestartServer>$hMailServer_Restart</RestartServer>
	</hMailServerSettings>
	<OpenSSLSettings>
		<OpenSSLFullPath>$OpenSSL_FullPath</OpenSSLFullPath>
	</OpenSSLSettings>
</ScriptSettings>
"@
# The above here-string terminator cannot be indented for some reason;
			
			New-Item -Path $global:Script_ConfigFile_FullPath -ItemType File -Force | Out-Null;
			Set-Content -Path $global:Script_ConfigFile_FullPath -Value $global:Script_ConfigFile_Content;
			
			If ((Get-Content $global:Script_ConfigFile_FullPath) -Eq $Null) {
				Write-Host -ForegroundColor Red "`t[ERROR]: Could not store generic configuration in file '$global:Script_ConfigFile_FullPath'. Exiting...";
				
				Break;
			} Else {
				Write-Host -ForegroundColor Green "`t[Success]: Stored generic configuration in file.";
				Write-Host "`tPath: '$global:Script_ConfigFile_FullPath'";
				Write-Host "";
			}
			
			# Remove credentials from memory. https://get-powershellblog.blogspot.com/2017/06/how-safe-are-your-strings.html
			$hMailServer_AdminPassword_Secure = $Null;
			$hMailServer_AdminPassword_BSTR = $Null;
			$hMailServer_AdminPassword_Plaintext = $Null;
			$AESKey = $Null;
			[System.GC]::Collect();
		}
		
		Catch {
			Write-Host -ForegroundColor Red "[ERROR]: Initial setup failed.";
			$_.Exception.Message;
			$_.Exception.ItemName;
			Break;
		}
	}
	
	End {
		If($?){
			Write-Host -ForegroundColor Green "[Success]: Initial setup complete.";
		}
	}
}

Function Update-hMailServerCertificate {
	Param()
	
	Begin {
		Write-Host "Updating hMailServer's SSL / TLS certificate...";
	}
	
	Process {
		Try {			
			$hMailServer_AdminPassword_Secure = Get-Content $global:Script_PasswordFile_FullPath | ConvertTo-SecureString -Key (Get-Content $global:Script_KeyFile_FullPath);
			$hMailServer_AdminPassword_BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($hMailServer_AdminPassword_Secure);
			$hMailServer_AdminPassword_Plaintext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($hMailServer_AdminPassword_BSTR);
			
			[xml]$Script_ConfigFile_Content = Get-Content $global:Script_ConfigFile_FullPath;

			$hMailServer_SSLCert_Path = $Script_ConfigFile_Content.ScriptSettings.hMailServerSettings.CertificateFolderPath;
			$hMailServer_Restart = $Script_ConfigFile_Content.ScriptSettings.hMailServerSettings.RestartServer;

			$OpenSSL_FullPath = $Script_ConfigFile_Content.ScriptSettings.OpenSSLSettings.OpenSSLFullPath;
			
			If (($hMailServer_AdminPassword_Secure) -And ($Script_ConfigFile_Content) -And ($hMailServer_SSLCert_Path) -And ($OpenSSL_FullPath)) {
				Write-Host -ForegroundColor Green "`t`t[Success]: Loaded existing settings.";
				Write-Host "";
			} Else {
				Write-Host -ForegroundColor Red "`t`t[ERROR]: Could not load existing settings. Exiting...";
				
				Break;
			}
			
			If ($Thumbprint){
				Write-Host "`t`tThumbprint specified. Obtaining certificate...";
				
				$Regex_SHA = "[0-9a-fA-F]{40}";
				
				If ($Thumbprint -Match $Regex_SHA){
					Write-Host -ForegroundColor Green "`t`t`t[Success]: Thumbprint validated.";
					Write-Host "";
				} Else {
					Write-Host -ForegroundColor Red "`t`t`t[ERROR]: Thumbprint invalid. Exiting...";
					
					Break;
				}
				
				$Windows_SSLCert = Get-ChildItem -Path "Cert:\" -Recurse | Where { $_.Thumbprint -Eq $Thumbprint };
			} Else {
				Write-Host "`t`tThumbprint not specified. Obtaining certificate...";
				
				$Windows_SSLCert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Sort-Object -Property NotAfter -Descending | Select-Object -First 1;
			}

			If ($Windows_SSLCert){
				$Windows_SSLCert_IssuedDate = $Windows_SSLCert.NotBefore.ToString("yyyy-MM-dd");
				$Windows_SSLCert_Subject = $Windows_SSLCert.Subject.Replace("CN=","").Split(",")[0];
				$Windows_SSLCert_Thumbprint = $Windows_SSLCert.Thumbprint;
				$Windows_SSLCert_Path = $Windows_SSLCert.PSParentPath.Split("::")[2];
				$Windows_SSLCert_Name = "$Windows_SSLCert_IssuedDate - $Windows_SSLCert_Subject";
				$Windows_SSLCert_File_Name = $Windows_SSLCert_Name.Replace("*","%WILDCARD%");
				$Windows_SSLCert_File_PathAndName = "$hMailServer_SSLCert_Path\$Windows_SSLCert_File_Name";
				$Windows_SSLCert_File_PFX = "$Windows_SSLCert_File_PathAndName.pfx";
				$Windows_SSLCert_File_KEY_Private = "$Windows_SSLCert_File_PathAndName - private.key";
				$Windows_SSLCert_File_CRT_Public = "$Windows_SSLCert_File_PathAndName - public.crt";
				
				If ($Thumbprint){
					Write-Host -ForegroundColor Green "`t`t`t[Success]: Obtained matching certificate.";
					Write-Host "`t`t`tPath: '$Windows_SSLCert_Path'";
				} Else {
					Write-Host -ForegroundColor Green "`t`t`t[Success]: Obtained newest certificate from store Local Computer | Personal | Certificates.";
				}
				
				Write-Host "`t`t`tSubject: '$Windows_SSLCert_Subject'";
				Write-Host "`t`t`tIssued date: $Windows_SSLCert_IssuedDate";
				Write-Host "`t`t`tThumbprint: $Windows_SSLCert_Thumbprint";
				Write-Host "";
				
			} Else {
				Write-Host -ForegroundColor Red "`t`t`t[ERROR]: A certificate could not be obtained. Exiting...";
				
				Break;
			}
			
			If (($Windows_SSLCert.HasPrivateKey -Eq $True) -And ($Windows_SSLCert.PrivateKey)){
				Write-Host -ForegroundColor Green "`t`t`t[Success]: Verified that the certificate has a corresponding private key.";
				Write-Host "";
			} Else {
				Write-Host -ForegroundColor Red "`t`t`t[ERROR]: Could not verify that the certificate has a corresponding private key. Exiting...";
				
				Break;
			}
			
			Write-Host "`t`tExporting files...";
			
			# Generate a random, 30-character password required for the PFX file and store it in a variable to be reused in OpenSSL commands
			Add-Type -AssemblyName System.Web;
			$Windows_SSLCert_Password_Plaintext = [System.Web.Security.Membership]::GeneratePassword(30, 5);
			
			# Convert the password to a format accepted by the export command
			$Windows_SSLCert_Password_Secure = ConvertTo-SecureString -String $Windows_SSLCert_Password_Plaintext -Force -AsPlainText;
			
			If (($Windows_SSLCert_Password_Plaintext) -And ($Windows_SSLCert_Password_Secure)){
				Write-Host -ForegroundColor Green "`t`t`t[Success]: Generated random, 30-character password for the upcoming PFX file.";
				Write-Host "";
			} Else {
				Write-Host -ForegroundColor Red "`t`t`t[ERROR]: Could not generate random, 30-character password for the upcoming PFX file. Exiting...";
				
				Break;
			}
			
			Export-PfxCertificate -Cert $Windows_SSLCert -FilePath $Windows_SSLCert_File_PFX -Password $Windows_SSLCert_Password_Secure | Out-Null;
			
			If ((Get-Content $Windows_SSLCert_File_PFX) -Eq $Null) {
				Write-Host -ForegroundColor Red "`t`t`t[ERROR]: Could not export certificate with private key to password-protected file '$Windows_SSLCert_File_PFX'. Exiting...";
				
				Break;
			} Else {
				Write-Host -ForegroundColor Green "`t`t`t[Success]: Exported certificate with private key to password-protected file.";
				Write-Host "`t`t`tPath: '$Windows_SSLCert_File_PFX'";
				Write-Host "";
			}
			
			& $OpenSSL_FullPath pkcs12 -in $Windows_SSLCert_File_PFX -passin pass:$Windows_SSLCert_Password_Plaintext -nocerts -nodes -out $Windows_SSLCert_File_KEY_Private;
			
			If ((Get-Content $Windows_SSLCert_File_KEY_Private) -Eq $Null) {
				Write-Host -ForegroundColor Red "`t`t`t[ERROR]: Could not extract private key to passwordless file '$Windows_SSLCert_File_KEY_Private'. Exiting...";
				
				Break;
			} Else {
				Write-Host -ForegroundColor Green "`t`t`t[Success]: Extracted private key to passwordless file.";
				Write-Host "`t`t`tPath: '$Windows_SSLCert_File_KEY_Private'";
				Write-Host "";
			}
			
			& $OpenSSL_FullPath pkcs12 -in $Windows_SSLCert_File_PFX -passin pass:$Windows_SSLCert_Password_Plaintext -clcerts -nokeys -out $Windows_SSLCert_File_CRT_Public;
			
			If ((Get-Content $Windows_SSLCert_File_CRT_Public) -Eq $Null) {
				Write-Host -ForegroundColor Red "`t`t`t[ERROR]: Could not extract public key and certificate to file '$Windows_SSLCert_File_CRT_Public'. Exiting...";
				
				Break;
			} Else {
				Write-Host -ForegroundColor Green "`t`t`t[Success]: Extracted public key and certificate to file.";
				Write-Host "`t`t`tPath: '$Windows_SSLCert_File_CRT_Public'";
				Write-Host "";
			}
			
			Write-Host "`t`tUpdating hMailServer...";
			
			$hMailServer = New-Object -ComObject hMailServer.Application;
			$hMailServer_AuthResults = $hMailServer.Authenticate($global:hMailServer_Admin_Username, $hMailServer_AdminPassword_Plaintext);
			
			If ($hMailServer_AuthResults -Eq $Null){
				Write-Host -ForegroundColor Red "`t`t`t[ERROR]: Could not connect and authenticate. Please delete file '$global:Script_PasswordFile_FullPath', re-run this script, and ensure that the submitted hMailServer administrator password is correct. Exiting...";
				
				Break;
			} Else {
				Write-Host -ForegroundColor Green "`t`t`t[Success]: Connected and authenticated.";
				Write-Host "";
			}
			
			$hMailServer_SSLCert_New = $hMailServer.Settings.SSLCertificates.Add();
			$hMailServer_SSLCert_New.Name = $Windows_SSLCert_Name;
			$hMailServer_SSLCert_New.PrivateKeyFile = $Windows_SSLCert_File_KEY_Private;
			$hMailServer_SSLCert_New.CertificateFile = $Windows_SSLCert_File_CRT_Public;
			$hMailServer_SSLCert_New.Save();
			# Once certificate object has been created, obtain ID 
			$hMailServer_SSLCert_New_ID = $hMailServer_SSLCert_New.ID;
			
			If ($hMailServer_SSLCert_New_ID) {
				Write-Host -ForegroundColor Green "`t`t`t[Success]: Added certificate '$Windows_SSLCert_Name' and set paths.";
				Write-Host "";
			} Else {
				Write-Host -ForegroundColor Red "`t`t`t[ERROR]: Could not add certificate '$Windows_SSLCert_Name' and set paths. Exiting...";
				
				Break;
			}

			Write-Host "`t`t`tSetting new certificate for secure TCP/IP ports...";
			
			$hMailServer_TCPIPPort_All = $hMailServer.Settings.TCPIPPorts;
			For ($i = 0; $i -NE $hMailServer_TCPIPPort_All.Count; $i++){
				$hMailServer_TCPIPPort_Current = $hMailServer_TCPIPPort_All.Item($i);
				
				If ($hMailServer_TCPIPPort_Current.Protocol -Eq 1){
					$hMailServer_TCPIPPort_Current_Protocol = "SMTP";
				} ElseIf ($hMailServer_TCPIPPort_Current.Protocol -Eq 3){
					$hMailServer_TCPIPPort_Current_Protocol = "POP3";
				} ElseIf ($hMailServer_TCPIPPort_Current.Protocol -Eq 5){
					$hMailServer_TCPIPPort_Current_Protocol = "IMAP";
				}
				
				$hMailServer_TCPIPPort_Current_Port = $hMailServer_TCPIPPort_Current.PortNumber;
				
				If ($hMailServer_TCPIPPort_Current.ConnectionSecurity -Eq 0){
					$hMailServer_TCPIPPort_Current_ConnectionSecurity = "None";
				} ElseIf ($hMailServer_TCPIPPort_Current.ConnectionSecurity -Eq 1){
					$hMailServer_TCPIPPort_Current_ConnectionSecurity = "SSL/TLS";
				} ElseIf ($hMailServer_TCPIPPort_Current.ConnectionSecurity -Eq 2){
					$hMailServer_TCPIPPort_Current_ConnectionSecurity = "STARTTLS (Optional)";
				} ElseIf ($hMailServer_TCPIPPort_Current.ConnectionSecurity -Eq 3){
					$hMailServer_TCPIPPort_Current_ConnectionSecurity = "STARTTLS (Required)";
				}
				
				If (($hMailServer_TCPIPPort_Current_ConnectionSecurity) -And ($hMailServer_TCPIPPort_Current_ConnectionSecurity -Ne "None")){
					$hMailServer_TCPIPPort_Current.SSLCertificateID = $hMailServer_SSLCert_New_ID;
					$hMailServer_TCPIPPort_Current.Save();
					
					If ($hMailServer_TCPIPPort_Current.SSLCertificateID -Eq $hMailServer_SSLCert_New_ID) {
						Write-Host -ForegroundColor Green "`t`t`t`t[Success]: Updated port with protocol $hMailServer_TCPIPPort_Current_Protocol, number $hMailServer_TCPIPPort_Current_Port, and connection security '$hMailServer_TCPIPPort_Current_ConnectionSecurity'.";
						Write-Host "";
					} Else {
						Write-Host -ForegroundColor Red "`t`t`t`t[ERROR]: Could not update port with protocol $hMailServer_TCPIPPort_Current_Protocol, number $hMailServer_TCPIPPort_Current_Port, and connection security '$hMailServer_TCPIPPort_Current_ConnectionSecurity'.";
					}
				}
			}
			
			If ($hMailServer_Restart -Eq $True){
				Write-Host "`t`t`thMailServer restart was opted into during initial setup.";
				
				Restart-Service -Name hMailServer -Force -ErrorAction SilentlyContinue;
				
				If ($? -Eq $True){
					Write-Host -ForegroundColor Green "`t`t`t[Success]: Restarted Windows service 'hMailServer'.";
				} Else {
					Write-Host -ForegroundColor Red "`t`t`t[ERROR]: Could not restart Windows service 'hMailServer'.";
				}
			} Else {
				Write-Host "`t`t`t[Notification]: Windows service 'hMailServer' needs restarting.";
			}
			
			Write-Host "";
			
			# Remove credentials from memory. https://get-powershellblog.blogspot.com/2017/06/how-safe-are-your-strings.html
			$Windows_SSLCert_Password_Plaintext = $Null;
			$Windows_SSLCert_Password_Secure = $Null;
			$hMailServer_AdminPassword_Secure = $Null;
			$hMailServer_AdminPassword_BSTR = $Null;
			$hMailServer_AdminPassword_Plaintext = $Null;
			[System.GC]::Collect();
		}
		
		Catch {
			Write-Host -ForegroundColor Red "[ERROR]: Could not update hMailServer's SSL / TLS certificate.";
			$_.Exception.Message;
			$_.Exception.ItemName;
			Break;
		}
	}
	
	End {
		If($?){
			Write-Host -ForegroundColor Green "[Success]: Updated hMailServer's SSL / TLS certificate.";
		}
	}
}





#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Check whether initial setup has been completed
If ((Test-Path -Path $global:Script_ConfigFile_FullPath) -And (Test-Path -Path $global:Script_PasswordFile_FullPath) -And (Test-Path -Path $global:Script_KeyFile_FullPath)) {
	$global:FirstRun = $False;
} Else {
	$global:FirstRun = $True;
}

If (-Not $LogPath) {
	$LogPath = $LogPath_Default;
}

# Check write access to log file
If ($LogOutput -Eq $True) {
	Try {
		[io.file]::OpenWrite($LogPath).Close();
	}
	Catch {
		Write-Host -ForegroundColor Red "[ERROR]: Unable to log output to file '$LogPath' due to insufficient permissions.";
		Write-Host "";
		
		$LogOutput = $False;
	}
}

# Set up logging
If ($LogOutput -Eq $True) {
	Start-Transcript -Path $LogPath -Append | Out-Null;
	
	If ($global:FirstRun -Eq $True){
		Write-Host "Logging output to file.";
	} ElseIf ($global:FirstRun -Eq $False){
		Write-Host "Initial setup has already been completed so assuming automatic mode and logging output to file.";
	}
	Write-Host "Path: '$LogPath'" 
	
	Write-Host "";
	Write-Host "----------------------------------------------------------------";
	Write-Host "";
}

# Handle admin
If ($RunAsAdministrator -Eq $False) {
	Write-Host "This script requires administrative permissions but was not run as administrator. Elevate now? (y/n)";
	$Elevate = Read-Host "[Input]";

	If (($Elevate -Like "y") -Or ($Elevate -Like "yes")){
		Write-Host "'Yes' selected. Launching a new session in a new window and ending this session...";
		
		# Preserve original parameters
		$AllParameters_String = "";
		ForEach ($Parameter in $PsBoundParameters.GetEnumerator()){
			$Parameter_Key = $Parameter.Key;
			$Parameter_Value = $Parameter.Value;
			$Parameter_Value_Type = $Parameter_Value.GetType().Name;
			
			If ($Parameter_Value_Type -Eq "SwitchParameter"){
				$AllParameters_String += " -$Parameter_Key";
				
			} Else {
				$AllParameters_String += " -$Parameter_Key $Parameter_Value";
			}
		}
		
		$Arguments = ' -NoExit -File "' + $global:Script_PS1File_FullPath + '"' + $AllParameters_String;
		
		If ($LogOutput -Eq $True) {
			Stop-Transcript | Out-Null;
		}
		
		Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $Arguments;
		
		# Stop-Process -Id $PID;
		
		Break;
	} Else {
		Write-Host "'No' selected. Exiting...";
		
		If ($LogOutput -Eq $True) {
			Stop-Transcript | Out-Null;
		}
		
		Break;
	}
}

# Execute main functions
If ($global:FirstRun -Eq $True) {
	Run-FirstSetup;
	
	Write-Host "";
	Write-Host "Re-run this script to actually update hMailServer? (y/n)";
	$ReRun = Read-Host "[Input]";
	
	If (($ReRun -Like "y") -Or ($ReRun -Like "yes")){
		Write-Host "";
		Write-Host "----------------------------------------------------------------";
		Write-Host "";
		Write-Host "                      ...RESTARTING...";
		Write-Host "";
		Write-Host "----------------------------------------------------------------";
		Write-Host "";
		
		If ($LogOutput -Eq $True) {
			Stop-Transcript | Out-Null;
		}
			
		& $global:Script_PS1File_FullPath -NoExit @PSBoundParameters;
		
		Break;
	}
} ElseIf ($global:FirstRun -Eq $False){
	Update-hMailServerCertificate;
}

Write-Host "";
Write-Host "----------------------------------------------------------------";
Write-Host "";

Write-Host "Script complete.";

<#
If ($Host.Name -Eq "ConsoleHost"){
    Write-Host "Script complete. Press any key to continue..."
    $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") > $null
}
#>

If ($LogOutput -Eq $True) {
	Stop-Transcript | Out-Null;
}
# SIG # Begin signature block
# MIIkjwYJKoZIhvcNAQcCoIIkgDCCJHwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDmflJh/ObZMYXG
# LyH3SPBMMo46f7pkecm+FmYCEzDsaqCCH3YwggSEMIIDbKADAgECAhBCGvKUCYQZ
# H1IKS8YkJqdLMA0GCSqGSIb3DQEBBQUAMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQK
# EwtBZGRUcnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5l
# dHdvcmsxIjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3QwHhcNMDUw
# NjA3MDgwOTEwWhcNMjAwNTMwMTA0ODM4WjCBlTELMAkGA1UEBhMCVVMxCzAJBgNV
# BAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2UgQ2l0eTEeMBwGA1UEChMVVGhlIFVT
# RVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExhodHRwOi8vd3d3LnVzZXJ0cnVzdC5j
# b20xHTAbBgNVBAMTFFVUTi1VU0VSRmlyc3QtT2JqZWN0MIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAzqqBP6OjYXiqMQBVlRGeJw8fHN86m4JoMMBKYR3x
# Lw76vnn3pSPvVVGWhM3b47luPjHYCiBnx/TZv5TrRwQ+As4qol2HBAn2MJ0Yipey
# qhz8QdKhNsv7PZG659lwNfrk55DDm6Ob0zz1Epl3sbcJ4GjmHLjzlGOIamr+C3bJ
# vvQi5Ge5qxped8GFB90NbL/uBsd3akGepw/X++6UF7f8hb6kq8QcMd3XttHk8O/f
# Fo+yUpPXodSJoQcuv+EBEkIeGuHYlTTbZHko/7ouEcLl6FuSSPtHC8Js2q0yg0Hz
# peVBcP1lkG36+lHE+b2WKxkELNNtp9zwf2+DZeJqq4eGdQIDAQABo4H0MIHxMB8G
# A1UdIwQYMBaAFK29mHo0tCb3+sQmVO8DveAky1QaMB0GA1UdDgQWBBTa7WR0FJwU
# PKvdmam9WyhNizzJ2DAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAR
# BgNVHSAECjAIMAYGBFUdIAAwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2NybC51
# c2VydHJ1c3QuY29tL0FkZFRydXN0RXh0ZXJuYWxDQVJvb3QuY3JsMDUGCCsGAQUF
# BwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTAN
# BgkqhkiG9w0BAQUFAAOCAQEATUIvpsGK6weAkFhGjPgZOWYqPFosbc/U2YdVjXkL
# Eoh7QI/Vx/hLjVUWY623V9w7K73TwU8eA4dLRJvj4kBFJvMmSStqhPFUetRC2vzT
# artmfsqe6um73AfHw5JOgzyBSZ+S1TIJ6kkuoRFxmjbSxU5otssOGyUWr2zeXXbY
# H3KxkyaGF9sY3q9F6d/7mK8UGO2kXvaJlEXwVQRK3f8n3QZKQPa0vPHkD5kCu/1d
# Di4owb47Xxo/lxCEvBY+2KOcYx1my1xf2j7zDwoJNSLb28A/APnmDV1n0f2gHgMr
# 2UD3vsyHZlSApqO49Rli1dImsZgm7prLRKdFWoGVFRr1UTCCBOYwggPOoAMCAQIC
# EGJcTZCM1UL7qy6lcz/xVBkwDQYJKoZIhvcNAQEFBQAwgZUxCzAJBgNVBAYTAlVT
# MQswCQYDVQQIEwJVVDEXMBUGA1UEBxMOU2FsdCBMYWtlIENpdHkxHjAcBgNVBAoT
# FVRoZSBVU0VSVFJVU1QgTmV0d29yazEhMB8GA1UECxMYaHR0cDovL3d3dy51c2Vy
# dHJ1c3QuY29tMR0wGwYDVQQDExRVVE4tVVNFUkZpcnN0LU9iamVjdDAeFw0xMTA0
# MjcwMDAwMDBaFw0yMDA1MzAxMDQ4MzhaMHoxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# ExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoT
# EUNPTU9ETyBDQSBMaW1pdGVkMSAwHgYDVQQDExdDT01PRE8gVGltZSBTdGFtcGlu
# ZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKqC8YSpW9hxtdJd
# K+30EyAM+Zvp0Y90Xm7u6ylI2Mi+LOsKYWDMvZKNfN10uwqeaE6qdSRzJ6438xqC
# pW24yAlGTH6hg+niA2CkIRAnQJpZ4W2vPoKvIWlZbWPMzrH2Fpp5g5c6HQyvyX3R
# TtjDRqGlmKpgzlXUEhHzOwtsxoi6lS7voEZFOXys6eOt6FeXX/77wgmN/o6apT9Z
# RvzHLV2Eh/BvWCbD8EL8Vd5lvmc4Y7MRsaEl7ambvkjfTHfAqhkLtv1Kjyx5VbH+
# WVpabVWLHEP2sVVyKYlNQD++f0kBXTybXAj7yuJ1FQWTnQhi/7oN26r4tb8QMspy
# 6ggmzRkCAwEAAaOCAUowggFGMB8GA1UdIwQYMBaAFNrtZHQUnBQ8q92Zqb1bKE2L
# PMnYMB0GA1UdDgQWBBRkIoa2SonJBA/QBFiSK7NuPR4nbDAOBgNVHQ8BAf8EBAMC
# AQYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNV
# HSAECjAIMAYGBFUdIAAwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybC51c2Vy
# dHJ1c3QuY29tL1VUTi1VU0VSRmlyc3QtT2JqZWN0LmNybDB0BggrBgEFBQcBAQRo
# MGYwPQYIKwYBBQUHMAKGMWh0dHA6Ly9jcnQudXNlcnRydXN0LmNvbS9VVE5BZGRU
# cnVzdE9iamVjdF9DQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0
# cnVzdC5jb20wDQYJKoZIhvcNAQEFBQADggEBABHJPeEF6DtlrMl0MQO32oM4xpK6
# /c3422ObfR6QpJjI2VhoNLXwCyFTnllG/WOF3/5HqnDkP14IlShfFPH9Iq5w5Lfx
# sLZWn7FnuGiDXqhg25g59txJXhOnkGdL427n6/BDx9Avff+WWqcD1ptUoCPTpcKg
# jvlP0bIGIf4hXSeMoK/ZsFLu/Mjtt5zxySY41qUy7UiXlF494D01tLDJWK/HWP9i
# dBaSZEHayqjriwO9wU6uH5EyuOEkO3vtFGgJhpYoyTvJbCjCJWn1SmGt4Cf4U6d1
# FbBRMbDxQf8+WiYeYH7i42o5msTq7j/mshM/VQMETQuQctTr+7yHkFGyOBkwggT+
# MIID5qADAgECAhArc9t0YxFMWlsySvIwV3JJMA0GCSqGSIb3DQEBBQUAMHoxCzAJ
# BgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcT
# B1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSAwHgYDVQQDExdD
# T01PRE8gVGltZSBTdGFtcGluZyBDQTAeFw0xOTA1MDIwMDAwMDBaFw0yMDA1MzAx
# MDQ4MzhaMIGDMQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVz
# dGVyMRAwDgYDVQQHDAdTYWxmb3JkMRgwFgYDVQQKDA9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMMIlNlY3RpZ28gU0hBLTEgVGltZSBTdGFtcGluZyBTaWduZXIwggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/UjaCOtx0Nw141X8WUBlm7boa
# mdFjOJoMZrJA26eAUL9pLjYvCmc/QKFKimM1m9AZzHSqFxmRK7VVIBn7wBo6bco5
# m4LyupWhGtg0x7iJe3CIcFFmaex3/saUcnrPJYHtNIKa3wgVNzG0ba4cvxjVDc/+
# teHE+7FHcen67mOR7PHszlkEEXyuC2BT6irzvi8CD9BMXTETLx5pD4WbRZbCjRKL
# Z64fr2mrBpaBAN+RfJUc5p4ZZN92yGBEL0njj39gakU5E0Qhpbr7kfpBQO1NArRL
# f9/i4D24qvMa2EGDj38z7UEG4n2eP1OEjSja3XbGvfeOHjjNwMtgJAPeekyrAgMB
# AAGjggF0MIIBcDAfBgNVHSMEGDAWgBRkIoa2SonJBA/QBFiSK7NuPR4nbDAdBgNV
# HQ4EFgQUru7ZYLpe9SwBEv2OjbJVcjVGb/EwDgYDVR0PAQH/BAQDAgbAMAwGA1Ud
# EwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwQAYDVR0gBDkwNzA1Bgwr
# BgEEAbIxAQIBAwgwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9D
# UFMwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybC5zZWN0aWdvLmNvbS9DT01P
# RE9UaW1lU3RhbXBpbmdDQV8yLmNybDByBggrBgEFBQcBAQRmMGQwPQYIKwYBBQUH
# MAKGMWh0dHA6Ly9jcnQuc2VjdGlnby5jb20vQ09NT0RPVGltZVN0YW1waW5nQ0Ff
# Mi5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqG
# SIb3DQEBBQUAA4IBAQB6f6lK0rCkHB0NnS1cxq5a3Y9FHfCeXJD2Xqxw/tPZzeQZ
# pApDdWBqg6TDmYQgMbrW/kzPE/gQ91QJfurc0i551wdMVLe1yZ2y8PIeJBTQnMfI
# Z6oLYre08Qbk5+QhSxkymTS5GWF3CjOQZ2zAiEqS9aFDAfOuom/Jlb2WOPeD9618
# KB/zON+OIchxaFMty66q4jAXgyIpGLXhjInrbvh+OLuQT7lfBzQSa5fV5juRvgAX
# IW7ibfxSee+BJbrPE9D73SvNgbZXiU7w3fMLSjTKhf8IuZZf6xET4OHFA61XHOFd
# kga+G8g8P6Ugn2nQacHFwsk+58Vy9+obluKUr4YuMIIFdzCCBF+gAwIBAgIQE+oo
# cFv07O0MNmMJgGFDNjANBgkqhkiG9w0BAQwFADBvMQswCQYDVQQGEwJTRTEUMBIG
# A1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFsIFRU
# UCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290MB4X
# DTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowgYgxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UE
# ChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNB
# IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAgBJlFzYOw9sIs9CsVw127c0n00ytUINh4qogTQktZAnczomfzD2p
# 7PbPwdzx07HWezcoEStH2jnGvDoZtF+mvX2do2NCtnbyqTsrkfjib9DsFiCQCT7i
# 6HTJGLSR1GJk23+jBvGIGGqQIjy8/hPwhxR79uQfjtTkUcYRZ0YIUcuGFFQ/vDP+
# fmyc/xadGL1RjjWmp2bIcmfbIWax1Jt4A8BQOujM8Ny8nkz+rwWWNR9XWrf/zvk9
# tyy29lTdyOcSOk2uTIq3XJq0tyA9yn8iNK5+O2hmAUTnAU5GU5szYPeUvlM3kHND
# 8zLDU+/bqv50TmnHa4xgk97Exwzf4TKuzJM7UXiVZ4vuPVb+DNBpDxsP8yUmazNt
# 925H+nND5X4OpWaxKXwyhGNVicQNwZNUMBkTrNN9N6frXTpsNVzbQdcS2qlJC9/Y
# gIoJk2KOtWbPJYjNhLixP6Q5D9kCnusSTJV882sFqV4Wg8y4Z+LoE53MW4LTTLPt
# W//e5XOsIzstAL81VXQJSdhJWBp/kjbmUZIO8yZ9HE0XvMnsQybQv0FfQKlERPSZ
# 51eHnlAfV1SoPv10Yy+xUGUJ5lhCLkMaTLTwJUdZ+gQek9QmRkpQgbLevni3/GcV
# 4clXhB4PY9bpYrrWX1Uu6lzGKAgEJTm4Diup8kyXHAc/DVL17e8vgg8CAwEAAaOB
# 9DCB8TAfBgNVHSMEGDAWgBStvZh6NLQm9/rEJlTvA73gJMtUGjAdBgNVHQ4EFgQU
# U3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQF
# MAMBAf8wEQYDVR0gBAowCDAGBgRVHSAAMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6
# Ly9jcmwudXNlcnRydXN0LmNvbS9BZGRUcnVzdEV4dGVybmFsQ0FSb290LmNybDA1
# BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVz
# dC5jb20wDQYJKoZIhvcNAQEMBQADggEBAJNl9jeDlQ9ew4IcH9Z35zyKwKoJ8OkL
# JvHgwmp1ocd5yblSYMgpEg7wrQPWCcR23+WmgZWnRtqCV6mVksW2jwMibDN3wXsy
# F24HzloUQToFJBv2FAY7qCUkDrvMKnXduXBBP3zQYzYhBx9G/2CkkeFnvN4ffhkU
# yWNnkepnB2u0j4vAbkN9w6GAbLIevFOFfdyQoaS8Le9Gclc1Bb+7RrtubTeZtv8j
# kpHGbkD4jylW6l/VXxRTrPBPYer3IsynVgviuDQfJtl7GQVoP7o81DgGotPmjw7j
# tHFtQELFhLRAlSv0ZaBIefYdgWOWnU914Ph85I6p0fKtirOMxyHNwu8wggWKMIIE
# cqADAgECAhAHvfU0ZuEKsr2CCQl/2DeWMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNV
# BAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1Nh
# bGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGln
# byBSU0EgQ29kZSBTaWduaW5nIENBMB4XDTE5MTExNDAwMDAwMFoXDTIwMTExMzIz
# NTk1OVowgdoxCzAJBgNVBAYTAkdCMREwDwYDVQQRDAhDRjQ1IDRTTjEWMBQGA1UE
# CAwNTWlkIEdsYW1vcmdhbjEVMBMGA1UEBwwMTW91bnRhaW4gQXNoMTEwLwYDVQQJ
# DChWZW50dXJlIEhvdXNlLCBOYXZpZ2F0aW9uIFBhcmsgQWJlcmN5bm9uMSowKAYD
# VQQKDCFBc3RyaXggSW50ZWdyYXRlZCBTeXN0ZW1zIExpbWl0ZWQxKjAoBgNVBAMM
# IUFzdHJpeCBJbnRlZ3JhdGVkIFN5c3RlbXMgTGltaXRlZDCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKGf2ZK/9edFfdkmNy2Cg+j6QkBbrO2c+lrSXEB8
# +XwIr6RgqSazOksf1Pb49T0dhox4VrUtbBIuyeQnxTrj8rUCx02gmhgNdJqX7mcx
# VkZWonSKk4FOG4B+Lba/JtedvFpg2ixNuZxDWZXJpGzhge04LYTjJO2WrIbrpJ5P
# vmUFUXnhjSEKptpKyeptikqD1bUepglUo0dWk99mbD8ufRhjqIrmvCB84UaZiOIx
# 5dO9J5H+VCrJ15+HzyhS73Ho0kRCXoeMoGpnaiqyzdPARSUOoDGdzvzMkbKP52sL
# cuLLEKf0UxjveVD/fAfHvAalC+jc7c35rD5m+YDnZpmbvhECAwEAAaOCAacwggGj
# MB8GA1UdIwQYMBaAFA7hOqhTOjHVir7Bu61nGgOFrTQOMB0GA1UdDgQWBBRa0KqE
# 4L1d64xMBilKiBhoIp0TzjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAT
# BgNVHSUEDDAKBggrBgEFBQcDAzARBglghkgBhvhCAQEEBAMCBBAwQAYDVR0gBDkw
# NzA1BgwrBgEEAbIxAQIBAwIwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdv
# LmNvbS9DUFMwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5zZWN0aWdvLmNv
# bS9TZWN0aWdvUlNBQ29kZVNpZ25pbmdDQS5jcmwwcwYIKwYBBQUHAQEEZzBlMD4G
# CCsGAQUFBzAChjJodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29SU0FDb2Rl
# U2lnbmluZ0NBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5j
# b20wHwYDVR0RBBgwFoEUc3VwcG9ydEBhc3RyaXguY28udWswDQYJKoZIhvcNAQEL
# BQADggEBACol7X9UrQLifw8Q+ZH3GoRnBAcEXcb2r1DbiRi7nDOXtmt1p7iZVex8
# aQz3nTamD429kllUPm5wIYN/sicXKno/lJ6cMYIMxOLF+BAKmsmYs0JOD5qecWHQ
# gOrWwStAsmVGuNQYnUTlE/IkXMBum5OJzZRXtS9DbaXJInLsFIageSsUpZdpvTYW
# VCu88Xl0HNOb198NtfB4Y7ZvNE/zLW51uS65Cb5DcNuxLVnlVnYedfumsqWG2jrj
# ven5mNvLmLSZh/CSZUN84L6S37zm7VcZpPOjMVmecjqOvcXIuqJq9tz/93aYJqwm
# FjJaFr4gx+PzVrb9GWo70GVe8PtUzhUwggX1MIID3aADAgECAhAdokgwb5smGNCC
# 4JZ9M9NqMA0GCSqGSIb3DQEBDAUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# TmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBV
# U0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZp
# Y2F0aW9uIEF1dGhvcml0eTAeFw0xODExMDIwMDAwMDBaFw0zMDEyMzEyMzU5NTla
# MHwxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
# BgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEkMCIGA1UE
# AxMbU2VjdGlnbyBSU0EgQ29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAhiKNMoV6GJ9J8JYvYwgeLdx8nxTP4ya2JWYpQIZURnQx
# YsUQ7bKHJ6aZy5UwwFb1pHXGqQ5QYqVRkRBq4Etirv3w+Bisp//uLjMg+gwZiahs
# e60Aw2Gh3GllbR9uJ5bXl1GGpvQn5Xxqi5UeW2DVftcWkpwAL2j3l+1qcr44O2Pe
# j79uTEFdEiAIWeg5zY/S1s8GtFcFtk6hPldrH5i8xGLWGwuNx2YbSp+dgcRyQLXi
# X+8LRf+jzhemLVWwt7C8VGqdvI1WU8bwunlQSSz3A7n+L2U18iLqLAevRtn5Rhzc
# jHxxKPP+p8YU3VWRbooRDd8GJJV9D6ehfDrahjVh0wIDAQABo4IBZDCCAWAwHwYD
# VR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFA7hOqhTOjHV
# ir7Bu61nGgOFrTQOMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEA
# MB0GA1UdJQQWMBQGCCsGAQUFBwMDBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUd
# IAAwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VT
# RVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHYGCCsGAQUFBwEB
# BGowaDA/BggrBgEFBQcwAoYzaHR0cDovL2NydC51c2VydHJ1c3QuY29tL1VTRVJU
# cnVzdFJTQUFkZFRydXN0Q0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51
# c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBNY1DtRzRKYaTb3moqjJvx
# AAAeHWJ7Otcywvaz4GOz+2EAiJobbRAHBE++uOqJeCLrD0bs80ZeQEaJEvQLd1qc
# KkE6/Nb06+f3FZUzw6GDKLfeL+SU94Uzgy1KQEi/msJPSrGPJPSzgTfTt2SwpiNq
# WWhSQl//BOvhdGV5CPWpk95rcUCZlrp48bnI4sMIFrGrY1rIFYBtdF5KdX6luMNs
# tc/fSnmHXMdATWM19jDTz7UKDgsEf6BLrrujpdCEAJM+U100pQA1aWy+nyAlEA0Z
# +1CQYb45j3qOTfafDh7+B1ESZoMmGUiVzkrJwX/zOgWb+W/fiH/AI57SHkN6RTHB
# nE2p8FmyWRnoao0pBAJ3fEtLzXC+OrJVWng+vLtvAxAldxU0ivk2zEOS5LpP8WKT
# KCVXKftRGcehJUBqhFfGsp2xvBwK2nxnfn0u6ShMGH7EezFBcZpLKewLPVdQ0srd
# /Z4FUeVEeN0B3rF1mA1UJP3wTuPi+IO9crrLPTru8F4XkmhtyGH5pvEqCgulufSe
# 7pgyBYWe6/mDKdPGLH29OncuizdCoGqC7TtKqpQQpOEN+BfFtlp5MxiS47V1+KHp
# jgolHuQe8Z9ahyP/n6RRnvs5gBHN27XEp6iAb+VT1ODjosLSWxr6MiYtaldwHDyk
# WC6j81tLB9wyWfOHpxptWDGCBG8wggRrAgEBMIGQMHwxCzAJBgNVBAYTAkdCMRsw
# GQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAW
# BgNVBAoTD1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGlnbyBSU0EgQ29k
# ZSBTaWduaW5nIENBAhAHvfU0ZuEKsr2CCQl/2DeWMA0GCWCGSAFlAwQCAQUAoIGE
# MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkE
# MSIEIEZs7m9hue7eNwxvQzXUBsBOgapVFvL/mSVVLcL8SVq5MA0GCSqGSIb3DQEB
# AQUABIIBAE+H1+ytUkatB5MO6hXxzqoMwtk/9y2ysWYWw6Hao8HZa/s8KlZu+Pe7
# 1IpVUSh0uRMwm6v1TWZz2meZbNIA7pRlL1jKTi+6jC/O23aVk7StrrtddA4JIx8G
# AQvUa8Ue/Pruuz/CC+1AskHYNxRrD7MQVN53lLYWm2Gs1JxU+T2cTs8NkHnI5is3
# Po2u0q0qEZf4/LJyzLxKAmhGJBXwvsnAF/9yQN6sYcHVmUGzHO6y1Yiltc7scO5c
# taFxjM/ElyhGKPQws5EzAl/qRTMQzlKWT+6bRNu+qUVVqq/2c3Hn4CgFL0OqTnd+
# X+enXq1VDvnHjneAaibjeA1VoueOAFOhggIoMIICJAYJKoZIhvcNAQkGMYICFTCC
# AhECAQEwgY4wejELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hl
# c3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0
# ZWQxIDAeBgNVBAMTF0NPTU9ETyBUaW1lIFN0YW1waW5nIENBAhArc9t0YxFMWlsy
# SvIwV3JJMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0xOTExMjEwOTM0NDVaMCMGCSqGSIb3DQEJBDEWBBSkwSCr
# knnjTGZUH4h/jE1h5gLZTzANBgkqhkiG9w0BAQEFAASCAQBLU78E7Hdr5IHXfAxu
# VkIj1WRZFS9GUCGZOx221xr0nDRHwlz1v5BQG1yiSuAkvXLDCB++Dr4YpsAugQwo
# 2c1/wcvA4ewg5o2n533OjqRZmwSbbqQ9vBY/2AKhBf+VI0YD5CumjJPIo9Jp7jCf
# EIJujupR3UgvrV7qsgNzyeWXuuyLJsJNHVhJWTXuzi4pLWRWNRgqG9qw6dDO3ucB
# g/+ruVpin9SWDs75MEBKfTqUCqAg0Mry/RC+aPTd8ZcFCsZuUaqnfpMOTLnMk6Fy
# iegivhMtnYokxULeOpeXJjZmT6b+7GKhBcTyy1SK5oFfQB62qs37hDTKU6lIlm1O
# fdSN
# SIG # End signature block
