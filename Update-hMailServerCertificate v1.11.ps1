<#
.SYNOPSIS
	Name: Update-hMailServerCertificate.ps1
	The purpose of this script is to automate the process of updating hMailServer's certificate and port bindings.
	
.DESCRIPTION
	ONCE INITIAL INTERACTIVE SETUP HAS BEEN COMPLETED, this script will:
		1. Obtains the specified or latest SSL / TLS certificate installed in the local computer account's personal store.
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
	Author:								Ben Hooper at Astrix
	Tested on:							Certify the Web v4.0.8 to v4.1.6 (latest), OpenSSL v1.1.0h to v1.1.1c (latest), and hMailServer v5.6.7 (latest) on Windows Server 2016 and Windows Server 2019 v1809
	Version:							1.11
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
			
			Write-Host "`t(1/4) hMailServer can only be modified using the administrator password. Please enter this in the popup window. This will be encrypted.";
			
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
			
			Write-Host "`t(2/4) A folder is required to store hMailServer's SSL / TLS certificates. Please enter the path below:";
			
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
					Write-Host -ForegroundColor Red "`t`t[ERROR]: Folder path is invalid. Please ensure that the path is valid and that this script has access to the folder.";
				}
				
				Write-Host "";
			}
			
			Write-Host "`t(3/4) hMailServer must be restarted for certificate and port changes to take effect. Would you like this to be done automatically? (y/n)";
			$Proceed_hMailServer_Restart = Read-Host "`t`t[Input]";
	
			If (($Proceed_hMailServer_Restart -Like "y") -Or ($Proceed_hMailServer_Restart -Like "yes")){
				Write-Host "`t`t'Yes' selected.";
				
				$hMailServer_Restart = $True;
			} Else {
				Write-Host "`t`t'No' selected.";
				
				$hMailServer_Restart = $False;
			}
			
			Write-Host "";
			
			Write-Host "`t(4/4) OpenSSL's EXE file is required to create certain certificate files. Please enter the path below:";
			
			$OpenSSL_FullPath_Validity = $False;
			While ($OpenSSL_FullPath_Validity -Eq $False){
				$OpenSSL_FullPath = Read-Host "`t`t[Input]";
				
				# Remove quotation marks, if any
				$OpenSSL_FullPath = $OpenSSL_FullPath -Replace '"','';
				$OpenSSL_FullPath = $OpenSSL_FullPath -Replace "'","";
				
				$OpenSSL_Extension = [IO.Path]::GetExtension($OpenSSL_FullPath);
				
				If (($OpenSSL_FullPath) -And (Test-Path -Path $OpenSSL_FullPath -PathType Leaf) -And ($OpenSSL_Extension -Like ".exe")) {
					Write-Host -ForegroundColor Green "`t`t[Success]: EXE file path validated.";
					
					$OpenSSL_FullPath_Validity = $True;
				} Else {
					Write-Host -ForegroundColor Red "`t`t[ERROR]: EXE file path is invalid. Please ensure that the path is valid and that this script has access to the folder.";
					
				}
				
				Write-Host "";
			}
			
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
				$Windows_SSLCert_File_PathAndName = "$hMailServer_SSLCert_Path\$Windows_SSLCert_Name";
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
# MIIe7AYJKoZIhvcNAQcCoIIe3TCCHtkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUs4DnJM5h6LWfBTRLI54wMTFT
# hyagghn2MIIEhDCCA2ygAwIBAgIQQhrylAmEGR9SCkvGJCanSzANBgkqhkiG9w0B
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
# KoZIhvcNAQkEMRYEFAolJL/28v01LYnxvVkuBH5MJqftMA0GCSqGSIb3DQEBAQUA
# BIIBAC+9HfX4RTRk/zYkP+bxmi1ua/0Z0deXhf2baPEp+Ug3VOGwAoVdNSK86Cz2
# +j6pu0f6mR7Lis/sXayVTZhHooeFkWRH3Eups+HcwLweviWZ7/Bhyy/nlwQI7KbA
# 17zNPVLJ8OQeAYxpgdV/tr70JtXF06n8MGVvWPjTPy4KatgSywVPuGhTZJwKiPbq
# ISRl1kXwHq6VJaLD9nMxEVLPp90N/WRXoijDvkA6tTSIqk/rTmltAJsrEEXxdIDm
# 3BrUtQeEv/ktpJzB9WGnmJQx4L4ob4ZE19XivXsFsTegturoRi6m9Dn4FopNPFZN
# +f0Cwut+8aErx4glNfqDy6HRw3ChggIoMIICJAYJKoZIhvcNAQkGMYICFTCCAhEC
# AQEwgY4wejELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3Rl
# cjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQx
# IDAeBgNVBAMTF0NPTU9ETyBUaW1lIFN0YW1waW5nIENBAhArc9t0YxFMWlsySvIw
# V3JJMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqG
# SIb3DQEJBTEPFw0xOTA4MjcwNzM2MzBaMCMGCSqGSIb3DQEJBDEWBBTnXQj8z0US
# PD6BJswK2h9er74nXjANBgkqhkiG9w0BAQEFAASCAQCLF2HS2lbgsPTjvUnWqOjH
# vwO0AJQYXdjlZUvcokiK4TYAKyY7BLOdqPeItjy55JYCijqVDLGTv7Y3sk3+4e6P
# PtLGcvuUYqVmb2/XgLBfa5lqo162i45XG47R2f889lJtULsJnfQMvgYCA8m8AGQY
# 5tL66+q1QpvDVJ6eXV+1XiBbaTXIqZXivAqwoUIkUmvu8sFdIHepmFTrDDJ3ujAn
# A3pG7Sdv3w9C8mTmXij2Yxgqj7q2cubOpWWWQGKCNJFwa5ZkOklopnW6aoFwWz6Z
# TfMDNlgc6iXcoDnzJF3HINUqQHpKCj9ZSEW5mfLP85xh/3Ju3pw9jUkQe93vYLNS
# SIG # End signature block
