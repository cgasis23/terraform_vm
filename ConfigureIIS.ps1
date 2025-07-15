# ConfigureIIS.ps1
Configuration ConfigureIIS {
    param (
        [string]$NodeName = 'localhost',
		[string]$SourceScriptPath = 'C:\DSC\Scripts\Log.js',
		[string]$LogDir = 'C:\logs'
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xWebAdministration

    function Write-DSCLog {
        param([string]$Message)
        $logFile = 'C:\logs\ConfigureIIS.log'
        "[$(Get-Date -Format o)] $Message" | Out-File -FilePath $logFile -Append
    }

    Node $NodeName {
#        WindowsFeature IIS {
#            Ensure = 'Present'
#            Name   = 'Web-Server'
#        }
# 
#         WindowsFeature NetFramework35 {
#             Ensure    = 'Present'
#             Name      = 'NET-Framework-Features'
#             DependsOn = '[WindowsFeature]IIS'
#         }
# 
#         WindowsFeature AspNet35 {
#             Ensure    = 'Present'
#             Name      = 'Web-Asp-Net'
#             DependsOn = '[WindowsFeature]NetFramework35'
#         }
# 
#         WindowsFeature AspNet45 {
#             Ensure    = 'Present'
#             Name      = 'Web-Asp-Net45'
#             DependsOn = '[WindowsFeature]IIS'
#         }
# 
#         WindowsFeature NetFramework45 {
#             Ensure    = 'Present'
#             Name      = 'NET-Framework-45-Core'
#             DependsOn = '[WindowsFeature]IIS'
#         }
# 
#         WindowsFeature WebManagementTools {
#             Ensure    = 'Present'
#             Name      = 'Web-Mgmt-Tools'
#             DependsOn = '[WindowsFeature]IIS'
#         }
# 
#         WindowsFeature WebManagementService {
#             Ensure    = 'Present'
#             Name      = 'Web-Mgmt-Service'
#             DependsOn = '[WindowsFeature]IIS'
#         }
# 
#         Service IISService {
#             Name       = 'W3SVC'
#             StartupType = 'Automatic'
#             State      = 'Running'
#             DependsOn  = '[WindowsFeature]IIS'
#         }
# 
#         Service WMSVC {
#             Name       = 'WMSVC'
#             StartupType = 'Automatic'
#             State      = 'Running'
#             DependsOn  = '[WindowsFeature]WebManagementService'
#         }
# 
#         xWebsite DefaultSite {
#             Ensure          = 'Present'
#             Name            = 'Default Web Site'
#             PhysicalPath    = 'C:\inetpub\wwwroot'
#             State           = 'Started'
#             BindingInfo     = @(
#                 MSFT_xWebBindingInformation {
#                     Protocol = 'HTTP'
#                     Port     = 80
#                 }
#             )
#             DependsOn       = '[WindowsFeature]IIS'
#         }
# 
#         xWebAppPool DefaultAppPool {
#             Ensure                = 'Present'
#             Name                  = 'DefaultAppPool'
#             Enable32BitAppOnWin64 = $true
#             ManagedRuntimeVersion = 'v4.0'
#             DependsOn             = '[WindowsFeature]IIS'
#         }
# 
#         xWebAppPool AppPoolV2 {
#             Ensure                = 'Present'
#             Name                  = 'DefaultAppPoolV2'
#             Enable32BitAppOnWin64 = $true
#             ManagedRuntimeVersion = 'v2.0'
#             DependsOn             = '[WindowsFeature]IIS'
#         }
# 
#         xWebAppPool AppPoolV4 {
#             Ensure                = 'Present'
#             Name                  = 'DefaultAppPoolV4'
#             Enable32BitAppOnWin64 = $true
#             ManagedRuntimeVersion = 'v4.0'
#             DependsOn             = '[WindowsFeature]IIS'
#         }

#         Script EnableWinRM {
#             SetScript = {
#                 $winrmService = Get-Service -Name WinRM
#                 if ($winrmService.Status -ne 'Running') {
#                     Enable-PSRemoting -Force
#                     Set-Service -Name WinRM -StartupType Automatic
#                     Start-Service -Name WinRM
#                 }
#             }
#             TestScript = {
#                 $winrmService = Get-Service -Name WinRM
#                 return ($winrmService.Status -eq 'Running')
#             }
#             GetScript = {
#                 $winrmService = Get-Service -Name WinRM
#                 return @{ Result = $winrmService.Status }
#             }
#             DependsOn = '[WindowsFeature]IIS'
#         }

#         Script EnableIISRemoteManagement {
#             SetScript = {
#                 Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/managementDelegation' -Name 'allowRemoteConnections' -Value $true
#                 $ruleName = 'IIS Remote Management'
#                 $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
#                 if (-not $rule) {
#                     New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort 8172 -Action Allow
#                 }
#             }
#             TestScript = {
#                 $allowRemote = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/managementDelegation' -Name 'allowRemoteConnections' -ErrorAction SilentlyContinue
#                 $rule = Get-NetFirewallRule -DisplayName 'IIS Remote Management' -ErrorAction SilentlyContinue
#                 return ($allowRemote.Value -eq $true -and $rule -ne $null)
#             }
#             GetScript = {
#                 $allowRemote = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/managementDelegation' -Name 'allowRemoteConnections' -ErrorAction SilentlyContinue
#                 $rule = Get-NetFirewallRule -DisplayName 'IIS Remote Management' -ErrorAction SilentlyContinue
#                 return @{ Result = "RemoteConnections: $($allowRemote.Value); FirewallRuleExists: $($rule -ne $null)" }
#             }
#             DependsOn = '[Service]WMSVC'
#         }

        # Ensure the log directory exists
		File LogDirectory {
			Ensure          = 'Present'
			Type            = 'Directory'
			DestinationPath = $LogDir
# 			DependsOn       = '[WindowsFeature]IIS'
		}

        # Ensure LogHelloWorld.js is present in C:\DSC
#         File LogHelloWorldScript {
#             Ensure          = 'Present'
#             Type            = 'File'
#             SourcePath      = 'C:\DSC\LogHelloWorld.js'
#             DestinationPath = 'C:\DSC\LogHelloWorld.js'
#             DependsOn       = '[File]LogDirectory'
#             Checksum        = 'SHA-256'
#             Force           = $true
#             MatchSource     = $true
#         }

        # Ensure getCredentials.js is present in C:\DSC
#         File GetCredentialsScript {
#             Ensure          = 'Present'
#             Type            = 'File'
#             SourcePath      = 'C:\DSC\getCredentials.js'
#             DestinationPath = 'C:\DSC\getCredentials.js'
#             DependsOn       = '[File]LogDirectory'
#             Checksum        = 'SHA-256'
#             Force           = $true
#             MatchSource     = $true
#         }

		# Ensure the scripts directory exists
		# File ScriptsDirectory {
		#	Ensure          = 'Present'
		#	Type            = 'Directory'
		#	DestinationPath = 'C:\Scripts'
		#	DependsOn       = '[File]LogDirectory'
		# }

		# Script to check if the source file exists before proceeding
		# Script CheckSourceFile {
		#	SetScript = {
		#	if (-not (Test-Path -Path $using:SourceScriptPath)) {
		#		throw "Source file $using:SourceScriptPath does not exist. Please ensure the file is available before applying the configuration."
		#	}
		#	}
		#	TestScript = {
		#		return (Test-Path -Path $using:SourceScriptPath)
		#	}
		#	GetScript = {
		#		return @{ Result = (Test-Path -Path $using:SourceScriptPath) }
		#	}
		#	DependsOn = '[File]LogDirectory'
		#}

		# Ensure the JavaScript file is copied with checksum verification and force overwrite
		# File LogScript {
		#	Ensure          = 'Present'
		#	Type            = 'File'
		#	SourcePath      = $SourceScriptPath
		#	DestinationPath = $ScriptPath
		#	DependsOn       = '[Script]CheckSourceFile'
		#	Checksum        = 'SHA-256'  # Verify file integrity
		#	Force           = $true      # Overwrite if the file exists
		#	MatchSource     = $true      # Ensure destination matches source attributes
		# }
		
		# Create a scheduled task to run the script
        Script ScheduledTask
        {
            SetScript = {
                $taskName = 'LogHelloWorldTask'
                $taskPath = '\CustomTasks\'
                $scriptPath = $using:SourceScriptPath
                $nodePath = 'C:\Program Files\nodejs\node.exe'
                $action = New-ScheduledTaskAction -Execute $nodePath -Argument "$SourceScriptPath"
                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
                $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Hours 1)

                # Create task folder using COM object
                $scheduler = New-Object -ComObject Schedule.Service
                $scheduler.Connect()
                $root = $scheduler.GetFolder('\')
                try {
                    $root.GetFolder('CustomTasks') | Out-Null
                }
                catch {
                    $root.CreateFolder('CustomTasks') | Out-Null
                }

                # Unregister existing task
                if (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
                    Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false
                }

                # Register the task
                Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Runs LogHelloWorld.js every 1 minute' -ErrorAction Stop
            }
            TestScript = {
                $taskName = 'LogHelloWorldTask'
                $taskPath = '\CustomTasks\'
                $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
                return $null -ne $task
            }
            GetScript = {
                return @{ Result = 'Scheduled task status' }
            }
            DependsOn = '[File]LogDirectory'
        }

        Script ScheduledTaskVBS
        {
            SetScript = {
                $taskName = 'LogHelloWorldVBSTask'
                $taskPath = '\CustomTasks\'
                $vbsPath = 'C:\DSC\Scripts\Log.vbs'
                $cscriptPath = "$env:SystemRoot\System32\cscript.exe"
                $secretName = "win_srv_2022-user-credentials-test"
                $secret = Get-SECSecretValue -SecretId $secretName
                $secretObj = $secret.SecretString | ConvertFrom-Json
                # $awsUsername = $secretObj.username
                # $awsPassword = $secretObj.password

                $action = New-ScheduledTaskAction -Execute $cscriptPath -Argument "//B `"$vbsPath`""
                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
                $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Hours 1)

                # Create task folder using COM object
                $scheduler = New-Object -ComObject Schedule.Service
                $scheduler.Connect()
                $root = $scheduler.GetFolder('\')
                try {
                    $root.GetFolder('CustomTasks') | Out-Null
                }
                catch {
                    $root.CreateFolder('CustomTasks') | Out-Null
                }

                # Unregister existing task
                if (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
                    Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false
                }

                # Register the task
                Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Runs LogHelloWorld.vbs every 1 minute' -ErrorAction Stop
            }
            TestScript = {
                $taskName = 'LogHelloWorldVBSTask'
                $taskPath = '\CustomTasks\'
                $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
                return $null -ne $task
            }
            GetScript = {
                return @{ Result = 'Scheduled task status for VBS' }
            }
            DependsOn = '[File]LogDirectory'
        }
    }
}

ConfigureIIS -OutputPath 'C:\DSC\ConfigureIIS'