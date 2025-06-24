# ConfigureIIS.ps1
Configuration ConfigureIIS {
    param (
        [string]$NodeName = 'localhost'
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xWebAdministration

    Node $NodeName {
        WindowsFeature IIS {
            Ensure = 'Present'
            Name   = 'Web-Server'
        }

        WindowsFeature NetFramework35 {
            Ensure    = 'Present'
            Name      = 'NET-Framework-Features'
            DependsOn = '[WindowsFeature]IIS'
        }

        WindowsFeature AspNet35 {
            Ensure    = 'Present'
            Name      = 'Web-Asp-Net'
            DependsOn = '[WindowsFeature]NetFramework35'
        }

        WindowsFeature AspNet45 {
            Ensure    = 'Present'
            Name      = 'Web-Asp-Net45'
            DependsOn = '[WindowsFeature]IIS'
        }

        WindowsFeature NetFramework45 {
            Ensure    = 'Present'
            Name      = 'NET-Framework-45-Core'
            DependsOn = '[WindowsFeature]IIS'
        }

        WindowsFeature WebManagementTools {
            Ensure    = 'Present'
            Name      = 'Web-Mgmt-Tools'
            DependsOn = '[WindowsFeature]IIS'
        }

        WindowsFeature WebManagementService {
            Ensure    = 'Present'
            Name      = 'Web-Mgmt-Service'
            DependsOn = '[WindowsFeature]IIS'
        }

        Service IISService {
            Name       = 'W3SVC'
            StartupType = 'Automatic'
            State      = 'Running'
            DependsOn  = '[WindowsFeature]IIS'
        }

        Service WMSVC {
            Name       = 'WMSVC'
            StartupType = 'Automatic'
            State      = 'Running'
            DependsOn  = '[WindowsFeature]WebManagementService'
        }

        xWebsite DefaultSite {
            Ensure          = 'Present'
            Name            = 'Default Web Site'
            PhysicalPath    = 'C:\inetpub\wwwroot'
            State           = 'Started'
            BindingInfo     = @(
                MSFT_xWebBindingInformation {
                    Protocol = 'HTTP'
                    Port     = 80
                }
            )
            DependsOn       = '[WindowsFeature]IIS'
        }

        xWebAppPool DefaultAppPool {
            Ensure                = 'Present'
            Name                  = 'DefaultAppPool'
            Enable32BitAppOnWin64 = $true
            ManagedRuntimeVersion = 'v4.0'
            DependsOn             = '[WindowsFeature]IIS'
        }

        xWebAppPool AppPoolV2 {
            Ensure                = 'Present'
            Name                  = 'DefaultAppPoolV2'
            Enable32BitAppOnWin64 = $true
            ManagedRuntimeVersion = 'v2.0'
            DependsOn             = '[WindowsFeature]IIS'
        }

        xWebAppPool AppPoolV4 {
            Ensure                = 'Present'
            Name                  = 'DefaultAppPoolV4'
            Enable32BitAppOnWin64 = $true
            ManagedRuntimeVersion = 'v4.0'
            DependsOn             = '[WindowsFeature]IIS'
        }

        Script EnableWinRM {
            SetScript = {
                # Ensure WinRM is enabled and configured
                $winrmService = Get-Service -Name WinRM
                if ($winrmService.Status -ne 'Running') {
                    Enable-PSRemoting -Force
                    Set-Service -Name WinRM -StartupType Automatic
                    Start-Service -Name WinRM
                }
            }
            TestScript = {
                $winrmService = Get-Service -Name WinRM
                return ($winrmService.Status -eq 'Running')
            }
            GetScript = {
                $winrmService = Get-Service -Name WinRM
                return @{ Result = $winrmService.Status }
            }
            DependsOn = '[WindowsFeature]IIS'
        }

        Script EnableIISRemoteManagement {
            SetScript = {
                # Enable remote management in IIS
                Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/managementDelegation' -Name 'allowRemoteConnections' -Value $true

                # Configure firewall rule for WMSVC (port 8172)
                $ruleName = 'IIS Remote Management'
                $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                if (-not $rule) {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort 8172 -Action Allow
                }
            }
            TestScript = {
                $allowRemote = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/managementDelegation' -Name 'allowRemoteConnections' -ErrorAction SilentlyContinue
                $rule = Get-NetFirewallRule -DisplayName 'IIS Remote Management' -ErrorAction SilentlyContinue
                return ($allowRemote.Value -eq $true -and $rule -ne $null)
            }
            GetScript = {
                $allowRemote = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/managementDelegation' -Name 'allowRemoteConnections' -ErrorAction SilentlyContinue
                $rule = Get-NetFirewallRule -DisplayName 'IIS Remote Management' -ErrorAction SilentlyContinue
                return @{ Result = "RemoteConnections: $($allowRemote.Value); FirewallRuleExists: $($rule -ne $null)" }
            }
            DependsOn = '[Service]WMSVC'
        }
    }
}

ConfigureIIS -OutputPath 'C:\DSC\ConfigureIIS'