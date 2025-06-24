Configuration DEVWEB {
    Import-Module WebAdministration

    Import-DscResource -ModuleName xTimeZone
    Import-DscResource -ModuleName xWebAdministration
    Import-DscResource -ModuleName PowerShellAccessControl

    Node $AllNodes.NodeName {
            xTimeZone TimeZoneExample
            {
                TimeZone = 'UTC'
                IsSingleInstance = "Yes" 
            }
        
            WindowsFeature IIS 
            {
                Ensure = "Present"
                Name = "Web-Server"
            }
        
            WindowsFeature IISManagement
            {
                Ensure = "Present"
                Name = "Web-Mgmt-Console"
                DependsOn = "[WindowsFeature]IIS"
            }
        
            WindowsFeature IISManagementService 
            {
                Ensure = "Present"
                Name = "Web-Mgmt-Service"
                DependsOn = "[WindowsFeature]IIS"
            }
        
            WindowsFeature AspNet35
            {
                Ensure = "Present"
                Name = "Web-Asp-Net"
                DependsOn = "[WindowsFeature]IIS"
            }
        
            WindowsFeature SmtpServer 
            {
                Ensure = "Present"
                Name = "SMTP-Server"
                DependsOn = "[WindowsFeature]IIS"
            }
        
            Script IISRemoteManagement 
            {
                SetScript = {
                    Set-ItemProperty -Path
                    "HKLM:\SOFTWARE\Microsoft\WebManagement\Server" -Name
                    EnableRemoteManagement -Value 1
                    Restart-Service wmsvc
                }
                TestScript = {
                    $enabled = (Get-ItemProperty -Path
                    "HKLM:\SOFTWARE\Microsoft\WebManagement\Server") .
                    EnableRemoteManagement
                    $result = $enabled -eq 1
                    return $result 
                }
                GetScript = {
                    $enabled = (Get-ItemProperty -Path
                    "HKLM:\SOFTWARE\Microsoft\WebManagement\Server") .
                    EnableRemoteManagement
                    $result = $enabled -eq 1
                    
                    return @{
                        GetScript = $GetScript
                        SetScript = $SetScript
                        TestScript = $TestScript
                        Result = $result
                    }
                }
                DependsOn = "[WindowsFeature]IISManagementService"
            }
        
            Service WebMgmtService 
            {
                Name = "wmsvc"
                StartupType = "Automatic"
                State = "Running"
                DependsOn = "[WindowsFeature]IISManagementService","[Script]IISRemoteManagement"
            }
        
            Service AspNetStateService
            {
                Name = "aspnet_state"
                StartupType = "Automatic"
                State = "Running"
                DependsOn = "[WindowsFeature]AspNet35"
            }
        
            xWebsite DefaultSite
            {
                Ensure = "Absent"
                Name = "Default Web Site"
                PhysicalPath = "C:\inetpub\wwwroot"
                DependsOn = "[WindowsFeature]IIS"
            }
        
            Script WebSiteLogFields 
            {
                SetScript = {
                    $desiredLogFileFields = @(
                        "date", "time", "c-ip", "cs-method", "cs-uri-stem",
                        "cs-uri-query", "s-port", "cs-username", "c-user-agent",
                        "cs-version", "sc-status", "sc-substatus", "sc-win32-status",
                        "time-taken"
                    )
                }
                TestScript = {
                    $desiredLogFileFields = @(
                        "date", "time", "c-ip", "cs-method", "cs-uri-stem",
                        "cs-uri-query", "s-port", "cs-username", "c-user-agent",
                        "cs-version", "sc-status", "sc-substatus", "sc-win32-status",
                        "time-taken"
                    )
                }
                GetScript = {
                    return @{
                        GetScript = $GetScript
                        SetScript = $SetScript
                        TestScript = $TestScript
                        Result = Get-WebConfiguration -Filter System.
                        ApplicationHost/Sites/SiteDefaults/logfile | Select  -
                        ExpandProperty logExtFileFlags
                    }
                    DependsOn = "[WindowsFeature]IIS"
                }
            }
    }
}

$ConfigData = @{
    AllNodes = @{
        @{
            NodeName = "test.aws"
        }
    }
}

DEVWEB -ConfigurationData $ConfigData -Output "DEVWEB"
