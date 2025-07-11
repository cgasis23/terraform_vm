# Variables
variable "instance_type" {
  default = "t2.micro" # Free Tier eligible
}

variable "env_prefix" {
  default = "win_srv_2022"
}

# VPC Configuration
resource "aws_vpc" "win_srv_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.env_prefix}_vpc"
  }
}

# Subnet
resource "aws_subnet" "win_srv_public_subnet" {
  vpc_id                  = aws_vpc.win_srv_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.env_prefix}_subnet"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "win_srv_igw" {
  vpc_id = aws_vpc.win_srv_vpc.id
  tags = {
    Name = "${var.env_prefix}_igw"
  }
}

# Route Table
resource "aws_route_table" "win_srv_route_table" {
  vpc_id = aws_vpc.win_srv_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.win_srv_igw.id
  }
  tags = {
    Name = "${var.env_prefix}_route_table"
  }
}

# IAM Role for S3 Access
resource "aws_iam_role" "ec2_s3_role" {
  name = "ec2-s3-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ec2_s3_policy" {
  name   = "ec2-s3-policy"
  role   = aws_iam_role.ec2_s3_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:GetObject"]
        Effect   = "Allow"
        Resource = "arn:aws:s3:::my-dsc-bucket-123/ConfigureIIS.zip"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ec2_full_access_policy" {
  name   = "ec2-full-access-policy"
  role   = aws_iam_role.ec2_s3_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:*"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_s3_profile" {
  name = "ec2-s3-profile"
  role = aws_iam_role.ec2_s3_role.name
}

resource "aws_route_table_association" "win_srv_route_assoc" {
  subnet_id      = aws_subnet.win_srv_public_subnet.id
  route_table_id = aws_route_table.win_srv_route_table.id
}

# Security Group for RDP Access
resource "aws_security_group" "win_srv_sg" {
  vpc_id = aws_vpc.win_srv_vpc.id
  name   = "${var.env_prefix}_sg"

  ingress {
    description = "RDP from my IP"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["73.134.168.28/32"] # Replace with your IP for better security (e.g., "YOUR_IP/32")
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.env_prefix}_sg"
  }
}

# EC2 Instance
# IIS And asp.net are installed by default on Windows Server 2022 AMI
resource "aws_instance" "win_srv_instance" {
  ami           = "ami-0345f44fe05216fc4" # Replace with the correct Windows Server 2022 AMI ID
  instance_type = var.instance_type
  subnet_id     = aws_subnet.win_srv_public_subnet.id
  vpc_security_group_ids = [aws_security_group.win_srv_sg.id]
  get_password_data = true # Enables password retrieval for RDP
  key_name = "aws-ec2" # Ensure you have created this key pair in AWS
  iam_instance_profile = aws_iam_instance_profile.ec2_s3_profile.name
  user_data = <<EOF
  <powershell>
    # Set up logging
    $LogFile = "C:\SetupLog.txt"
    $ErrorActionPreference = "Stop"
    
    function Write-Log {
        param($Message)
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
    }
    
    try {
        Write-Log "Starting setup script"
        
        # Create the C:\DSC 
        New-Item -ItemType Directory -Path "C:\DSC" -Force
        
        # Install AWS CLI
        Write-Log "Installing AWS CLI..."
        Invoke-WebRequest -Uri "https://awscli.amazonaws.com/AWSCLIV2.msi" -OutFile "C:\DSC\AWSCLIV2.msi"
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i C:\DSC\AWSCLIV2.msi /quiet" -Wait
        Remove-Item "C:\DSC\AWSCLIV2.msi" -Force
        
        # Add AWS CLI to PATH
        $env:Path += ";C:\Program Files\Amazon\AWSCLIV2"
        [Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)
        
        # Download ConfigureIIS.zip from S3
        Write-Log "Downloading ConfigureIIS.zip from S3..."
        aws s3 cp s3://my-dsc-bucket-123/ConfigureIIS.zip C:\DSC\ConfigureIIS.zip --region us-east-1
  
        # Verify file download
        if (Test-Path "C:\DSC\ConfigureIIS.zip") {
            Write-Log "ConfigureIIS.zip downloaded successfully."
        } else {
            Write-Log "Failed to download ConfigureIIS.zip."
            Stop-Transcript
            exit 1
        }
    
        # Unzip the package
        Write-Log "Unzipping ConfigureIIS.zip..."
        Expand-Archive -Path "C:\DSC\ConfigureIIS.zip" -DestinationPath "C:\DSC" -Force
  
        # Add AWS CLI to PATH
        $env:Path += ";C:\Program Files\Amazon\AWSCLIV2"
        [Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine) 
    
        # Speed up downloads by disabling progress bar
        $ProgressPreference = 'SilentlyContinue'
    
        # Install PowerShell 7.4
        Write-Log "Downloading PowerShell 7.4 installer"
        $PwshUrl = "https://github.com/PowerShell/PowerShell/releases/download/v7.4.0/PowerShell-7.4.0-win-x64.msi"
        $PwshOutFile = "$env:TEMP\PowerShell-7.4.0-win-x64.msi"
        Invoke-WebRequest -Uri $PwshUrl -OutFile $PwshOutFile
        Write-Log "PowerShell 7.4 download completed"
    
        Write-Log "Installing PowerShell 7.4"
        Start-Process msiexec.exe -Wait -ArgumentList "/I $PwshOutFile /quiet /norestart"
        Write-Log "PowerShell 7.4 installation completed"
    
        # Clean up PowerShell installer
        Remove-Item $PwshOutFile
        Write-Log "Removed PowerShell installer"
    
        # Install winget dependencies and winget
        Write-Log "Installing winget dependencies and winget"
    
        # Download and install Microsoft.VCLibs
        Write-Log "Downloading Microsoft.VCLibs"
        $VCLibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
        $VCLibsOutFile = "$env:TEMP\Microsoft.VCLibs.appx"
        Invoke-WebRequest -Uri $VCLibsUrl -OutFile $VCLibsOutFile
        Write-Log "Microsoft.VCLibs download completed"
    
        Write-Log "Installing Microsoft.VCLibs"
        Add-AppxPackage -Path $VCLibsOutFile
        Write-Log "Microsoft.VCLibs installation completed"
    
        # Download and install Microsoft.UI.Xaml
        Write-Log "Downloading Microsoft.UI.Xaml"
        $UIXamlUrl = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx"
        $UIXamlOutFile = "$env:TEMP\Microsoft.UI.Xaml.appx"
        Invoke-WebRequest -Uri $UIXamlUrl -OutFile $UIXamlOutFile
        Write-Log "Microsoft.UI.Xaml download completed"
    
        Write-Log "Installing Microsoft.UI.Xaml"
        Add-AppxPackage -Path $UIXamlOutFile
        Write-Log "Microsoft.UI.Xaml installation completed"
    
        # Download and install winget (Microsoft.DesktopAppInstaller)
        Write-Log "Downloading winget (Microsoft.DesktopAppInstaller)"
        $WingetVersion = "v1.8.1911"
        $WingetLicenseFile = "76fba573f02545629706ab99170237bc_License1.xml"
        $WingetUrl = "https://github.com/microsoft/winget-cli/releases/download/$WingetVersion/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
        $WingetLicenseUrl = "https://github.com/microsoft/winget-cli/releases/download/$WingetVersion/$WingetLicenseFile"
        $WingetOutFile = "$env:TEMP\Microsoft.DesktopAppInstaller.msixbundle"
        $WingetLicenseOutFile = "$env:TEMP\license.xml"
        Invoke-WebRequest -Uri $WingetUrl -OutFile $WingetOutFile
        Invoke-WebRequest -Uri $WingetLicenseUrl -OutFile $WingetLicenseOutFile
        Write-Log "winget download completed"
    
        Write-Log "Installing winget"
        Add-AppxProvisionedPackage -Online -PackagePath $WingetOutFile -LicensePath $WingetLicenseOutFile
        Write-Log "winget installation completed"
    
        # Clean up winget installation files
        Remove-Item $VCLibsOutFile, $UIXamlOutFile, $WingetOutFile, $WingetLicenseOutFile
        Write-Log "Removed winget installation files"
    
        # Update PATH to include winget
        Write-Log "Updating PATH to include winget"
        $WingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" | Select-Object -Last 1 -ExpandProperty Path
        if ($WingetPath) {
            $env:PATH = "$env:PATH;$WingetPath"
            [Environment]::SetEnvironmentVariable("Path", "$env:PATH;$WingetPath", [EnvironmentVariableTarget]::Machine)
            Write-Log "Added winget path ($WingetPath) to system PATH"
        } else {
            Write-Log "Failed to locate winget path"
            throw "Winget path not found"
        }
    
        # Verify winget is functional (attempt with elevated context)
        Write-Log "Verifying winget installation"
        try {
            $WingetCommand = "winget --version"
            $WingetVersion = (Start-Process powershell -ArgumentList "-Command $WingetCommand" -Wait -NoNewWindow -PassThru).ExitCode
            if ($WingetVersion -eq 0) {
                Write-Log "winget is functional, version retrieved successfully"
                Write-Log "Updating winget source"
                Start-Process powershell -ArgumentList "-Command 'winget source update'" -Wait -NoNewWindow
                Write-Log "winget source update completed"
            } else {
                Write-Log "winget verification returned exit code $WingetVersion"
                Write-Log "Note: Manual verification via RDP may be required due to access restrictions during user data execution"
            }
        } catch {
            Write-Log "winget verification failed: $_"
            Write-Log "Note: Manual verification via RDP may be required due to access restrictions during user data execution"
        }
    
        # Extract DSC v3
        Write-Log "Extracting DSC v3"
        $DscOutFile = "C:\DSC\Modules\DSC-3.1.0-x86_64-pc-windows-msvc.zip"
        $DscExtractPath = "$env:ProgramFiles\DSC"
        Expand-Archive -Path $DscOutFile -DestinationPath $DscExtractPath -Force
        Write-Log "DSC v3 extraction completed"
     
        # Clean up DSC zip file
        Remove-Item $DscOutFile
        Write-Log "Removed DSC zip file"
     
        # Add DSC to PATH
        Write-Log "Adding DSC to PATH"
        $env:PATH = "$env:PATH;$DscExtractPath"
        [Environment]::SetEnvironmentVariable("Path", "$env:PATH;$DscExtractPath", [EnvironmentVariableTarget]::Machine)
        Write-Log "Added DSC path to system PATH"
     
        # Define a simple DSC v3 configuration in JSON
        $DscConfig = @{
            resources = @(
                @{
                    type = "Microsoft.Windows/WindowsPowerShell"
                    name = "PowerShellCheck"
                    properties = @{
                        moduleName = "PowerShell"
                        version = "7.4.0"
                        ensure = "Present"
                    }
                },
                @{
                    type = "Microsoft.Windows/WindowsPowerShell"
                    name = "WingetCheck"
                    properties = @{
                        moduleName = "Microsoft.DesktopAppInstaller"
                        version = "1.8.1911"
                        ensure = "Present"
                    }
                }
            )
        } | ConvertTo-Json -Depth 3
   
        $DscConfigFile = "$env:TEMP\config.json"
        $DscConfig | Out-File -FilePath $DscConfigFile
        Write-Log "DSC configuration file created"
   
        # Apply DSC configuration
        Write-Log "Applying DSC configuration"
        & "$DscExtractPath\dsc.exe" config set --config $DscConfigFile
        Write-Log "DSC configuration applied" 
  
        Write-Log "Setup script completed successfully"
    } catch {
        Write-Log "Error occurred: $_"
        throw
    }
    </powershell>>
  EOF
  tags = {
    Name = "${var.env_prefix}_instance"
  }
}

# Output RDP Connection Info
output "rdp_connection_info" {
  value = <<EOT
RDP Connection Details:
-----------------------
Full Address: ${aws_instance.win_srv_instance.public_ip}
Username: Administrator
Password: Run `aws ec2 get-password-data --instance-id ${aws_instance.win_srv_instance.id} --priv-launch-key ~/.ssh/aws-ec2.pem` to decrypt the password
Instructions:
1. Use an RDP client (e.g., Microsoft Remote Desktop) to connect to the public IP.
2. Log in with the Administrator username and decrypted password.
EOT
}