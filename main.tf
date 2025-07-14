# Variables
variable "instance_type" {
  default = "t2.micro" # Free Tier eligible
}

variable "env_prefix" {
  default = "win_srv_2022"
}

variable "AdminPassword" {
    default = "1" # Default Administrator password, will be relaxed to allow simple passwords
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

resource "aws_iam_role_policy" "ec2_secretsmanager_policy" {
  name = "ec2-secretsmanager-policy"
  role = aws_iam_role.ec2_s3_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "secretsmanager:GetSecretValue"
        ],
        Resource = "arn:aws:secretsmanager:us-east-1:*:secret:win_srv_2022-user-credentials-test*"
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
        Write-Log "==== Starting Windows Server 2022 setup via Terraform ===="
        
        # Relax password policy to allow simple password
        Write-Log "Configuring password policy: allowing simple passwords (min length 1, complexity disabled)..."
        net accounts /minpwlen:1
        secedit /export /cfg C:\secpol.cfg
        (Get-Content C:\secpol.cfg) -replace "PasswordComplexity = 1", "PasswordComplexity = 0" | Set-Content C:\secpol.cfg
        secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY
        Remove-Item C:\secpol.cfg
        Write-Log "Password policy updated successfully."
        
        # Set Administrator password
        Write-Log "Setting Administrator password..."
        net user Administrator ${var.AdminPassword}
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Administrator password set successfully."
        } else {
            Write-Log "ERROR: Failed to set Administrator password. Please check password policy and try again."
            throw "Failed to set Administrator password"
        }
        
        # Create the C:\DSC 
        Write-Log "Creating C:\DSC directory for setup files..."
        New-Item -ItemType Directory -Path "C:\DSC" -Force
        Write-Log "C:\DSC directory created."

        # Install Node.js
        Write-Output "Installing Node.js..."
        $nodeUrl = "https://nodejs.org/dist/v20.17.0/node-v20.17.0-x64.msi" # Use the latest LTS version
        Invoke-WebRequest -Uri $nodeUrl -OutFile "C:\DSC\node-v20.17.0-x64.msi"
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i C:\DSC\node-v20.17.0-x64.msi /quiet /norestart" -Wait
        Remove-Item "C:\DSC\node-v20.17.0-x64.msi" -Force
        $env:Path += ";C:\Program Files\nodejs\"
        [Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)
        Write-Output "Node.js installation completed."
        
        # Install AWS CLI
        Write-Log "Installing AWS CLI..."
        Invoke-WebRequest -Uri "https://awscli.amazonaws.com/AWSCLIV2.msi" -OutFile "C:\DSC\AWSCLIV2.msi"
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i C:\DSC\AWSCLIV2.msi /quiet" -Wait
        Remove-Item "C:\DSC\AWSCLIV2.msi" -Force
        Write-Log "AWS CLI installed successfully."
        
        # Add AWS CLI to PATH
        Write-Log "Adding AWS CLI to system PATH..."
        $env:Path += ";C:\Program Files\Amazon\AWSCLIV2"
        [Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)
        Write-Log "AWS CLI path added to system PATH."
        
        # Download ConfigureIIS.zip from S3
        Write-Log "Downloading IIS configuration package (ConfigureIIS.zip) from S3..."
        aws s3 cp s3://my-dsc-bucket-123/ConfigureIIS.zip C:\DSC\ConfigureIIS.zip --region us-east-1
  
        # Verify file download
        if (Test-Path "C:\DSC\ConfigureIIS.zip") {
            Write-Log "ConfigureIIS.zip downloaded successfully."
        } else {
            Write-Log "ERROR: Failed to download ConfigureIIS.zip from S3. Please check S3 bucket and permissions."
            Stop-Transcript
            exit 1
        }
    
        # Unzip the package
        Write-Log "Extracting ConfigureIIS.zip to C:\DSC..."
        Expand-Archive -Path "C:\DSC\ConfigureIIS.zip" -DestinationPath "C:\DSC" -Force
        Write-Log "ConfigureIIS.zip extracted successfully."
  
        # Speed up downloads by disabling progress bar
        $ProgressPreference = 'SilentlyContinue'
    
        # Install npm packages for Node.js scripts
        Write-Log "Installing npm packages in C:\DSC\scripts..."
        if (Test-Path "C:\DSC\scripts\package.json") {
            Set-Location -Path "C:\DSC\scripts"
            npm install
            Write-Log "npm packages installed successfully."
        } else {
            Write-Log "package.json not found in C:\DSC\scripts. Skipping npm install."
        }
    
        # Install PowerShell 7.4
        Write-Log "Downloading PowerShell 7.4 installer..."
        $PwshUrl = "https://github.com/PowerShell/PowerShell/releases/download/v7.4.0/PowerShell-7.4.0-win-x64.msi"
        $PwshOutFile = "$env:TEMP\PowerShell-7.4.0-win-x64.msi"
        Invoke-WebRequest -Uri $PwshUrl -OutFile $PwshOutFile
        Write-Log "PowerShell 7.4 installer downloaded."
    
        Write-Log "Installing PowerShell 7.4..."
        Start-Process msiexec.exe -Wait -ArgumentList "/I $PwshOutFile /quiet /norestart"
        Write-Log "PowerShell 7.4 installed successfully."
    
        # Clean up PowerShell installer
        Write-Log "Cleaning up PowerShell installer..."
        Remove-Item $PwshOutFile
        Write-Log "PowerShell installer removed."
    
        # Install winget dependencies and winget
        Write-Log "Installing dependencies for winget (Microsoft.VCLibs, Microsoft.UI.Xaml)..."
    
        # Download and install Microsoft.VCLibs
        Write-Log "Downloading Microsoft.VCLibs..."
        $VCLibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
        $VCLibsOutFile = "$env:TEMP\Microsoft.VCLibs.appx"
        Invoke-WebRequest -Uri $VCLibsUrl -OutFile $VCLibsOutFile
        Write-Log "Microsoft.VCLibs downloaded."
    
        Write-Log "Installing Microsoft.VCLibs..."
        Add-AppxPackage -Path $VCLibsOutFile
        Write-Log "Microsoft.VCLibs installed."
    
        # Download and install Microsoft.UI.Xaml
        Write-Log "Downloading Microsoft.UI.Xaml..."
        $UIXamlUrl = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx"
        $UIXamlOutFile = "$env:TEMP\Microsoft.UI.Xaml.appx"
        Invoke-WebRequest -Uri $UIXamlUrl -OutFile $UIXamlOutFile
        Write-Log "Microsoft.UI.Xaml downloaded."
    
        Write-Log "Installing Microsoft.UI.Xaml..."
        Add-AppxPackage -Path $UIXamlOutFile
        Write-Log "Microsoft.UI.Xaml installed."
    
        # Download and install winget (Microsoft.DesktopAppInstaller)
        Write-Log "Downloading and installing winget (Windows Package Manager)..."
        $WingetVersion = "v1.8.1911"
        $WingetLicenseFile = "76fba573f02545629706ab99170237bc_License1.xml"
        $WingetUrl = "https://github.com/microsoft/winget-cli/releases/download/$WingetVersion/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
        $WingetLicenseUrl = "https://github.com/microsoft/winget-cli/releases/download/$WingetVersion/$WingetLicenseFile"
        $WingetOutFile = "$env:TEMP\Microsoft.DesktopAppInstaller.msixbundle"
        $WingetLicenseOutFile = "$env:TEMP\license.xml"
        Invoke-WebRequest -Uri $WingetUrl -OutFile $WingetOutFile
        Invoke-WebRequest -Uri $WingetLicenseUrl -OutFile $WingetLicenseOutFile
        Write-Log "winget downloaded."
    
        Write-Log "Installing winget..."
        Add-AppxProvisionedPackage -Online -PackagePath $WingetOutFile -LicensePath $WingetLicenseOutFile
        Write-Log "winget installed."
    
        # Clean up winget installation files
        Write-Log "Cleaning up winget installation files..."
        Remove-Item $VCLibsOutFile, $UIXamlOutFile, $WingetOutFile, $WingetLicenseOutFile
        Write-Log "winget installation files removed."
    
        # Update PATH to include winget
        Write-Log "Updating system PATH to include winget..."
        $WingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" | Select-Object -Last 1 -ExpandProperty Path
        if ($WingetPath) {
            $env:PATH = "$env:PATH;$WingetPath"
            [Environment]::SetEnvironmentVariable("Path", "$env:PATH;$WingetPath", [EnvironmentVariableTarget]::Machine)
            Write-Log "winget path added to system PATH."
        } else {
            Write-Log "ERROR: Could not locate winget installation path. Please verify installation."
            throw "Winget path not found"
        }
    
        # Verify winget is functional (attempt with elevated context)
        Write-Log "Verifying winget installation..."
        try {
            $WingetCommand = "winget --version"
            $WingetVersion = (Start-Process powershell -ArgumentList "-Command $WingetCommand" -Wait -NoNewWindow -PassThru).ExitCode
            if ($WingetVersion -eq 0) {
                Write-Log "winget is working correctly."
                Write-Log "Updating winget sources..."
                Start-Process powershell -ArgumentList "-Command 'winget source update'" -Wait -NoNewWindow
                Write-Log "winget sources updated."
            } else {
                Write-Log "WARNING: winget verification returned exit code $WingetVersion. Manual verification may be required."
            }
        } catch {
            Write-Log "ERROR: winget verification failed: $_"
            Write-Log "Manual verification via RDP may be required due to access restrictions during user data execution."
        }
    
        # Extract DSC v3
        Write-Log "Extracting DSC v3 to C:\Program Files\DSC\bin..."
        $DscOutFile = "C:\DSC\Modules\DSC-3.1.0-x86_64-pc-windows-msvc.zip"
        
        # Create DSC installation directory with proper permissions
        $DscInstallPath = "C:\Program Files\DSC"
        $DscBinPath = "$DscInstallPath\bin"
        
        Write-Log "Creating DSC installation directory: $DscInstallPath..."
        New-Item -ItemType Directory -Path $DscInstallPath -Force | Out-Null
        New-Item -ItemType Directory -Path $DscBinPath -Force | Out-Null
        Write-Log "DSC installation directories created."
        
        Write-Log "Extracting DSC v3 files..."
        Expand-Archive -Path $DscOutFile -DestinationPath $DscBinPath -Force
        Write-Log "DSC v3 files extracted successfully."
     
        # Clean up DSCv3 zip file
        Write-Log "Cleaning up DSC v3 zip file..."
        Remove-Item $DscOutFile
        Write-Log "DSC v3 zip file removed."
     
        # Verify DSC v3 executable exists
        Write-Log "Checking for DSC executable (dsc.exe)..."
        $DscExePath = "$DscBinPath\dsc.exe"
        if (Test-Path $DscExePath) {
            Write-Log "DSC executable found at: $DscExePath"
        } else {
            Write-Log "ERROR: DSC executable not found at expected location: $DscExePath"
            Write-Log "Searching for dsc.exe in extracted files..."
            $FoundDscExe = Get-ChildItem -Path $DscBinPath -Recurse -Name "dsc.exe" | Select-Object -First 1
            if ($FoundDscExe) {
                $DscExePath = Join-Path $DscBinPath $FoundDscExe
                Write-Log "Found DSC executable at: $DscExePath"
                $DscBinPath = Split-Path $DscExePath -Parent
            } else {
                Write-Log "ERROR: Could not find dsc.exe in any extracted files. Setup cannot continue."
                throw "DSC executable not found after extraction"
            }
        }
     
        # Add DSC v3 to PATH
        Write-Log "Adding DSC v3 to system PATH..."
        $env:PATH = "$env:PATH;$DscBinPath"
        [Environment]::SetEnvironmentVariable("Path", "$env:PATH;$DscBinPath", [EnvironmentVariableTarget]::Machine)
        Write-Log "DSC v3 path added to system PATH."
  
        # Install xWebAdministration module
        Write-Output "Copying xWebAdministration module..."
        if (Test-Path "C:\DSC\Modules\xWebAdministration") {
            Copy-Item -Path "C:\DSC\Modules\xWebAdministration" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Force
        } else {
            Write-Output "xWebAdministration module not found in C:\DSC\Modules."
            Stop-Transcript
            exit 1
        }

        # Apply DSCv2 configuration
        Write-Log "Applying DSCv2 configuration..."
        Set-Location -Path "C:\DSC"
        if (Test-Path ".\ConfigureIIS.ps1") {
            . .\ConfigureIIS.ps1
            ConfigureIIS -OutputPath "C:\DSC\MOF"
            Start-DscConfiguration -Path "C:\DSC\MOF" -Wait -Verbose -Force
        } else {
            Write-Log "ConfigureIIS.ps1 not found."
            Stop-Transcript
            exit 1
        }

        Write-Log "==== Windows Server 2022 setup via Terraform completed successfully! ===="
    } catch {
        Write-Log "ERROR: An error occurred during setup: $_"
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
Password: ${var.AdminPassword}
Instructions:
1. Use an RDP client (e.g., Microsoft Remote Desktop) to connect to the public IP.
2. Log in with the Administrator username and decrypted password.

EOT
}