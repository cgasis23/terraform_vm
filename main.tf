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
      # Create log file for debugging
      Start-Transcript -Path "C:\DSC\user_data_log.txt" -Append
      
      # Create the C:\DSC and C:\logs directories with proper permissions
      New-Item -ItemType Directory -Path "C:\DSC" -Force
      $logDir = "C:\logs"
      if (-not (Test-Path -Path $logDir)) {
          New-Item -ItemType Directory -Path $logDir -Force
          $acl = Get-Acl -Path $logDir
          $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
          $acl.AddAccessRule($rule)
          Set-Acl -Path $logDir -AclObject $acl
          Write-Output "Created C:\logs with SYSTEM full control."
      }
  
      # Install Node.js
      Write-Output "Installing Node.js..."
      $nodeUrl = "https://nodejs.org/dist/v20.17.0/node-v20.17.0-x64.msi" # Use the latest LTS version
      Invoke-WebRequest -Uri $nodeUrl -OutFile "C:\DSC\node-v20.17.0-x64.msi"
      Start-Process -FilePath "msiexec.exe" -ArgumentList "/i C:\DSC\node-v20.17.0-x64.msi /quiet /norestart" -Wait
      Remove-Item "C:\DSC\node-v20.17.0-x64.msi" -Force
      $env:Path += ";C:\Program Files\nodejs\"
      [Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)
      Write-Output "Node.js installation completed."
  
#       $scriptDir = "C:\Scripts"
#       if (-not (Test-Path -Path $scriptDir)) {
#           New-Item -ItemType Directory -Path $scriptDir -Force
#           $acl = Get-Acl -Path $scriptDir
#           $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
#           $acl.AddAccessRule($rule)
#           Set-Acl -Path $scriptDir -AclObject $acl
#           Write-Output "Created C:\Scripts with SYSTEM full control."
#       }
      
      # Install AWS CLI
      Write-Output "Installing AWS CLI..."
      Invoke-WebRequest -Uri "https://awscli.amazonaws.com/AWSCLIV2.msi" -OutFile "C:\DSC\AWSCLIV2.msi"
      Start-Process -FilePath "msiexec.exe" -ArgumentList "/i C:\DSC\AWSCLIV2.msi /quiet" -Wait
      Remove-Item "C:\DSC\AWSCLIV2.msi" -Force
      
      # Add AWS CLI to PATH
      $env:Path += ";C:\Program Files\Amazon\AWSCLIV2"
      [Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)
      
      # Download ConfigureIIS.zip from S3
      Write-Output "Downloading ConfigureIIS.zip from S3..."
      aws s3 cp s3://my-dsc-bucket-123/ConfigureIIS.zip C:\DSC\ConfigureIIS.zip --region us-east-1
      
      # Verify file download
      if (Test-Path "C:\DSC\ConfigureIIS.zip") {
          Write-Output "ConfigureIIS.zip downloaded successfully."
      } else {
          Write-Output "Failed to download ConfigureIIS.zip."
          Stop-Transcript
          exit 1
      }
      
      # Unzip the package
      Write-Output "Unzipping ConfigureIIS.zip..."
      Expand-Archive -Path "C:\DSC\ConfigureIIS.zip" -DestinationPath "C:\DSC" -Force
      
      # Install xWebAdministration module
      Write-Output "Copying xWebAdministration module..."
      if (Test-Path "C:\DSC\Modules\xWebAdministration") {
          Copy-Item -Path "C:\DSC\Modules\xWebAdministration" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Force
      } else {
          Write-Output "xWebAdministration module not found in C:\DSC\Modules."
          Stop-Transcript
          exit 1
      } 
      
      # Apply DSC configuration
      Write-Output "Applying DSC configuration..."
      Set-Location -Path "C:\DSC"
      if (Test-Path ".\ConfigureIIS.ps1") {
          . .\ConfigureIIS.ps1
          ConfigureIIS -OutputPath "C:\DSC\MOF"
          Start-DscConfiguration -Path "C:\DSC\MOF" -Wait -Verbose -Force
      } else {
          Write-Output "ConfigureIIS.ps1 not found."
          Stop-Transcript
          exit 1
      }
      
      Write-Output "User data script completed."
      Stop-Transcript
  </powershell>
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