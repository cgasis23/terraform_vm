# Windows IIS Configuration Automation

This project provides scripts and resources to automate the configuration of IIS (Internet Information Services) on Windows servers using PowerShell Desired State Configuration (DSC).

## Contents

- `ConfigureIIS.ps1`: Main PowerShell DSC configuration script for setting up IIS and related scheduled tasks.
- `scripts/`: Contains supporting JavaScript and VBScript files for logging and credential management.
- `Modules/`: Contains required DSC modules (e.g., xWebAdministration, PSDesiredStateConfiguration).

## Usage

1. **Edit Configuration**
   - Adjust parameters in `ConfigureIIS.ps1` as needed for your environment.

2. **Prepare for Deployment**
   - Ensure all files and folders (`ConfigureIIS.ps1`, `scripts/`, `Modules/`) are present in the root directory.

3. **Zipping Files via PowerShell**

   To create a zip archive containing `ConfigureIIS.ps1`, the `scripts` folder, and the `Modules` folder, run the following PowerShell command from the project root:

   ```powershell
   Compress-Archive -Path .\ConfigureIIS.ps1, .\scripts, .\Modules -DestinationPath .\IISConfigPackage.zip -Force
   ```

   - This will create `IISConfigPackage.zip` in the root directory, containing all specified files and folders.

4. **Extracting the Package**
   - To extract the contents, use:
     ```powershell
     Expand-Archive -Path .\IISConfigPackage.zip -DestinationPath .\ExtractedPackage -Force
     ```

## Uploading the Zip File to S3

To upload your zip file to an S3 bucket using the AWS CLI, use the following command (replace the local path and bucket as needed):

```powershell
aws s3 cp C:\DSC\ConfigureIIS.zip s3://my-dsc-bucket-123/ConfigureIIS.zip --region us-east-1
```

- Ensure you have the AWS CLI installed and configured with appropriate credentials.
- Adjust the local path and S3 bucket/key as needed for your environment.

## Requirements
- Windows PowerShell 5.1 or later
- Administrative privileges to run DSC and scheduled tasks
- Node.js (if using JavaScript scripts)

## Notes
- Make sure the `Modules` folder contains all required DSC modules before deployment.
- Update script paths and parameters in `ConfigureIIS.ps1` as needed for your environment. 

## Applying the Terraform Script to Provision an EC2 Instance

To use the provided `main.tf` Terraform script to provision an EC2 instance, follow these steps:

### Prerequisites
- [Terraform](https://www.terraform.io/downloads.html) installed on your system
- AWS CLI installed and configured with credentials (`aws configure`)
- Sufficient permissions to create EC2 resources in your AWS account

### Steps
1. **Open a terminal and navigate to your project directory:**
   ```sh
   cd C:/Users/cgasi/source/repos/terraform-windows-vm
   ```

2. **Initialize Terraform:**
   ```sh
   terraform init
   ```
   This will download the necessary provider plugins and set up your working directory.

3. **Create and review the execution plan:**
   ```sh
   terraform plan -out=tfplan
   ```
   This command creates a plan file (`tfplan`) and shows what resources will be created or changed.

4. **Apply the Terraform plan:**
   ```sh
   terraform apply tfplan
   ```
   - This applies exactly what was planned in the previous step.
   - Type `yes` when prompted to confirm the action.

5. **Verify the EC2 instance:**
   - After the apply completes, you can check your AWS Console to see the new EC2 instance.

### Notes
- Make sure your `main.tf` is configured with the correct region, AMI, instance type, and any other required variables.
- You can destroy the resources when done with:
  ```sh
  terraform destroy
  ``` 