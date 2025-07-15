@echo off
REM Batch file to package IIS config and upload to S3

REM Set variables
set ZIP_NAME=ConfigureIIS.zip
set ZIP_PATH=C:\DSC\%ZIP_NAME%
set SRC1=ConfigureIIS.ps1
set SRC2=scripts
set SRC3=Modules
set S3_BUCKET=s3://my-dsc-bucket-123/ConfigureIIS.zip
set AWS_REGION=us-east-1

echo [INFO] Compressing files and folders into %ZIP_PATH% ...
powershell -Command "Compress-Archive -Path %SRC1%, .\%SRC2%, .\%SRC3% -DestinationPath %ZIP_PATH% -Force"

echo [INFO] Uploading %ZIP_PATH% to %S3_BUCKET% ...
aws s3 cp %ZIP_PATH% %S3_BUCKET% --region %AWS_REGION%

echo [SUCCESS] Packaging and upload complete!
pause 