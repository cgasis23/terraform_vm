// Use this code snippet in your app.
// If you need more information about configurations or implementing the sample code, visit the AWS docs:
// https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/getting-started.html

const { SecretsManagerClient, GetSecretValueCommand } = require("@aws-sdk/client-secrets-manager");

const secret_name = "win_srv_2022-user-credentials-test";

const client = new SecretsManagerClient({
    region: "us-east-1",
});

/**
 * Retrieves user credentials from AWS Secrets Manager
 * @returns {Promise<Object>} Object containing username and password
 * @throws {Error} If secret retrieval fails
 */
async function getCredentials() {
    try {
        const response = await client.send(
            new GetSecretValueCommand({
                SecretId: secret_name,
                VersionStage: "AWSCURRENT", // VersionStage defaults to AWSCURRENT if unspecified
            })
        );

        // Parse the secret string as JSON
        const secretData = JSON.parse(response.SecretString);
        
        // Return the credentials object
        return {
            username: secretData.username,
            password: secretData.password
        };
    } catch (error) {
        // For a list of exceptions thrown, see
        // https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        console.error('Error retrieving credentials from Secrets Manager:', error);
        throw error;
    }
}

// Example usage
async function main() {
    try {
        const credentials = await getCredentials();
        console.log('Retrieved credentials:', {
            username: credentials.username,
            password: credentials.password
        });
        return credentials;
    } catch (error) {
        console.error('Failed to get credentials:', error);
        throw error;
    }
}

// Export the function for use in other modules
module.exports = { getCredentials };

// If this file is run directly, execute the main function
if (require.main === module) {
    main().catch(console.error);
}