// Use this code snippet in your app.
// If you need more information about configurations or implementing the sample code, visit the AWS docs:
// https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/getting-started.html

const { SecretsManagerClient, GetSecretValueCommand } = require("@aws-sdk/client-secrets-manager");

const secret_name = "win_srv_2022-user-credentials-test";

const client = new SecretsManagerClient({
    region: "us-east-1",
});

// Cache configuration
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes in milliseconds
let credentialsCache = null;
let cacheTimestamp = null;

/**
 * Retrieves user credentials from AWS Secrets Manager with caching
 * @param {boolean} forceRefresh - Force refresh the cache (default: false)
 * @returns {Promise<Object>} Object containing username and password
 * @throws {Error} If secret retrieval fails
 */
async function getCredentials(forceRefresh = false) {
    const now = Date.now();
    
    // Check if we have valid cached credentials
    if (!forceRefresh && 
        credentialsCache && 
        cacheTimestamp && 
        (now - cacheTimestamp) < CACHE_TTL) {
        console.log('Using cached credentials (cache age:', Math.round((now - cacheTimestamp) / 1000), 'seconds)');
        return credentialsCache;
    }

    try {
        console.log('Fetching fresh credentials from AWS Secrets Manager...');
        const response = await client.send(
            new GetSecretValueCommand({
                SecretId: secret_name,
                VersionStage: "AWSCURRENT", // VersionStage defaults to AWSCURRENT if unspecified
            })
        );

        // Parse the secret string as JSON
        const secretData = JSON.parse(response.SecretString);
        
        // Create credentials object
        const credentials = {
            username: secretData.username,
            password: secretData.password
        };

        // Update cache
        credentialsCache = credentials;
        cacheTimestamp = now;
        
        console.log('Credentials cached successfully');
        return credentials;
    } catch (error) {
        // For a list of exceptions thrown, see
        // https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        console.error('Error retrieving credentials from Secrets Manager:', error);
        
        // If we have cached credentials and there's an error, return cached version
        if (credentialsCache && !forceRefresh) {
            console.log('Using cached credentials due to API error');
            return credentialsCache;
        }
        
        throw error;
    }
}

/**
 * Clears the credentials cache
 */
function clearCache() {
    credentialsCache = null;
    cacheTimestamp = null;
    console.log('Credentials cache cleared');
}

/**
 * Gets cache status information
 * @returns {Object} Cache status including age and validity
 */
function getCacheStatus() {
    if (!credentialsCache || !cacheTimestamp) {
        return { cached: false, age: null, valid: false };
    }
    
    const now = Date.now();
    const age = now - cacheTimestamp;
    const valid = age < CACHE_TTL;
    
    return {
        cached: true,
        age: Math.round(age / 1000), // age in seconds
        valid: valid,
        ttl: Math.round(CACHE_TTL / 1000) // TTL in seconds
    };
}

// Example usage
async function main() {
    try {
        // First call - will fetch from AWS
        console.log('=== First call ===');
        const credentials1 = await getCredentials();
        console.log('Retrieved credentials:', {
            username: credentials1.username,
            password: credentials1.password
        });

        // Second call - will use cache
        console.log('\n=== Second call (should use cache) ===');
        const credentials2 = await getCredentials();
        console.log('Retrieved credentials:', {
            username: credentials2.username,
            password: credentials2.password
        });

        // Check cache status
        console.log('\n=== Cache Status ===');
        console.log('Cache status:', getCacheStatus());

        // Force refresh
        console.log('\n=== Force refresh ===');
        const credentials3 = await getCredentials(true);
        console.log('Retrieved credentials (forced refresh):', {
            username: credentials3.username,
            password: credentials3.password
        });

        return credentials1;
    } catch (error) {
        console.error('Failed to get credentials:', error);
        throw error;
    }
}

// Export the functions for use in other modules
module.exports = { 
    getCredentials, 
    clearCache, 
    getCacheStatus 
};

// If this file is run directly, execute the main function
if (require.main === module) {
    main().catch(console.error);
}