const fs = require('fs');
const path = require('path');
const { getCredentials } = require('./getCredentials.js');

const logDir = 'C:\\logs';
const logFile = path.join(logDir, 'hello_world.log');

async function logHelloWorld() {
    try {
        // Get credentials from AWS Secrets Manager
        const credentials = await getCredentials();
        
        const timestamp = new Date().toISOString();
        const logMessage = `${timestamp}: Hello World! Username: ${credentials.username}, Password: ${credentials.password}\n`;
        
        // Ensure log directory exists
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }
        
        fs.appendFile(logFile, logMessage, (err) => {
            if (err) {
                console.error('Error writing to log file:', err);
                process.exit(1);
            } else {
                console.log('Log entry written successfully!');
                console.log('Retrieved credentials from AWS Secrets Manager:');
                console.log(`Username: ${credentials.username}`);
                console.log(`Password: ${credentials.password}`);
            }
        });
    } catch (error) {
        console.error('Error retrieving credentials:', error);
        process.exit(1);
    }
}

logHelloWorld();