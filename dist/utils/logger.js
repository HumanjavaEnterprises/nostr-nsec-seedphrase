/**
 * @module Logger
 * @category Utils
 * @description Enhanced logging utility with support for both ESM and CJS.
 * Provides consistent logging across the application with proper type safety.
 */
import pino from 'pino';
/**
 * Configuration options for the logger
 */
const options = {
    level: process.env.LOG_LEVEL || 'info'
};
// Create the logger instance
const baseLogger = pino(options);
// Create the custom logger instance
const logger = baseLogger;
// Add log method as an alias for info with enhanced type safety
logger.log = (obj, msg) => {
    if (typeof obj === 'string') {
        logger.info(obj);
    }
    else {
        logger.info(obj, msg);
    }
};
export { logger };
export default logger;
