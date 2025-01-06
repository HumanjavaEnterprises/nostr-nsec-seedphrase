/**
 * @module Logger
 * @category Utils
 * @description Enhanced logging utility with support for both ESM and CJS.
 * Provides consistent logging across the application with proper type safety.
 */

import pino, { Logger } from 'pino';

/**
 * Configuration options for the logger
 */
const options = {
  level: process.env.LOG_LEVEL || 'info'
};

/**
 * Custom logger type that extends pino's Logger with additional functionality
 */
type CustomLogger = Logger & {
  /**
   * Enhanced log method that handles both string and object-based logging
   * @param {string | Record<string, unknown>} obj - The message or object to log
   * @param {string} [msg] - Optional message when logging an object
   */
  log: (obj: string | Record<string, unknown>, msg?: string) => void;
};

// Create the logger instance
const baseLogger = pino(options) as Logger;

// Create the custom logger instance
const logger = baseLogger as CustomLogger;

// Add log method as an alias for info with enhanced type safety
logger.log = (obj: string | Record<string, unknown>, msg?: string) => {
  if (typeof obj === 'string') {
    logger.info(obj);
  } else {
    logger.info(obj, msg);
  }
};

export { logger };
export default logger;
