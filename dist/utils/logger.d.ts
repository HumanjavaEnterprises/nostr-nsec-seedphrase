/**
 * @module Logger
 * @category Utils
 * @description Enhanced logging utility with support for both ESM and CJS.
 * Provides consistent logging across the application with proper type safety.
 */
import { Logger } from 'pino';
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
declare const logger: CustomLogger;
export { logger };
export default logger;
