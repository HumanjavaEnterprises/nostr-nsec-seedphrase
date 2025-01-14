/**
 * @module Logger
 * @category Utils
 * @description Enhanced logging utility with support for both browser and Node environments.
 * Provides consistent logging across the application with proper type safety.
 */
interface LoggerInterface {
    error(obj: string | Record<string, unknown>, msg?: string): void;
    warn(obj: string | Record<string, unknown>, msg?: string): void;
    info(obj: string | Record<string, unknown>, msg?: string): void;
    debug(obj: string | Record<string, unknown>, msg?: string): void;
    log(obj: string | Record<string, unknown>, msg?: string): void;
}
declare const logger: LoggerInterface;
export { logger };
export default logger;
