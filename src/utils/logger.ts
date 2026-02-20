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

class BrowserLogger implements LoggerInterface {
  private logWithLevel(
    level: "error" | "warn" | "info" | "debug" | "log",
    obj: string | Record<string, unknown>,
    msg?: string,
  ): void {
    const consoleMethod = console[level];
    if (typeof obj === "string") {
      consoleMethod(obj);
    } else {
      consoleMethod(obj, msg || "");
    }
  }

  error(obj: string | Record<string, unknown>, msg?: string): void {
    this.logWithLevel("error", obj, msg);
  }

  warn(obj: string | Record<string, unknown>, msg?: string): void {
    this.logWithLevel("warn", obj, msg);
  }

  info(obj: string | Record<string, unknown>, msg?: string): void {
    this.logWithLevel("info", obj, msg);
  }

  debug(obj: string | Record<string, unknown>, msg?: string): void {
    this.logWithLevel("debug", obj, msg);
  }

  log(obj: string | Record<string, unknown>, msg?: string): void {
    this.logWithLevel("log", obj, msg);
  }
}

// Create and export the browser-compatible logger
const logger: LoggerInterface = new BrowserLogger();

export { logger };
export default logger;
