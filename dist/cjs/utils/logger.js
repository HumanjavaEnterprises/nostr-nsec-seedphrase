"use strict";
/**
 * @module Logger
 * @category Utils
 * @description Enhanced logging utility with support for both browser and Node environments.
 * Provides consistent logging across the application with proper type safety.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
class BrowserLogger {
    logWithLevel(level, obj, msg) {
        const consoleMethod = console[level];
        if (typeof obj === 'string') {
            consoleMethod(obj);
        }
        else {
            consoleMethod(obj, msg || '');
        }
    }
    error(obj, msg) {
        this.logWithLevel('error', obj, msg);
    }
    warn(obj, msg) {
        this.logWithLevel('warn', obj, msg);
    }
    info(obj, msg) {
        this.logWithLevel('info', obj, msg);
    }
    debug(obj, msg) {
        this.logWithLevel('debug', obj, msg);
    }
    log(obj, msg) {
        this.logWithLevel('log', obj, msg);
    }
}
// Create and export the browser-compatible logger
const logger = new BrowserLogger();
exports.logger = logger;
exports.default = logger;
