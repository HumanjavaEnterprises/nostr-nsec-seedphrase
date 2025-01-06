"use strict";
/**
 * @module Logger
 * @category Utils
 * @description Enhanced logging utility with support for both ESM and CJS.
 * Provides consistent logging across the application with proper type safety.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
const pino_1 = __importDefault(require("pino"));
/**
 * Configuration options for the logger
 */
const options = {
    level: process.env.LOG_LEVEL || 'info'
};
// Create the logger instance
const baseLogger = (0, pino_1.default)(options);
// Create the custom logger instance
const logger = baseLogger;
exports.logger = logger;
// Add log method as an alias for info with enhanced type safety
logger.log = (obj, msg) => {
    if (typeof obj === 'string') {
        logger.info(obj);
    }
    else {
        logger.info(obj, msg);
    }
};
exports.default = logger;
