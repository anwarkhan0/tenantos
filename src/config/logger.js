/**
 * Winston Logger
 * Outputs structured JSON logs.
 * In production, streams to AWS CloudWatch Logs.
 */

const winston = require('winston');

const { combine, timestamp, json, errors, colorize, printf } = winston.format;

const devFormat = printf(({ level, message, timestamp, ...meta }) => {
  const metaStr = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
  return `${timestamp} [${level}]: ${message}${metaStr}`;
});

const transports = [
  new winston.transports.Console({
    format: process.env.NODE_ENV === 'production'
      ? combine(timestamp(), errors({ stack: true }), json())
      : combine(colorize(), timestamp({ format: 'HH:mm:ss' }), errors({ stack: true }), devFormat),
  }),
];

// CloudWatch transport (only when LOG_TO_CLOUDWATCH=true)
if (process.env.LOG_TO_CLOUDWATCH === 'true' && process.env.AWS_CLOUDWATCH_GROUP) {
  try {
    const WinstonCloudWatch = require('winston-cloudwatch');
    transports.push(new WinstonCloudWatch({
      logGroupName:  process.env.AWS_CLOUDWATCH_GROUP,
      logStreamName: `${process.env.NODE_ENV}-${process.env.HOSTNAME || 'app'}`,
      awsRegion:     process.env.AWS_REGION || 'us-east-1',
      jsonMessage:   true,
      uploadRate:    2000,
    }));
  } catch (e) {
    console.warn('CloudWatch transport not available:', e.message);
  }
}

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  defaultMeta: {
    service: 'tenantOS',
    env:     process.env.NODE_ENV || 'development',
    version: process.env.npm_package_version || '2.0.0',
  },
  transports,
  exitOnError: false,
});

module.exports = logger;
