/**
 * AWS Services
 *  - S3:               Asset storage (avatars, exports, backups)
 *  - SES:              Transactional email (welcome, password reset, alerts)
 *  - Secrets Manager:  Rotate DB credentials & JWT secrets
 *  - CloudWatch:       Structured logs + custom metrics
 */

const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, GetObjectCommandInput } = require('@aws-sdk/client-s3');
const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
const { SecretsManagerClient, GetSecretValueCommand, RotateSecretCommand } = require('@aws-sdk/client-secrets-manager');
const logger = require('./logger');

const awsConfig = {
  region:      process.env.AWS_REGION || 'us-east-1',
  credentials: process.env.AWS_ACCESS_KEY_ID ? {
    accessKeyId:     process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  } : undefined,  // Falls back to IAM role in production (ECS/EC2)
};

const s3Client       = new S3Client(awsConfig);
const sesClient      = new SESClient(awsConfig);
const secretsClient  = new SecretsManagerClient(awsConfig);

const BUCKET = process.env.AWS_S3_BUCKET || 'tenantOS-assets';
const FROM   = process.env.AWS_SES_FROM_EMAIL || 'noreply@tenantOS.io';

// ─── S3 ──────────────────────────────────────────────────────

/**
 * Upload file to S3 with tenant isolation
 * All objects are prefixed with tenantId for access control
 */
async function uploadToS3(tenantId, key, body, contentType, metadata = {}) {
  const objectKey = `tenants/${tenantId}/${key}`;
  const cmd = new PutObjectCommand({
    Bucket:      BUCKET,
    Key:         objectKey,
    Body:        body,
    ContentType: contentType,
    Metadata: {
      tenantId,
      uploadedAt: new Date().toISOString(),
      ...metadata,
    },
    ServerSideEncryption: 'AES256',
    Tagging: `tenantId=${tenantId}`,
  });

  try {
    await s3Client.send(cmd);
    logger.info('S3: file uploaded', { tenantId, key: objectKey });
    return {
      key:  objectKey,
      url:  `https://${BUCKET}.s3.${awsConfig.region}.amazonaws.com/${objectKey}`,
    };
  } catch (err) {
    logger.error('S3 upload error', { error: err.message, tenantId, key });
    throw err;
  }
}

async function deleteFromS3(tenantId, key) {
  const objectKey = `tenants/${tenantId}/${key}`;
  try {
    await s3Client.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: objectKey }));
    logger.info('S3: file deleted', { tenantId, key: objectKey });
  } catch (err) {
    logger.error('S3 delete error', { error: err.message, tenantId, key });
    throw err;
  }
}

/**
 * Upload audit log export to S3 (with server-side encryption)
 */
async function uploadAuditExport(tenantId, csvData, date) {
  const key = `exports/audit-${date}-${Date.now()}.csv`;
  return uploadToS3(tenantId, key, csvData, 'text/csv', { type: 'audit_export' });
}

// ─── SES ─────────────────────────────────────────────────────

const EMAIL_TEMPLATES = {
  welcome: (data) => ({
    subject: `Welcome to TenantOS, ${data.firstName}!`,
    html: `
      <h1>Welcome, ${data.firstName}!</h1>
      <p>Your account for <strong>${data.tenantName}</strong> has been created.</p>
      <p>Click below to verify your email:</p>
      <a href="${data.verifyUrl}" style="background:#00d4ff;color:#000;padding:10px 20px;border-radius:6px;text-decoration:none">Verify Email</a>
      <p>Your role: <strong>${data.role}</strong></p>
    `,
    text: `Welcome ${data.firstName}! Verify your email: ${data.verifyUrl}`,
  }),

  passwordReset: (data) => ({
    subject: 'Reset Your TenantOS Password',
    html: `
      <h1>Password Reset Request</h1>
      <p>Click the link below to reset your password. This link expires in 1 hour.</p>
      <a href="${data.resetUrl}">Reset Password</a>
      <p>If you didn't request this, ignore this email.</p>
    `,
    text: `Reset your password: ${data.resetUrl} (expires in 1 hour)`,
  }),

  securityAlert: (data) => ({
    subject: `[Security Alert] ${data.event}`,
    html: `
      <h1>Security Alert</h1>
      <p><strong>Event:</strong> ${data.event}</p>
      <p><strong>IP:</strong> ${data.ip}</p>
      <p><strong>Time:</strong> ${new Date().toISOString()}</p>
      ${data.action ? `<p><strong>Action taken:</strong> ${data.action}</p>` : ''}
    `,
    text: `Security alert: ${data.event} from ${data.ip}`,
  }),

  tenantSuspended: (data) => ({
    subject: 'Your TenantOS Account Has Been Suspended',
    html: `
      <h1>Account Suspended</h1>
      <p>Your tenant <strong>${data.tenantName}</strong> has been suspended.</p>
      <p>Reason: ${data.reason}</p>
      <p>Contact support@tenantOS.io to resolve this issue.</p>
    `,
    text: `Your tenant ${data.tenantName} has been suspended. Reason: ${data.reason}`,
  }),
};

async function sendEmail(to, templateName, templateData) {
  const template = EMAIL_TEMPLATES[templateName];
  if (!template) throw new Error(`Email template "${templateName}" not found`);

  const { subject, html, text } = template(templateData);

  const cmd = new SendEmailCommand({
    Source: FROM,
    Destination: { ToAddresses: Array.isArray(to) ? to : [to] },
    Message: {
      Subject: { Data: subject, Charset: 'UTF-8' },
      Body: {
        Html: { Data: html, Charset: 'UTF-8' },
        Text: { Data: text, Charset: 'UTF-8' },
      },
    },
    ConfigurationSetName: 'tenantOS-transactional',
  });

  try {
    const result = await sesClient.send(cmd);
    logger.info('SES: email sent', { to, template: templateName, messageId: result.MessageId });
    return result.MessageId;
  } catch (err) {
    // Don't throw — email failure shouldn't break auth flow
    logger.error('SES email error', { error: err.message, to, template: templateName });
    return null;
  }
}

// ─── SECRETS MANAGER ─────────────────────────────────────────

/**
 * Fetch secrets from AWS Secrets Manager at startup.
 * Enables automatic credential rotation without redeployment.
 */
async function getSecret(secretArn) {
  try {
    const cmd = new GetSecretValueCommand({ SecretId: secretArn });
    const response = await secretsClient.send(cmd);
    const secret = response.SecretString
      ? JSON.parse(response.SecretString)
      : JSON.parse(Buffer.from(response.SecretBinary, 'base64').toString('ascii'));
    logger.info('Secrets Manager: secret fetched', { arn: secretArn.split(':').pop() });
    return secret;
  } catch (err) {
    logger.warn('Secrets Manager: could not fetch secret (using env vars)', { error: err.message });
    return null;
  }
}

/**
 * Load secrets and override env vars.
 * Called at startup if AWS_SECRETS_MANAGER_ARN is set.
 */
async function loadSecretsFromAWS() {
  const arn = process.env.AWS_SECRETS_MANAGER_ARN;
  if (!arn) {
    logger.info('Secrets Manager: no ARN set, using env vars');
    return;
  }

  const secrets = await getSecret(arn);
  if (!secrets) return;

  // Override environment with secrets
  const mappings = {
    POSTGRES_PASSWORD:   'db_password',
    JWT_ACCESS_SECRET:   'jwt_access_secret',
    JWT_REFRESH_SECRET:  'jwt_refresh_secret',
    REDIS_PASSWORD:      'redis_password',
    SESSION_SECRET:      'session_secret',
  };

  for (const [envKey, secretKey] of Object.entries(mappings)) {
    if (secrets[secretKey]) {
      process.env[envKey] = secrets[secretKey];
    }
  }

  logger.info('Secrets Manager: credentials loaded and applied');
}

// ─── CLOUDWATCH METRICS ──────────────────────────────────────
// Metrics are emitted as structured log lines that a CloudWatch
// Logs metric filter can parse into custom metrics.

function emitMetric(name, value, unit = 'Count', dimensions = {}) {
  logger.info('METRIC', {
    metricName: name,
    value,
    unit,
    dimensions,
    timestamp: new Date().toISOString(),
  });
}

const Metrics = {
  loginSuccess:  (tenantId) => emitMetric('LoginSuccess',  1, 'Count', { tenantId }),
  loginFailure:  (tenantId) => emitMetric('LoginFailure',  1, 'Count', { tenantId }),
  tokenRefresh:  (tenantId) => emitMetric('TokenRefresh',  1, 'Count', { tenantId }),
  sessionRevoke: (tenantId) => emitMetric('SessionRevoke', 1, 'Count', { tenantId }),
  bruteForceBlock:(ip)      => emitMetric('BruteForceBlock',1,'Count', { ip }),
  apiRequest:    (tenantId, method, path, status, duration) =>
    emitMetric('ApiRequest', duration, 'Milliseconds', { tenantId, method, path, status: String(status) }),
};

module.exports = {
  s3Client, sesClient, secretsClient,
  uploadToS3, deleteFromS3, uploadAuditExport,
  sendEmail,
  getSecret, loadSecretsFromAWS,
  Metrics,
};
