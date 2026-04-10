/**
 * Auth Routes
 *
 * POST /api/v1/auth/register       — Create user account
 * POST /api/v1/auth/login          — Issue access + refresh tokens
 * POST /api/v1/auth/refresh        — Rotate refresh token
 * POST /api/v1/auth/logout         — Revoke current session
 * POST /api/v1/auth/logout-all     — Revoke ALL sessions
 * GET  /api/v1/auth/sessions       — List active sessions
 * GET  /api/v1/auth/me             — Current user profile
 * POST /api/v1/auth/change-password
 */

const express  = require('express');
const Joi      = require('joi');
const router   = express.Router();

const AuthService  = require('../services/auth.service');
const AuditService = require('../services/audit.service');
const {
  bruteForceProtection, authRateLimit, authenticate,
  tenantContext, validateBody,
} = require('../middleware');
const db     = require('../config/database');
const redis  = require('../config/redis');
const logger = require('../config/logger');

// ─── VALIDATION SCHEMAS ───────────────────────────────────────

const schemas = {
  register: Joi.object({
    email:     Joi.string().email().lowercase().required(),
    password:  Joi.string().min(8).max(128)
                 .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
                 .message('Password must have uppercase, lowercase, and number').required(),
    firstName: Joi.string().min(1).max(100).required(),
    lastName:  Joi.string().min(1).max(100).required(),
    role:      Joi.string().valid('admin','developer','analyst','viewer').default('viewer'),
  }),

  login: Joi.object({
    email:    Joi.string().email().lowercase().required(),
    password: Joi.string().required(),
  }),

  refresh: Joi.object({
    refreshToken: Joi.string().required(),
  }),

  logout: Joi.object({
    refreshToken: Joi.string().optional(),
  }),

  changePassword: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword:     Joi.string().min(8).max(128)
                       .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
                       .required(),
  }),
};

// Helper to get request metadata
const meta = (req) => ({
  ipAddress: req.ip || req.connection?.remoteAddress,
  userAgent: req.get('User-Agent'),
});

// ─── REGISTER ─────────────────────────────────────────────────

router.post('/register',
  authRateLimit,
  tenantContext,
  validateBody(schemas.register),
  async (req, res, next) => {
    try {
      const user = await AuthService.register({
        ...req.body,
        tenantId: req.tenant.id,
        ...meta(req),
      });

      res.status(201).json({
        ok:   true,
        data: {
          user: {
            id:        user.id,
            email:     user.email,
            firstName: user.first_name,
            lastName:  user.last_name,
            role:      user.role,
            tenantId:  req.tenant.id,
          },
          message: 'Account created. Please check your email to verify.',
        },
      });
    } catch (err) { next(err); }
  }
);

// ─── LOGIN ────────────────────────────────────────────────────

router.post('/login',
  authRateLimit,
  tenantContext,
  bruteForceProtection,         // ← checks Redis before touching DB
  validateBody(schemas.login),
  async (req, res, next) => {
    try {
      const result = await AuthService.login({
        email:    req.body.email,
        password: req.body.password,
        tenantId: req.tenant.id,
        ...meta(req),
      });

      // Set refresh token as HttpOnly cookie (more secure than body)
      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure:   process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge:   7 * 24 * 60 * 60 * 1000,  // 7 days
        path:     '/api/v1/auth',             // scoped to auth routes
      });

      res.json({
        ok:   true,
        data: {
          accessToken: result.accessToken,
          tokenType:   result.tokenType,
          expiresIn:   result.expiresIn,
          sessionId:   result.sessionId,
          user:        result.user,
          // Refresh token also in body for non-browser clients
          refreshToken: result.refreshToken,
        },
      });
    } catch (err) { next(err); }
  }
);

// ─── REFRESH TOKEN ROTATION ───────────────────────────────────

router.post('/refresh',
  authRateLimit,
  validateBody(schemas.refresh),
  async (req, res, next) => {
    try {
      // Accept from body or cookie
      const refreshToken = req.body.refreshToken || req.cookies?.refreshToken;
      if (!refreshToken) {
        return res.status(400).json({ ok: false, error: 'Refresh token required', code: 'NO_REFRESH_TOKEN' });
      }

      const result = await AuthService.refresh({ refreshToken, ...meta(req) });

      // Rotate cookie
      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure:   process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge:   7 * 24 * 60 * 60 * 1000,
        path:     '/api/v1/auth',
      });

      res.json({
        ok:   true,
        data: {
          accessToken:  result.accessToken,
          refreshToken: result.refreshToken,
          tokenType:    result.tokenType,
          expiresIn:    result.expiresIn,
        },
      });
    } catch (err) { next(err); }
  }
);

// ─── LOGOUT ───────────────────────────────────────────────────

router.post('/logout',
  authenticate,
  validateBody(schemas.logout),
  async (req, res, next) => {
    try {
      const refreshToken = req.body.refreshToken || req.cookies?.refreshToken;
      const { user } = req;

      await AuthService.logout({
        userId:         user.id,
        tenantId:       user.tenantId,
        jti:            user.jti,
        accessExpiresIn: Math.max(0, user.tokenExp - Math.floor(Date.now() / 1000)),
        refreshToken,
        ...meta(req),
      });

      // Clear cookie
      res.clearCookie('refreshToken', { path: '/api/v1/auth' });

      res.json({ ok: true, data: { message: 'Logged out successfully' } });
    } catch (err) { next(err); }
  }
);

// ─── LOGOUT ALL SESSIONS ──────────────────────────────────────

router.post('/logout-all',
  authenticate,
  async (req, res, next) => {
    try {
      const count = await AuthService.logoutAll(req.user.id, req.user.tenantId, req.ip);
      res.clearCookie('refreshToken', { path: '/api/v1/auth' });
      res.json({ ok: true, data: { message: `${count} sessions terminated`, sessionsRevoked: count } });
    } catch (err) { next(err); }
  }
);

// ─── ACTIVE SESSIONS ──────────────────────────────────────────

router.get('/sessions',
  authenticate,
  async (req, res, next) => {
    try {
      // Get sessions from DB (persistent) + Redis (fast)
      const dbSessions = await db.query(
        `SELECT id, ip_address, user_agent, last_active, created_at, expires_at
         FROM sessions
         WHERE user_id = $1 AND is_active = TRUE AND expires_at > NOW()
         ORDER BY last_active DESC`,
        [req.user.id]
      );

      const sessions = dbSessions.rows.map(s => ({
        sessionId:  s.id,
        ipAddress:  s.ip_address,
        userAgent:  s.user_agent,
        lastActive: s.last_active,
        createdAt:  s.created_at,
        expiresAt:  s.expires_at,
      }));

      res.json({ ok: true, data: { sessions, total: sessions.length } });
    } catch (err) { next(err); }
  }
);

// DELETE /sessions/:sessionId — revoke a specific session
router.delete('/sessions/:sessionId',
  authenticate,
  async (req, res, next) => {
    try {
      const { sessionId } = req.params;

      // Verify ownership
      const result = await db.query(
        `UPDATE sessions SET is_active = FALSE
         WHERE id = $1 AND user_id = $2
         RETURNING token_family`,
        [sessionId, req.user.id]
      );

      if (!result.rows[0]) {
        return res.status(404).json({ ok: false, error: 'Session not found' });
      }

      await redis.deleteSession(sessionId);

      // Revoke the token family
      await db.query(
        `UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW(), revoke_reason = 'session_deleted'
         WHERE family_id = $1`,
        [result.rows[0].token_family]
      );

      await AuditService.log({
        tenantId: req.user.tenantId, userId: req.user.id,
        type: 'auth', severity: 'info', action: 'SESSION_REVOKED',
        metadata: { sessionId }, ipAddress: req.ip,
      });

      res.json({ ok: true, data: { message: 'Session revoked' } });
    } catch (err) { next(err); }
  }
);

// ─── ME ───────────────────────────────────────────────────────

router.get('/me',
  authenticate,
  async (req, res, next) => {
    try {
      const result = await db.query(
        `SELECT u.id, u.email, u.first_name, u.last_name, u.role, u.status,
                u.email_verified, u.last_login_at, u.mfa_enabled, u.created_at,
                t.name as tenant_name, t.plan, t.slug as tenant_slug
         FROM users u
         JOIN tenants t ON t.id = u.tenant_id
         WHERE u.id = $1 AND u.deleted_at IS NULL`,
        [req.user.id]
      );

      const user = result.rows[0];
      if (!user) return res.status(404).json({ ok: false, error: 'User not found' });

      res.json({
        ok:   true,
        data: {
          id:           user.id,
          email:        user.email,
          firstName:    user.first_name,
          lastName:     user.last_name,
          role:         user.role,
          status:       user.status,
          emailVerified: user.email_verified,
          mfaEnabled:   user.mfa_enabled,
          lastLoginAt:  user.last_login_at,
          createdAt:    user.created_at,
          tenant: {
            name: user.tenant_name,
            plan: user.plan,
            slug: user.tenant_slug,
          },
        },
      });
    } catch (err) { next(err); }
  }
);

// ─── CHANGE PASSWORD ──────────────────────────────────────────

router.post('/change-password',
  authenticate,
  validateBody(schemas.changePassword),
  async (req, res, next) => {
    try {
      const { currentPassword, newPassword } = req.body;

      const userRes = await db.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
      const user = userRes.rows[0];

      const valid = await AuthService.verifyPassword(currentPassword, user.password_hash);
      if (!valid) {
        return res.status(401).json({ ok: false, error: 'Current password is incorrect' });
      }

      const newHash = await AuthService.hashPassword(newPassword);
      await db.query(
        'UPDATE users SET password_hash = $1, password_changed_at = NOW() WHERE id = $2',
        [newHash, req.user.id]
      );

      // Revoke all other sessions after password change (security best practice)
      await AuthService.logoutAll(req.user.id, req.user.tenantId, req.ip);

      await AuditService.log({
        tenantId: req.user.tenantId, userId: req.user.id,
        type: 'auth', severity: 'info', action: 'PASSWORD_CHANGED',
        ipAddress: req.ip,
      });

      res.json({ ok: true, data: { message: 'Password changed. All other sessions have been terminated.' } });
    } catch (err) { next(err); }
  }
);

// ─── LOCKOUT STATUS (debug/support) ──────────────────────────

router.get('/lockout-status',
  async (req, res, next) => {
    try {
      const email = req.query.email;
      if (!email) return res.status(400).json({ ok: false, error: 'email query required' });
      const status = await redis.getLockoutStatus(email.toLowerCase());
      res.json({ ok: true, data: status });
    } catch (err) { next(err); }
  }
);

module.exports = router;
