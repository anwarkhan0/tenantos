'use strict';
const express = require('express');
const Joi     = require('joi');
const router  = express.Router();

const { authenticate, validateBody } = require('../middleware');
const rbac   = require('../services/rbac.service');
const Audit  = require('../services/audit.service');
const Billing = require('../services/billing.service');
const db     = require('../config/database');
const redis  = require('../config/redis');
const { uploadAuditExport } = require('../config/aws');

const {
  mfaRouter, webhookRouter, eventsRouter,
  apiKeyRouter, jobsRouter, statsRouter
} = require('./extended.routes');

// ── AUTH ─────────────────────────────────────────────────────
router.use('/auth/mfa', mfaRouter);
router.use('/auth', require('./auth.routes'));

// ── TENANTS ──────────────────────────────────────────────────
const T = express.Router();

T.get('/', authenticate, rbac.require('tenants','read'), async (req,res,next) => {
  try {
    const {status,plan,search,limit=20,offset=0}=req.query;
    const conds=['t.deleted_at IS NULL']; const params=[]; let i=1;
    if(status){conds.push(`t.status=$${i++}`);params.push(status);}
    if(plan)  {conds.push(`t.plan=$${i++}`);  params.push(plan);}
    if(search){conds.push(`(t.name ILIKE $${i} OR t.slug ILIKE $${i})`);params.push(`%${search}%`);i++;}
    const w=conds.join(' AND ');
    params.push(parseInt(limit));params.push(parseInt(offset));
    const [d,c]=await Promise.all([
      db.query(`SELECT t.*,COUNT(DISTINCT u.id) FILTER(WHERE u.deleted_at IS NULL) as user_count FROM tenants t LEFT JOIN users u ON u.tenant_id=t.id WHERE ${w} GROUP BY t.id ORDER BY t.created_at DESC LIMIT $${i} OFFSET $${i+1}`,params),
      db.query(`SELECT COUNT(*) FROM tenants t WHERE ${w}`,params.slice(0,-2)),
    ]);
    res.json({ok:true,data:{tenants:d.rows,total:parseInt(c.rows[0].count),limit:parseInt(limit),offset:parseInt(offset)}});
  } catch(e){next(e);}
});

T.get('/:id', authenticate, rbac.require('tenants','read'), async(req,res,next)=>{
  try{
    const r=await db.query(`SELECT t.*,COUNT(u.id) FILTER(WHERE u.deleted_at IS NULL) as user_count FROM tenants t LEFT JOIN users u ON u.tenant_id=t.id WHERE t.id=$1 AND t.deleted_at IS NULL GROUP BY t.id`,[req.params.id]);
    if(!r.rows[0])return res.status(404).json({ok:false,error:'Tenant not found'});
    res.json({ok:true,data:{tenant:r.rows[0]}});
  }catch(e){next(e);}
});

T.post('/', authenticate, rbac.require('tenants','create'),
  validateBody(Joi.object({slug:Joi.string().alphanum().min(2).max(64).required(),name:Joi.string().min(2).max(255).required(),plan:Joi.string().valid('trial','pro','enterprise').default('trial'),region:Joi.string().default('us-east-1')})),
  async(req,res,next)=>{
    try{
      const limits=Billing.PLANS[req.body.plan];
      const t=await db.withTransaction(async c=>(await c.query(`INSERT INTO tenants(slug,name,plan,region,db_schema,rate_limit,max_users) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[req.body.slug,req.body.name,req.body.plan,req.body.region,`tenant_${req.body.slug.replace(/-/g,'_')}`,limits.rateLimit,limits.maxUsers])).rows[0]);
      await Audit.log({userId:req.user.id,type:'tenant',severity:'info',action:'TENANT_CREATED',afterData:t,ipAddress:req.ip});
      res.status(201).json({ok:true,data:{tenant:t}});
    }catch(e){
      if(e.code==='23505')return res.status(409).json({ok:false,error:'Slug already exists',code:'SLUG_TAKEN'});
      next(e);
    }
  }
);

T.patch('/:id', authenticate, rbac.require('tenants','update'),
  validateBody(Joi.object({name:Joi.string(),plan:Joi.string().valid('trial','pro','enterprise'),status:Joi.string().valid('active','suspended'),rateLimit:Joi.number().integer()}).min(1)),
  async(req,res,next)=>{
    try{
      const before=await db.query('SELECT * FROM tenants WHERE id=$1',[req.params.id]);
      if(!before.rows[0])return res.status(404).json({ok:false,error:'Tenant not found'});
      const sets=[];const params=[];let i=1;
      if(req.body.name)     {sets.push(`name=$${i++}`);params.push(req.body.name);}
      if(req.body.plan)     {sets.push(`plan=$${i++}`);params.push(req.body.plan);}
      if(req.body.status)   {sets.push(`status=$${i++}`);params.push(req.body.status);}
      if(req.body.rateLimit!==undefined){sets.push(`rate_limit=$${i++}`);params.push(req.body.rateLimit);}
      params.push(req.params.id);
      const r=await db.query(`UPDATE tenants SET ${sets.join(',')} WHERE id=$${i} RETURNING *`,params);
      await redis.deleteTenantCache(req.params.id,'tenant_data');
      await Audit.log({tenantId:req.params.id,userId:req.user.id,type:'tenant',severity:'info',action:'TENANT_UPDATED',beforeData:before.rows[0],afterData:r.rows[0],ipAddress:req.ip});
      res.json({ok:true,data:{tenant:r.rows[0]}});
    }catch(e){next(e);}
  }
);

T.post('/:id/suspend', authenticate, rbac.require('tenants','suspend'), async(req,res,next)=>{
  try{
    const r=await db.query(`UPDATE tenants SET status='suspended' WHERE id=$1 RETURNING *`,[req.params.id]);
    if(!r.rows[0])return res.status(404).json({ok:false,error:'Tenant not found'});
    await redis.deleteTenantCache(req.params.id,'tenant_data');
    await Audit.log({tenantId:req.params.id,userId:req.user.id,type:'tenant',severity:'warning',action:'TENANT_SUSPENDED',ipAddress:req.ip});
    res.json({ok:true,data:{tenant:r.rows[0]}});
  }catch(e){next(e);}
});

T.post('/:id/reactivate', authenticate, rbac.require('tenants','suspend'), async(req,res,next)=>{
  try{
    const r=await db.query(`UPDATE tenants SET status='active' WHERE id=$1 RETURNING *`,[req.params.id]);
    if(!r.rows[0])return res.status(404).json({ok:false,error:'Tenant not found'});
    await redis.deleteTenantCache(req.params.id,'tenant_data');
    await Audit.log({tenantId:req.params.id,userId:req.user.id,type:'tenant',severity:'info',action:'TENANT_REACTIVATED',ipAddress:req.ip});
    res.json({ok:true,data:{tenant:r.rows[0]}});
  }catch(e){next(e);}
});

T.use('/:tenantId', statsRouter);
router.use('/tenants', T);

// ── USERS ────────────────────────────────────────────────────
const U = express.Router();
U.get('/', authenticate, rbac.require('users','read'), async(req,res,next)=>{
  try{
    const tid=req.user.role==='superadmin'?(req.query.tenantId||req.user.tenantId):req.user.tenantId;
    const r=await db.query(`SELECT id,email,first_name,last_name,role,status,email_verified,mfa_enabled,last_login_at,last_login_ip,failed_attempts,created_at FROM users WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC`,[tid]);
    res.json({ok:true,data:{users:r.rows,total:r.rows.length}});
  }catch(e){next(e);}
});
U.patch('/:id/role', authenticate, rbac.require('users','update'),
  validateBody(Joi.object({role:Joi.string().valid('admin','developer','analyst','viewer').required()})),
  async(req,res,next)=>{try{const u=await rbac.changeUserRole(req.params.id,req.body.role,req.user.id,req.user.tenantId);res.json({ok:true,data:{user:u}});}catch(e){next(e);}}
);
U.patch('/:id/status', authenticate, rbac.require('users','update'),
  validateBody(Joi.object({status:Joi.string().valid('active','inactive','locked').required()})),
  async(req,res,next)=>{
    try{
      const r=await db.query(`UPDATE users SET status=$1,updated_at=NOW() WHERE id=$2 AND tenant_id=$3 RETURNING id,email,status`,[req.body.status,req.params.id,req.user.tenantId]);
      if(!r.rows[0])return res.status(404).json({ok:false,error:'User not found'});
      if(req.body.status!=='active')await redis.revokeAllUserSessions(req.params.id);
      await Audit.log({tenantId:req.user.tenantId,userId:req.user.id,type:'user',severity:'warning',action:`USER_${req.body.status.toUpperCase()}`,resourceId:req.params.id,ipAddress:req.ip});
      res.json({ok:true,data:{user:r.rows[0]}});
    }catch(e){next(e);}
  }
);
U.post('/:id/unlock', authenticate, rbac.require('users','update'), async(req,res,next)=>{
  try{
    const r=await db.query(`UPDATE users SET status='active',failed_attempts=0,locked_until=NULL WHERE id=$1 AND tenant_id=$2 RETURNING email`,[req.params.id,req.user.tenantId]);
    if(!r.rows[0])return res.status(404).json({ok:false,error:'User not found'});
    await redis.redis.del(`bf:login:${r.rows[0].email}`);
    await Audit.log({tenantId:req.user.tenantId,userId:req.user.id,type:'user',severity:'info',action:'USER_UNLOCKED',resourceId:req.params.id,ipAddress:req.ip});
    res.json({ok:true,data:{message:'User unlocked'}});
  }catch(e){next(e);}
});
U.delete('/:id', authenticate, rbac.require('users','delete'), async(req,res,next)=>{
  try{
    const r=await db.query(`UPDATE users SET deleted_at=NOW(),status='inactive' WHERE id=$1 AND tenant_id=$2 RETURNING email`,[req.params.id,req.user.tenantId]);
    if(!r.rows[0])return res.status(404).json({ok:false,error:'User not found'});
    await redis.revokeAllUserSessions(req.params.id);
    await Audit.log({tenantId:req.user.tenantId,userId:req.user.id,type:'user',severity:'warning',action:'USER_DELETED',resourceId:req.params.id,ipAddress:req.ip});
    res.json({ok:true,data:{message:'User deleted'}});
  }catch(e){next(e);}
});
router.use('/users', U);

// ── AUDIT ────────────────────────────────────────────────────
const A = express.Router();
A.get('/', authenticate, rbac.require('audit','read'), async(req,res,next)=>{
  try{
    const tid=req.user.role==='superadmin'?req.query.tenantId:req.user.tenantId;
    const r=await Audit.query({tenantId:tid,userId:req.query.userId,type:req.query.type,severity:req.query.severity,action:req.query.action,from:req.query.from,to:req.query.to,limit:parseInt(req.query.limit||'50'),offset:parseInt(req.query.offset||'0')});
    res.json({ok:true,data:r});
  }catch(e){next(e);}
});
A.get('/summary', authenticate, rbac.require('audit','read'), async(req,res,next)=>{
  try{const s=await Audit.getSecuritySummary(req.user.tenantId,parseInt(req.query.days||'7'));res.json({ok:true,data:{summary:s}});}catch(e){next(e);}
});
A.post('/export', authenticate, rbac.require('audit','export'), async(req,res,next)=>{
  try{
    const csv=await Audit.exportToCsv(req.user.tenantId,req.body.from,req.body.to);
    const date=new Date().toISOString().slice(0,10);
    res.setHeader('Content-Type','text/csv');
    res.setHeader('Content-Disposition',`attachment; filename="audit-${date}.csv"`);
    res.send(csv);
  }catch(e){next(e);}
});
router.use('/audit', A);

// ── RBAC ─────────────────────────────────────────────────────
const R = express.Router();
R.get('/permissions', authenticate, async(req,res,next)=>{try{res.json({ok:true,data:{permissions:await rbac.getAllPermissions()}});}catch(e){next(e);}});
R.get('/matrix',      authenticate, async(req,res,next)=>{try{res.json({ok:true,data:{matrix:await rbac.getRoleMatrix()}});}catch(e){next(e);}});
R.get('/check',       authenticate, async(req,res,next)=>{
  try{
    const{resource,action}=req.query;
    if(!resource||!action)return res.status(400).json({ok:false,error:'resource and action required'});
    res.json({ok:true,data:{role:req.user.role,resource,action,allowed:await rbac.can(req.user,resource,action)}});
  }catch(e){next(e);}
});
router.use('/rbac', R);

// ── BILLING ──────────────────────────────────────────────────
const B = express.Router();
B.get('/plans',   (_,res)=>res.json({ok:true,data:{plans:Billing.getAllPlans()}}));
B.get('/summary', authenticate, rbac.require('billing','read'), async(req,res,next)=>{try{res.json({ok:true,data:await Billing.getBillingSummary(req.user.tenantId)});}catch(e){next(e);}});
B.get('/usage',   authenticate, rbac.require('billing','read'), async(req,res,next)=>{try{const u=await Billing.getUsage(req.user.tenantId,parseInt(req.query.days||'30'));res.json({ok:true,data:{usage:u}});}catch(e){next(e);}});
B.get('/quota',   authenticate, async(req,res,next)=>{try{const[u,k,w]=await Promise.all([Billing.checkUserQuota(req.user.tenantId),Billing.checkApiKeyQuota(req.user.tenantId),Billing.checkWebhookQuota(req.user.tenantId)]);res.json({ok:true,data:{quotas:{users:u,apiKeys:k,webhooks:w}}});}catch(e){next(e);}});
B.post('/invoice', authenticate, rbac.require('billing','manage'), async(req,res,next)=>{try{const inv=await Billing.generateInvoice(req.user.tenantId,req.body.month||new Date().toISOString().slice(0,7));res.json({ok:true,data:{invoice:inv}});}catch(e){next(e);}});
router.use('/billing', B);

// ── CACHE ────────────────────────────────────────────────────
const C = express.Router();
C.get('/stats',  authenticate, rbac.require('cache','read'),  async(req,res,next)=>{try{res.json({ok:true,data:{redis:await redis.healthCheck()}});}catch(e){next(e);}});
C.post('/flush', authenticate, rbac.require('cache','flush'), async(req,res,next)=>{try{const n=await redis.flushTenantCache(req.user.tenantId);await Audit.log({tenantId:req.user.tenantId,userId:req.user.id,type:'system',severity:'warning',action:'CACHE_FLUSHED',metadata:{keysDeleted:n},ipAddress:req.ip});res.json({ok:true,data:{flushedKeys:n}});}catch(e){next(e);}});
router.use('/cache', C);

// ── OVERVIEW ─────────────────────────────────────────────────
router.get('/overview', authenticate, async(req,res,next)=>{
  try{
    const Queue=require('../services/queue.service');
    const[tc,sec,cache,qs]=await Promise.all([
      db.query(`SELECT COUNT(*) FILTER(WHERE status='active') as active, COUNT(*) FILTER(WHERE status='suspended') as suspended, COUNT(*) as total FROM tenants WHERE deleted_at IS NULL`),
      Audit.getSecuritySummary(req.user.tenantId,7),
      redis.healthCheck(),
      Queue.getAllQueueStats(),
    ]);
    res.json({ok:true,data:{tenants:tc.rows[0],security:sec,cache,queues:qs,timestamp:new Date().toISOString()}});
  }catch(e){next(e);}
});

// ── EXTENDED ─────────────────────────────────────────────────
router.use('/webhooks', webhookRouter);
router.use('/events',   eventsRouter);
router.use('/api-keys', apiKeyRouter);
router.use('/jobs',     jobsRouter);

module.exports = router;
