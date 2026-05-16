/**
 * 示例 Express.js 路由文件（含各类代码异味）
 * 文件用途：用户管理路由（故意包含巨型函数、重复代码、硬编码配置、缺少错误处理、类型不安全等问题）
 * 警告：本文件仅用于重构演示，不包含真实业务逻辑
 */

import express, { Request, Response, NextFunction } from 'express';
import { Pool } from 'mysql2/promise';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import axios from 'axios';

const router = express.Router();

// ========== 硬编码配置（问题：配置未外部化） ==========
const JWT_SECRET = 'my-super-secret-key-123456';
const DB_HOST = 'localhost';
const DB_PORT = 3306;
const DB_USER = 'admin';
const DB_PASS = 'password123';
const DB_NAME = 'user_db';
const API_BASE_URL = 'https://api.example.com';
const SALT_ROUNDS = 10;
const PAGE_SIZE = 20;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000;

// ========== 数据库池（问题：未做类型封装） ==========
const pool = new Pool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASS,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

// ========== 巨型函数（问题：超过100行，职责过多） ==========
// eslint-disable-next-line @typescript-eslint/no-explicit-any
router.post('/api/users/register', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, name, phone, age, city, country } = req.body;

    // 参数校验（内联，未提取）
    if (!email || !password || !name) {
      res.status(400).json({ error: 'Missing required fields' });
      return;
    }
    if (password.length < 8) {
      res.status(400).json({ error: 'Password too short' });
      return;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      res.status(400).json({ error: 'Invalid email format' });
      return;
    }
    if (age && (isNaN(Number(age)) || Number(age) < 0 || Number(age) > 150)) {
      res.status(400).json({ error: 'Invalid age' });
      return;
    }

    // 检查用户是否已存在（重复代码：类似逻辑在登录中也出现）
    const [existingRows]: any = await pool.query(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    if ((existingRows as any[]).length > 0) {
      res.status(409).json({ error: 'Email already registered' });
      return;
    }

    // 哈希密码
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // 创建用户（巨型 SQL，未提取）
    const [result]: any = await pool.query(
      `INSERT INTO users (email, password, name, phone, age, city, country, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [email, hashedPassword, name, phone || null, age || null, city || null, country || null]
    );

    const userId = (result as any).insertId;

    // 生成 JWT（重复代码：登录接口也生成 JWT）
    const token = jwt.sign(
      { userId, email, role: 'user' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // 发送欢迎邮件（直接内联 axios 调用，未提取）
    try {
      await axios.post(`${API_BASE_URL}/send-email`, {
        to: email,
        subject: 'Welcome!',
        body: `Hello ${name}, welcome to our platform!`
      });
    } catch (emailErr) {
      console.log('Email send failed:', emailErr);
      // 问题：邮件发送失败仅 console.log，不影响注册流程，但未通知用户
    }

    // 记录审计日志（重复代码：多处出现类似日志逻辑）
    await pool.query(
      'INSERT INTO audit_logs (user_id, action, details, ip, created_at) VALUES (?, ?, ?, ?, NOW())',
      [userId, 'REGISTER', JSON.stringify({ email, name }), req.ip]
    );

    // 设置缓存（内联逻辑）
    const redis = req.app.get('redis');
    if (redis) {
      await redis.set(`user:${userId}`, JSON.stringify({ id: userId, email, name }), 'EX', 3600);
    }

    // 返回结果（巨型响应对象）
    res.status(201).json({
      success: true,
      data: {
        user: {
          id: userId,
          email,
          name,
          phone: phone || null,
          age: age || null,
          city: city || null,
          country: country || null,
        },
        token,
        expiresIn: 7 * 24 * 3600,
      },
      message: 'Registration successful',
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    // 问题：全局 catch 过于宽泛，未区分错误类型
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== 登录接口（重复代码多，类型不安全） ==========
// eslint-disable-next-line @typescript-eslint/no-explicit-any
router.post('/api/users/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({ error: 'Missing email or password' });
      return;
    }

    // 重复：邮箱格式校验（与注册接口重复）
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      res.status(400).json({ error: 'Invalid email format' });
      return;
    }

    // 查询用户（类型不安全：使用 any）
    const [rows]: any = await pool.query(
      'SELECT id, email, password, name, role, login_attempts, locked_until FROM users WHERE email = ?',
      [email]
    );

    if ((rows as any[]).length === 0) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const user = (rows as any[])[0];

    // 账户锁定检查
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      res.status(403).json({ error: 'Account locked, try again later' });
      return;
    }

    // 密码校验
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      // 更新登录失败次数（重复代码：审计日志）
      const attempts = (user.login_attempts || 0) + 1;
      const lockedUntil = attempts >= MAX_LOGIN_ATTEMPTS ? new Date(Date.now() + LOCK_TIME) : null;
      await pool.query(
        'UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?',
        [attempts, lockedUntil, user.id]
      );
      // 重复：审计日志
      await pool.query(
        'INSERT INTO audit_logs (user_id, action, details, ip, created_at) VALUES (?, ?, ?, ?, NOW())',
        [user.id, 'LOGIN_FAILED', JSON.stringify({ email }), req.ip]
      );
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // 重置登录次数
    await pool.query(
      'UPDATE users SET login_attempts = 0, last_login_at = NOW() WHERE id = ?',
      [user.id]
    );

    // 重复：生成 JWT（与注册接口完全相同逻辑）
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // 重复：审计日志
    await pool.query(
      'INSERT INTO audit_logs (user_id, action, details, ip, created_at) VALUES (?, ?, ?, ?, NOW())',
      [user.id, 'LOGIN_SUCCESS', JSON.stringify({ email }), req.ip]
    );

    // 重复：设置缓存
    const redis = req.app.get('redis');
    if (redis) {
      await redis.set(`user:${user.id}`, JSON.stringify({ id: user.id, email: user.email, name: user.name }), 'EX', 3600);
    }

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
        token,
        expiresIn: 7 * 24 * 3600,
      },
      message: 'Login successful',
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== 获取用户列表（类型不安全、无分页校验） ==========
// eslint-disable-next-line @typescript-eslint/no-explicit-any
router.get('/api/users', async (req: Request, res: Response): Promise<void> => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const pageSize = parseInt(req.query.pageSize as string) || PAGE_SIZE;
    const search = req.query.search as string || '';
    const role = req.query.role as string || '';
    const sortBy = req.query.sortBy as string || 'created_at';
    const sortOrder = (req.query.sortOrder as string)?.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

    // 问题：SQL 拼接，虽有参数化但排序字段未校验（潜在注入点）
    const allowedSortFields = ['created_at', 'name', 'email', 'id'];
    const actualSortBy = allowedSortFields.includes(sortBy) ? sortBy : 'created_at';

    let whereClause = 'WHERE 1=1';
    const queryParams: any[] = [];

    if (search) {
      whereClause += ' AND (name LIKE ? OR email LIKE ?)';
      queryParams.push(`%${search}%`, `%${search}%`);
    }
    if (role) {
      whereClause += ' AND role = ?';
      queryParams.push(role);
    }

    // 查询总数
    const [countRows]: any = await pool.query(
      `SELECT COUNT(*) as total FROM users ${whereClause}`,
      queryParams
    );
    const total = (countRows as any[])[0].total;

    // 查询数据（重复代码：分页逻辑在多处出现）
    const offset = (page - 1) * pageSize;
    queryParams.push(pageSize, offset);
    const [userRows]: any = await pool.query(
      `SELECT id, email, name, phone, age, city, country, role, created_at
       FROM users ${whereClause}
       ORDER BY ${actualSortBy} ${sortOrder}
       LIMIT ? OFFSET ?`,
      queryParams
    );

    // 问题：直接返回数据库原始数据，未做字段过滤
    res.json({
      success: true,
      data: {
        users: userRows,
        pagination: {
          page,
          pageSize,
          total,
          totalPages: Math.ceil(total / pageSize),
        },
      },
    });
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== 获取单个用户（类型不安全、无错误处理细化） ==========
// eslint-disable-next-line @typescript-eslint/no-explicit-any
router.get('/api/users/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.params.id;

    // 问题：未校验 id 是否为有效数字
    const [rows]: any = await pool.query(
      'SELECT id, email, name, phone, age, city, country, role, created_at, updated_at FROM users WHERE id = ?',
      [userId]
    );

    if ((rows as any[]).length === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    const user = (rows as any[])[0];

    // 重复：审计日志
    await pool.query(
      'INSERT INTO audit_logs (user_id, action, details, ip, created_at) VALUES (?, ?, ?, ?, NOW())',
      [userId, 'VIEW_USER', JSON.stringify({ viewedUserId: userId }), req.ip]
    );

    res.json({
      success: true,
      data: { user },
    });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== 更新用户（巨型函数、重复代码） ==========
// eslint-disable-next-line @typescript-eslint/no-explicit-any
router.put('/api/users/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.params.id;
    const { name, phone, age, city, country, email } = req.body;
    const requesterId = (req as any).user?.userId; // 问题：类型不安全，依赖中间件注入但未定义类型

    // 权限检查（内联，未提取）
    if (requesterId !== userId && (req as any).user?.role !== 'admin') {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    // 重复：邮箱格式校验
    if (email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        res.status(400).json({ error: 'Invalid email format' });
        return;
      }
      // 重复：检查邮箱是否被占用
      const [existingRows]: any = await pool.query(
        'SELECT id FROM users WHERE email = ? AND id != ?',
        [email, userId]
      );
      if ((existingRows as any[]).length > 0) {
        res.status(409).json({ error: 'Email already in use' });
        return;
      }
    }

    // 动态构建更新语句（类型不安全：any）
    const updates: string[] = [];
    const params: any[] = [];

    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (phone !== undefined) { updates.push('phone = ?'); params.push(phone); }
    if (age !== undefined) {
      if (isNaN(Number(age)) || Number(age) < 0 || Number(age) > 150) {
        res.status(400).json({ error: 'Invalid age' });
        return;
      }
      updates.push('age = ?'); params.push(Number(age));
    }
    if (city !== undefined) { updates.push('city = ?'); params.push(city); }
    if (country !== undefined) { updates.push('country = ?'); params.push(country); }
    if (email !== undefined) { updates.push('email = ?'); params.push(email); }

    if (updates.length === 0) {
      res.status(400).json({ error: 'No fields to update' });
      return;
    }

    updates.push('updated_at = NOW()');
    params.push(userId);

    await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
      params
    );

    // 重复：审计日志
    await pool.query(
      'INSERT INTO audit_logs (user_id, action, details, ip, created_at) VALUES (?, ?, ?, ?, NOW())',
      [requesterId, 'UPDATE_USER', JSON.stringify({ updatedUserId: userId, fields: updates }), req.ip]
    );

    // 重复：更新缓存
    const redis = req.app.get('redis');
    if (redis) {
      const [updatedRows]: any = await pool.query('SELECT id, email, name FROM users WHERE id = ?', [userId]);
      if ((updatedRows as any[]).length > 0) {
        await redis.set(`user:${userId}`, JSON.stringify((updatedRows as any[])[0]), 'EX', 3600);
      }
    }

    res.json({
      success: true,
      message: 'User updated successfully',
    });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== 删除用户（类型不安全、无事务保护） ==========
// eslint-disable-next-line @typescript-eslint/no-explicit-any
router.delete('/api/users/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.params.id;
    const requesterId = (req as any).user?.userId;
    const requesterRole = (req as any).user?.role;

    if (!requesterId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    if (requesterId !== userId && requesterRole !== 'admin') {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    // 问题：未使用事务，删除用户和审计日志可能不一致
    const [rows]: any = await pool.query('SELECT id FROM users WHERE id = ?', [userId]);
    if ((rows as any[]).length === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    await pool.query('DELETE FROM users WHERE id = ?', [userId]);

    // 重复：审计日志
    await pool.query(
      'INSERT INTO audit_logs (user_id, action, details, ip, created_at) VALUES (?, ?, ?, ?, NOW())',
      [requesterId, 'DELETE_USER', JSON.stringify({ deletedUserId: userId }), req.ip]
    );

    // 重复：清除缓存
    const redis = req.app.get('redis');
    if (redis) {
      await redis.del(`user:${userId}`);
    }

    res.json({
      success: true,
      message: 'User deleted successfully',
    });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== 第三方 API 代理（硬编码 URL、无超时配置、无错误处理） ==========
// eslint-disable-next-line @typescript-eslint/no-explicit-any
router.get('/api/external/profile', async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.query.userId as string;
    if (!userId) {
      res.status(400).json({ error: 'Missing userId parameter' });
      return;
    }

    // 问题：硬编码 URL，无超时，无重试
    const response = await axios.get(`${API_BASE_URL}/users/${userId}/profile`);

    // 问题：直接透传第三方响应，未做数据清洗
    res.json({
      success: true,
      data: response.data,
    });
  } catch (err: any) {
    // 问题：catch 中未区分错误类型，直接返回 500
    console.error('External API error:', err.message);
    res.status(500).json({ error: 'Failed to fetch external profile' });
  }
});

export default router;
