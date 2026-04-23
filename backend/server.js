require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = Number.parseInt(process.env.PORT, 10) || 4000;
const SESSION_TTL_DAYS = 30;
const allowedCurrencies = ['USD', 'MXN', 'JPY', 'EUR'];
const DATABASE_URL =
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL ||
  process.env.POSTGRES_PRISMA_URL ||
  process.env.POSTGRESQL_URL ||
  process.env.NEON_DATABASE_URL ||
  '';

app.use(cors());
app.use(express.json());

function readPositiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function shouldUseSsl() {
  if (process.env.PGSSLMODE === 'disable' || process.env.DATABASE_SSL === 'false') {
    return false;
  }

  if (DATABASE_URL.includes('sslmode=disable')) {
    return false;
  }

  return true;
}

if (!DATABASE_URL) {
  console.error('Falta DATABASE_URL para conectar con PostgreSQL.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: readPositiveInt(process.env.PG_MAX_POOL_SIZE, 10),
  idleTimeoutMillis: readPositiveInt(process.env.PG_IDLE_TIMEOUT_MS, 30000),
  connectionTimeoutMillis: readPositiveInt(process.env.PG_CONNECTION_TIMEOUT_MS, 10000),
  ssl: shouldUseSsl() ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err) => {
  console.error('Error inesperado del pool de PostgreSQL.', err);
});

async function query(text, params = []) {
  return pool.query(text, params);
}

async function withTransaction(work) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const passwordHash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { passwordHash, passwordSalt: salt };
}

function verifyPassword(password, user) {
  if (!user || !user.passwordHash) return false;

  if (user.passwordHash.startsWith('$2a$') || user.passwordHash.startsWith('$2b$')) {
    return bcrypt.compareSync(String(password), user.passwordHash);
  }

  if (!user.passwordSalt) return false;

  const { passwordHash } = hashPassword(password, user.passwordSalt);
  return crypto.timingSafeEqual(Buffer.from(passwordHash, 'hex'), Buffer.from(user.passwordHash, 'hex'));
}

function mapUser(row) {
  if (!row) return null;
  return {
    _id: String(row.id),
    name: row.name,
    email: row.email,
    passwordHash: row.password_hash,
    passwordSalt: row.password_salt || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapAccount(row) {
  if (!row) return null;
  return {
    _id: String(row.id),
    userId: String(row.user_id),
    accountNumber: row.account_number,
    ownerName: row.owner_name,
    balance: Number(row.balance),
    currency: row.currency,
    card: {
      cardNumber: row.card_number,
      expMonth: row.card_exp_month,
      expYear: row.card_exp_year,
      cvv: row.card_cvv,
    },
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapTransaction(row) {
  if (!row) return null;
  return {
    _id: String(row.id),
    userId: String(row.user_id),
    accountNumber: row.account_number,
    type: row.type,
    status: row.status,
    amount: Number(row.amount),
    currency: row.currency,
    description: row.description,
    source: row.source,
    transactionId: row.transaction_id,
    balanceAfter: row.balance_after === null ? null : Number(row.balance_after),
    merchantName: row.merchant_name,
    failureReason: row.failure_reason,
    relatedTransactionId: row.related_transaction_id,
    refundTransactionId: row.refund_transaction_id,
    refundedAt: row.refunded_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function publicUser(user) {
  return {
    id: String(user._id),
    name: user.name,
    email: user.email,
    createdAt: user.createdAt,
  };
}

function buildAuthPayload(user, token) {
  return {
    token,
    user: publicUser(user),
  };
}

function buildTransactionId(prefix) {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

function paymentResponse(tx, account, extra = {}) {
  return {
    status: tx.status,
    transactionId: tx.transactionId,
    message: tx.status === 'declined' ? tx.failureReason || 'Pago rechazado.' : 'Operacion exitosa.',
    amount: tx.amount,
    currency: tx.currency,
    description: tx.description,
    accountNumber: account.accountNumber,
    remainingBalance: account.balance,
    balanceAfter: tx.balanceAfter,
    type: tx.type,
    source: tx.source,
    ...extra,
  };
}

function sanitizeAccount(account) {
  return {
    _id: account._id,
    userId: account.userId,
    accountNumber: account.accountNumber,
    ownerName: account.ownerName,
    balance: account.balance,
    currency: account.currency,
    card: account.card,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
  };
}

function generateCardForAccount() {
  const prefix = '411111';
  const random = String(Math.floor(1000000000 + Math.random() * 9000000000));
  const cardNumber = (prefix + random).slice(0, 16);
  const expYearFull = new Date().getFullYear() + 3;
  const expMonth = '12';
  const expYear = String(expYearFull).slice(-2);
  const cvv = String(Math.floor(100 + Math.random() * 900));
  return { cardNumber, expMonth, expYear, cvv };
}

async function createSessionForUser(user) {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);

  await query(
    `
      INSERT INTO sessions (user_id, token_hash, expires_at)
      VALUES ($1, $2, $3)
    `,
    [user._id, hashToken(rawToken), expiresAt]
  );

  return rawToken;
}

async function cleanupExpiredSessions() {
  try {
    await query('DELETE FROM sessions WHERE expires_at <= NOW()');
  } catch (err) {
    console.error('No se pudieron limpiar sesiones expiradas.', err);
  }
}

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const [, token] = header.match(/^Bearer\s+(.+)$/i) || [];

  if (!token) {
    return res.status(401).json({ message: 'Debes iniciar sesion.' });
  }

  try {
    const authResult = await query(
      `
        SELECT
          u.id,
          u.name,
          u.email,
          u.password_hash,
          u.password_salt,
          u.created_at,
          u.updated_at
        FROM sessions s
        INNER JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = $1 AND s.expires_at > NOW()
        LIMIT 1
      `,
      [hashToken(token)]
    );

    if (!authResult.rows.length) {
      return res.status(401).json({ message: 'Sesion invalida o expirada.' });
    }

    req.authUser = mapUser(authResult.rows[0]);
    req.authToken = token;
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo validar la sesion.' });
  }
}

async function generateUniqueAccountNumber() {
  for (let i = 0; i < 10; i += 1) {
    const random = Math.floor(1 + Math.random() * 99999999);
    const accountNumber = `001-${String(random).padStart(8, '0')}`;
    const result = await query(
      'SELECT 1 FROM accounts WHERE account_number = $1 LIMIT 1',
      [accountNumber]
    );
    if (!result.rows.length) return accountNumber;
  }

  throw new Error('No se pudo generar un numero de cuenta unico.');
}

async function generateUniqueCard() {
  for (let i = 0; i < 10; i += 1) {
    const card = generateCardForAccount();
    const result = await query(
      'SELECT 1 FROM accounts WHERE card_number = $1 LIMIT 1',
      [card.cardNumber]
    );
    if (!result.rows.length) return card;
  }

  throw new Error('No se pudo generar una tarjeta unica.');
}

async function registerTransaction(
  {
    userId,
    accountNumber,
    type,
    status = 'approved',
    amount,
    currency,
    description,
    source,
    transactionId,
    balanceAfter,
    merchantName,
    failureReason,
    relatedTransactionId,
    refundTransactionId,
    refundedAt,
  },
  client = pool
) {
  try {
    const result = await client.query(
      `
        INSERT INTO transactions (
          user_id,
          account_number,
          type,
          status,
          amount,
          currency,
          description,
          source,
          transaction_id,
          balance_after,
          merchant_name,
          failure_reason,
          related_transaction_id,
          refund_transaction_id,
          refunded_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        RETURNING *
      `,
      [
        userId,
        accountNumber,
        type,
        status,
        amount,
        currency,
        description || null,
        source || null,
        transactionId,
        balanceAfter === undefined ? null : balanceAfter,
        merchantName || null,
        failureReason || null,
        relatedTransactionId || null,
        refundTransactionId || null,
        refundedAt || null,
      ]
    );

    return mapTransaction(result.rows[0]);
  } catch (err) {
    console.error('No se pudo registrar la transaccion.', err);
    throw err;
  }
}

async function findUserByEmail(email) {
  const result = await query(
    `
      SELECT id, name, email, password_hash, password_salt, created_at, updated_at
      FROM users
      WHERE email = $1
      LIMIT 1
    `,
    [email]
  );
  return mapUser(result.rows[0]);
}

async function findOwnedAccount(userId, accountNumber, client = pool) {
  const result = await client.query(
    `
      SELECT *
      FROM accounts
      WHERE user_id = $1 AND account_number = $2
      LIMIT 1
    `,
    [userId, String(accountNumber)]
  );

  return mapAccount(result.rows[0]);
}

async function findOwnedAccountForUpdate(userId, accountNumber, client) {
  const result = await client.query(
    `
      SELECT *
      FROM accounts
      WHERE user_id = $1 AND account_number = $2
      FOR UPDATE
    `,
    [userId, String(accountNumber)]
  );

  return mapAccount(result.rows[0]);
}

async function updateAccount(account, client) {
  const result = await client.query(
    `
      UPDATE accounts
      SET owner_name = $2,
          balance = $3,
          currency = $4,
          card_number = $5,
          card_exp_month = $6,
          card_exp_year = $7,
          card_cvv = $8,
          updated_at = NOW()
      WHERE id = $1
      RETURNING *
    `,
    [
      account._id,
      account.ownerName,
      account.balance,
      account.currency,
      account.card.cardNumber,
      account.card.expMonth,
      account.card.expYear,
      account.card.cvv,
    ]
  );

  return mapAccount(result.rows[0]);
}

async function initDb() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      account_number TEXT NOT NULL UNIQUE,
      owner_name TEXT NOT NULL,
      balance NUMERIC(18, 2) NOT NULL,
      currency TEXT NOT NULL,
      card_number TEXT NOT NULL UNIQUE,
      card_exp_month TEXT NOT NULL,
      card_exp_year TEXT NOT NULL,
      card_cvv TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      account_number TEXT NOT NULL,
      type TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'approved',
      amount NUMERIC(18, 2) NOT NULL,
      currency TEXT NOT NULL,
      description TEXT,
      source TEXT,
      transaction_id TEXT NOT NULL UNIQUE,
      balance_after NUMERIC(18, 2),
      merchant_name TEXT,
      failure_reason TEXT,
      related_transaction_id TEXT,
      refund_transaction_id TEXT,
      refunded_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(
    'CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)'
  );
  await query(
    'CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)'
  );
  await query(
    'CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts (user_id)'
  );
  await query(
    'CREATE INDEX IF NOT EXISTS idx_transactions_user_account_created ON transactions (user_id, account_number, created_at DESC)'
  );
}

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  const normalizedEmail = normalizeEmail(email);
  const finalName = String(name || '').trim();

  if (!finalName || !normalizedEmail || !String(password || '').trim()) {
    return res.status(400).json({ message: 'Nombre, email y password son obligatorios.' });
  }

  if (String(password).length < 6) {
    return res.status(400).json({ message: 'La password debe tener al menos 6 caracteres.' });
  }

  try {
    const existingUser = await findUserByEmail(normalizedEmail);
    if (existingUser) {
      return res.status(409).json({ message: 'Ya existe una cuenta con ese email.' });
    }

    const passwordHash = bcrypt.hashSync(String(password), 10);
    const result = await query(
      `
        INSERT INTO users (name, email, password_hash, password_salt)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, email, password_hash, password_salt, created_at, updated_at
      `,
      [finalName, normalizedEmail, passwordHash, '']
    );

    const user = mapUser(result.rows[0]);
    const token = await createSessionForUser(user);
    res.status(201).json(buildAuthPayload(user, token));
  } catch (err) {
    console.error(err);
    if (err && err.code === '23505') {
      return res.status(409).json({ message: 'Ya existe una cuenta con ese email.' });
    }
    res.status(500).json({ message: 'No se pudo registrar el usuario.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail || !String(password || '').trim()) {
    return res.status(400).json({ message: 'Email y password son obligatorios.' });
  }

  try {
    await cleanupExpiredSessions();
    const user = await findUserByEmail(normalizedEmail);

    if (!user || !verifyPassword(password, user)) {
      return res.status(401).json({ message: 'Credenciales invalidas.' });
    }

    const token = await createSessionForUser(user);
    res.json(buildAuthPayload(user, token));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo iniciar sesion.' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  res.json({ user: publicUser(req.authUser) });
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  try {
    await query('DELETE FROM sessions WHERE token_hash = $1', [hashToken(req.authToken)]);
    res.json({ message: 'Sesion cerrada.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo cerrar sesion.' });
  }
});

app.post('/api/accounts', authMiddleware, async (req, res) => {
  const { ownerName, currency, initialBalance } = req.body || {};
  const normalizedCurrency = allowedCurrencies.includes(currency) ? currency : 'USD';
  const balance =
    typeof initialBalance === 'number' && initialBalance >= 0 ? initialBalance : 10000;
  const finalOwnerName =
    ownerName && String(ownerName).trim() ? String(ownerName).trim() : req.authUser.name;

  try {
    const accountNumber = await generateUniqueAccountNumber();
    const card = await generateUniqueCard();

    const created = await withTransaction(async (client) => {
      const accountResult = await client.query(
        `
          INSERT INTO accounts (
            user_id,
            account_number,
            owner_name,
            balance,
            currency,
            card_number,
            card_exp_month,
            card_exp_year,
            card_cvv
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
          RETURNING *
        `,
        [
          req.authUser._id,
          accountNumber,
          finalOwnerName,
          balance,
          normalizedCurrency,
          card.cardNumber,
          card.expMonth,
          card.expYear,
          card.cvv,
        ]
      );

      const account = mapAccount(accountResult.rows[0]);

      await registerTransaction(
        {
          userId: req.authUser._id,
          accountNumber: account.accountNumber,
          type: 'credit',
          status: 'approved',
          amount: balance,
          currency: normalizedCurrency,
          description: 'Saldo inicial de la cuenta',
          source: 'manual_topup',
          transactionId: buildTransactionId('POVY-OPEN'),
          balanceAfter: account.balance,
          merchantName: 'Povy Sandbox',
        },
        client
      );

      return account;
    });

    res.status(201).json(sanitizeAccount(created));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo crear la cuenta.' });
  }
});

app.get('/api/accounts', authMiddleware, async (req, res) => {
  try {
    const result = await query(
      `
        SELECT *
        FROM accounts
        WHERE user_id = $1
        ORDER BY created_at DESC
      `,
      [req.authUser._id]
    );

    res.json(result.rows.map((row) => sanitizeAccount(mapAccount(row))));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudieron obtener las cuentas.' });
  }
});

app.get('/api/accounts/:accountNumber', authMiddleware, async (req, res) => {
  try {
    const account = await findOwnedAccount(req.authUser._id, req.params.accountNumber);
    if (!account) {
      return res.status(404).json({ message: 'Cuenta no encontrada.' });
    }

    res.json(sanitizeAccount(account));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo obtener la cuenta.' });
  }
});

app.get('/api/accounts/:accountNumber/transactions', authMiddleware, async (req, res) => {
  try {
    const account = await findOwnedAccount(req.authUser._id, req.params.accountNumber);
    if (!account) {
      return res.status(404).json({ message: 'Cuenta no encontrada.' });
    }

    const result = await query(
      `
        SELECT *
        FROM transactions
        WHERE user_id = $1 AND account_number = $2
        ORDER BY created_at DESC
        LIMIT 100
      `,
      [req.authUser._id, String(req.params.accountNumber)]
    );

    res.json(result.rows.map(mapTransaction));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo obtener el historial de transacciones.' });
  }
});

app.patch('/api/accounts/:accountNumber', authMiddleware, async (req, res) => {
  const { currency, balance, addBalance } = req.body || {};

  try {
    const updatedAccount = await withTransaction(async (client) => {
      const account = await findOwnedAccountForUpdate(
        req.authUser._id,
        req.params.accountNumber,
        client
      );

      if (!account) {
        return null;
      }

      if (currency) {
        if (!allowedCurrencies.includes(currency)) {
          const error = new Error('Moneda no soportada. Usa USD, MXN, JPY o EUR.');
          error.statusCode = 400;
          throw error;
        }
        account.currency = currency;
      }

      if (balance !== undefined && addBalance !== undefined) {
        const error = new Error('Usa "balance" (establecer) o "addBalance" (sumar), no ambos.');
        error.statusCode = 400;
        throw error;
      }

      if (balance !== undefined) {
        const numericBalance = Number(balance);
        if (!Number.isFinite(numericBalance) || numericBalance < 0) {
          const error = new Error('Saldo invalido.');
          error.statusCode = 400;
          throw error;
        }

        account.balance = numericBalance;
        const saved = await updateAccount(account, client);

        await registerTransaction(
          {
            userId: req.authUser._id,
            accountNumber: saved.accountNumber,
            type: 'credit',
            status: 'approved',
            amount: numericBalance,
            currency: saved.currency,
            description: 'Saldo establecido manualmente',
            source: 'balance_set',
            transactionId: buildTransactionId('POVY-BAL'),
            balanceAfter: saved.balance,
            merchantName: 'Povy Sandbox',
          },
          client
        );

        return saved;
      }

      if (addBalance !== undefined) {
        const numericAdd = Number(addBalance);
        if (!Number.isFinite(numericAdd)) {
          const error = new Error('Monto invalido.');
          error.statusCode = 400;
          throw error;
        }

        const nextBalance = account.balance + numericAdd;
        if (nextBalance < 0) {
          const error = new Error('El ajuste dejaria el saldo negativo.');
          error.statusCode = 400;
          throw error;
        }

        account.balance = nextBalance;
        const saved = await updateAccount(account, client);

        await registerTransaction(
          {
            userId: req.authUser._id,
            accountNumber: saved.accountNumber,
            type: numericAdd >= 0 ? 'credit' : 'debit',
            status: 'approved',
            amount: Math.abs(numericAdd),
            currency: saved.currency,
            description: numericAdd >= 0 ? 'Recarga manual de saldo' : 'Descuento manual de saldo',
            source: 'manual_topup',
            transactionId: buildTransactionId('POVY-TOPUP'),
            balanceAfter: saved.balance,
            merchantName: 'Povy Sandbox',
          },
          client
        );

        return saved;
      }

      return updateAccount(account, client);
    });

    if (!updatedAccount) {
      return res.status(404).json({ message: 'Cuenta no encontrada.' });
    }

    res.json(sanitizeAccount(updatedAccount));
  } catch (err) {
    console.error(err);
    res.status(err.statusCode || 500).json({ message: err.message || 'No se pudo actualizar la cuenta.' });
  }
});

app.delete('/api/accounts/:accountNumber', authMiddleware, async (req, res) => {
  try {
    const result = await query(
      `
        DELETE FROM accounts
        WHERE user_id = $1 AND account_number = $2
        RETURNING account_number
      `,
      [req.authUser._id, String(req.params.accountNumber)]
    );

    if (!result.rows.length) {
      return res.status(404).json({ message: 'Cuenta no encontrada.' });
    }

    res.json({
      message: 'Cuenta eliminada correctamente.',
      accountNumber: result.rows[0].account_number,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo eliminar la cuenta.' });
  }
});

app.post('/api/payments', async (req, res) => {
  const { amount, currency, description, merchantName } = req.body || {};

  if (amount === undefined || amount === null) {
    return res.status(400).json({
      status: 'error',
      message: 'Falta el dato obligatorio: amount.',
    });
  }

  try {
    const numericAmount = Number(amount);
    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ status: 'error', message: 'Monto invalido.' });
    }

    res.json({
      status: 'approved',
      transactionId: buildTransactionId('POVY'),
      message: 'Pago simulado correctamente.',
      amount: numericAmount,
      currency: allowedCurrencies.includes(currency) ? currency : 'USD',
      description: description || 'Pago de prueba',
      merchantName: merchantName || 'Povy Test',
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: 'Error interno al procesar el pago.' });
  }
});

app.post('/api/payments/card', async (req, res) => {
  const { cardNumber, expMonth, expYear, cvv, amount, currency, description, merchantName } =
    req.body || {};

  if (!cardNumber || !expMonth || !expYear || !cvv || amount === undefined || amount === null) {
    return res.status(400).json({
      status: 'error',
      message: 'Faltan datos obligatorios para el pago con tarjeta.',
    });
  }

  try {
    const responsePayload = await withTransaction(async (client) => {
      const cleanCardNumber = String(cardNumber).replace(/\s+/g, '');
      const accountResult = await client.query(
        `
          SELECT *
          FROM accounts
          WHERE card_number = $1
          FOR UPDATE
        `,
        [cleanCardNumber]
      );

      const account = mapAccount(accountResult.rows[0]);
      if (!account) {
        const error = new Error('Tarjeta no encontrada.');
        error.statusCode = 404;
        error.responseBody = { status: 'error', message: error.message };
        throw error;
      }

      if (
        account.card.expMonth !== String(expMonth) ||
        account.card.expYear !== String(expYear) ||
        account.card.cvv !== String(cvv)
      ) {
        const error = new Error('Datos de tarjeta invalidos.');
        error.statusCode = 400;
        error.responseBody = { status: 'error', message: error.message };
        throw error;
      }

      const numericAmount = Number(amount);
      if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
        const error = new Error('Monto invalido.');
        error.statusCode = 400;
        error.responseBody = { status: 'error', message: error.message };
        throw error;
      }

      const finalCurrency = allowedCurrencies.includes(currency) ? currency : account.currency;
      const approved = numericAmount <= account.balance;

      if (approved) {
        account.balance -= numericAmount;
        await updateAccount(account, client);
      }

      const tx = await registerTransaction(
        {
          userId: account.userId,
          accountNumber: account.accountNumber,
          type: 'debit',
          status: approved ? 'approved' : 'declined',
          amount: numericAmount,
          currency: finalCurrency,
          description: description || 'Pago de prueba con tarjeta',
          source: 'card_payment',
          transactionId: buildTransactionId('POVY-CARD'),
          balanceAfter: account.balance,
          merchantName: merchantName || 'Povy Test',
          failureReason: approved ? undefined : 'Fondos insuficientes en la cuenta.',
        },
        client
      );

      return paymentResponse(tx, account, {
        cardLast4: account.card.cardNumber.slice(-4),
        message: approved ? 'Pago aprobado.' : 'Fondos insuficientes en la cuenta.',
      });
    });

    res.json(responsePayload);
  } catch (err) {
    console.error(err);
    res.status(err.statusCode || 500).json(
      err.responseBody || {
        status: 'error',
        message: 'Error interno al procesar el pago con tarjeta.',
      }
    );
  }
});

app.post('/api/payments/:transactionId/refund', authMiddleware, async (req, res) => {
  const { amount, description } = req.body || {};

  try {
    const refundResponse = await withTransaction(async (client) => {
      const originalResult = await client.query(
        `
          SELECT *
          FROM transactions
          WHERE user_id = $1 AND transaction_id = $2
          FOR UPDATE
        `,
        [req.authUser._id, String(req.params.transactionId)]
      );

      const original = mapTransaction(originalResult.rows[0]);
      if (!original) {
        const error = new Error('Transaccion no encontrada.');
        error.statusCode = 404;
        throw error;
      }

      if (!['account_payment', 'card_payment'].includes(original.source)) {
        const error = new Error('Solo se pueden devolver pagos.');
        error.statusCode = 400;
        throw error;
      }

      if (original.status !== 'approved') {
        const error = new Error('Solo se pueden devolver pagos aprobados.');
        error.statusCode = 400;
        throw error;
      }

      if (original.refundTransactionId) {
        const error = new Error('La transaccion ya fue devuelta.');
        error.statusCode = 400;
        throw error;
      }

      const account = await findOwnedAccountForUpdate(req.authUser._id, original.accountNumber, client);
      if (!account) {
        const error = new Error('Cuenta no encontrada para la devolucion.');
        error.statusCode = 404;
        throw error;
      }

      const requestedAmount =
        amount === undefined || amount === null ? original.amount : Number(amount);
      if (!Number.isFinite(requestedAmount) || requestedAmount <= 0) {
        const error = new Error('Monto de devolucion invalido.');
        error.statusCode = 400;
        throw error;
      }

      if (requestedAmount > original.amount) {
        const error = new Error('La devolucion no puede superar el pago original.');
        error.statusCode = 400;
        throw error;
      }

      account.balance += requestedAmount;
      const savedAccount = await updateAccount(account, client);

      const refundTx = await registerTransaction(
        {
          userId: req.authUser._id,
          accountNumber: savedAccount.accountNumber,
          type: 'credit',
          status: 'approved',
          amount: requestedAmount,
          currency: original.currency,
          description: description || `Devolucion de ${original.transactionId}`,
          source: 'refund',
          transactionId: buildTransactionId('POVY-RFD'),
          balanceAfter: savedAccount.balance,
          merchantName: original.merchantName || 'Povy Test',
          relatedTransactionId: original.transactionId,
        },
        client
      );

      await client.query(
        `
          UPDATE transactions
          SET status = 'refunded',
              refund_transaction_id = $2,
              refunded_at = NOW(),
              updated_at = NOW()
          WHERE id = $1
        `,
        [original._id, refundTx.transactionId]
      );

      return {
        message: 'Devolucion aplicada correctamente.',
        transactionId: refundTx.transactionId,
        relatedTransactionId: original.transactionId,
        accountNumber: savedAccount.accountNumber,
        amount: refundTx.amount,
        currency: refundTx.currency,
        remainingBalance: savedAccount.balance,
      };
    });

    res.json(refundResponse);
  } catch (err) {
    console.error(err);
    res.status(err.statusCode || 500).json({ message: err.message || 'No se pudo procesar la devolucion.' });
  }
});

app.get('/api', (req, res) => {
  res.json({
    message: 'Povy API operativa (sandbox)',
    currencies: allowedCurrencies,
    auth: ['/api/auth/register', '/api/auth/login', '/api/auth/me', '/api/auth/logout'],
    accounts: ['/api/accounts', '/api/accounts/:accountNumber', '/api/accounts/:accountNumber/transactions'],
    payments: ['/api/payments', '/api/payments/card', '/api/payments/:transactionId/refund'],
  });
});

app.get('/', (req, res) => {
  res.json({ message: 'Povy API operativa (sandbox)' });
});

async function start() {
  await initDb();
  console.log('Conectado a PostgreSQL y esquema listo.');
  app.listen(PORT, () => {
    console.log(`Povy backend sandbox corriendo en http://localhost:${PORT}`);
  });
}

start().catch((err) => {
  console.error('No se pudo iniciar el backend con PostgreSQL.', err);
  process.exit(1);
});
