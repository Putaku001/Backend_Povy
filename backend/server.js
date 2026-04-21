require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI;
const SESSION_TTL_DAYS = 30;
const allowedCurrencies = ['USD', 'MXN', 'JPY', 'EUR'];

app.use(cors());
app.use(express.json());

if (!MONGODB_URI) {
  console.error(
    'Falta la variable de entorno MONGODB_URI con la cadena de conexion de MongoDB.'
  );
} else {
  mongoose
    .connect(MONGODB_URI, { dbName: 'povy_sandbox' })
    .then(() => {
      console.log('Conectado a MongoDB (Povy sandbox)');
    })
    .catch((err) => {
      console.error('Error al conectar con MongoDB.', err);
    });
}

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, index: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    passwordSalt: { type: String, required: true },
  },
  { timestamps: true }
);

const sessionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    tokenHash: { type: String, required: true, unique: true, index: true },
    expiresAt: { type: Date, required: true, index: true },
  },
  { timestamps: true }
);

const accountSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    accountNumber: { type: String, unique: true, index: true },
    ownerName: { type: String, required: true },
    balance: { type: Number, required: true },
    currency: { type: String, required: true, enum: allowedCurrencies },
    card: {
      cardNumber: String,
      expMonth: String,
      expYear: String,
      cvv: String,
    },
  },
  { timestamps: true }
);

const transactionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    accountNumber: { type: String, index: true },
    type: { type: String, enum: ['debit', 'credit'], required: true },
    status: { type: String, enum: ['approved', 'declined', 'refunded'], default: 'approved' },
    amount: { type: Number, required: true },
    currency: { type: String, required: true },
    description: { type: String },
    source: { type: String }, // account_payment, card_payment, manual_topup, balance_set, refund
    transactionId: { type: String, required: true, unique: true, index: true },
    balanceAfter: { type: Number },
    merchantName: { type: String },
    failureReason: { type: String },
    relatedTransactionId: { type: String },
    refundTransactionId: { type: String },
    refundedAt: { type: Date },
  },
  { timestamps: true }
);

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Session = mongoose.models.Session || mongoose.model('Session', sessionSchema);
const Account = mongoose.models.Account || mongoose.model('Account', accountSchema);
const Transaction =
  mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);

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
  const { passwordHash } = hashPassword(password, user.passwordSalt);
  return crypto.timingSafeEqual(Buffer.from(passwordHash, 'hex'), Buffer.from(user.passwordHash, 'hex'));
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

async function createSessionForUser(user) {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);

  await Session.create({
    userId: user._id,
    tokenHash: hashToken(rawToken),
    expiresAt,
  });

  return rawToken;
}

async function cleanupExpiredSessions() {
  try {
    await Session.deleteMany({ expiresAt: { $lte: new Date() } });
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
    const session = await Session.findOne({
      tokenHash: hashToken(token),
      expiresAt: { $gt: new Date() },
    }).lean();

    if (!session) {
      return res.status(401).json({ message: 'Sesion invalida o expirada.' });
    }

    const user = await User.findById(session.userId);
    if (!user) {
      return res.status(401).json({ message: 'Usuario no encontrado.' });
    }

    req.authUser = user;
    req.authToken = token;
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo validar la sesion.' });
  }
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

async function generateUniqueAccountNumber() {
  for (let i = 0; i < 10; i += 1) {
    const random = Math.floor(1 + Math.random() * 99999999);
    const accountNumber = `001-${String(random).padStart(8, '0')}`;
    const exists = await Account.exists({ accountNumber });
    if (!exists) return accountNumber;
  }
  throw new Error('No se pudo generar un numero de cuenta unico.');
}

async function registerTransaction({
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
}) {
  try {
    return await Transaction.create({
      userId,
      accountNumber,
      type,
      status,
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
    });
  } catch (err) {
    console.error('No se pudo registrar la transaccion.', err);
    throw err;
  }
}

async function findOwnedAccount(userId, accountNumber) {
  return Account.findOne({
    userId,
    accountNumber: String(accountNumber),
  });
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
    const exists = await User.exists({ email: normalizedEmail });
    if (exists) {
      return res.status(409).json({ message: 'Ya existe una cuenta con ese email.' });
    }

    const { passwordHash, passwordSalt } = hashPassword(password);
    const user = await User.create({
      name: finalName,
      email: normalizedEmail,
      passwordHash,
      passwordSalt,
    });

    const token = await createSessionForUser(user);
    res.status(201).json(buildAuthPayload(user, token));
  } catch (err) {
    console.error(err);
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
    const user = await User.findOne({ email: normalizedEmail });

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
    await Session.deleteOne({ tokenHash: hashToken(req.authToken) });
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
    const card = generateCardForAccount();

    const account = await Account.create({
      userId: req.authUser._id,
      accountNumber,
      ownerName: finalOwnerName,
      balance,
      currency: normalizedCurrency,
      card,
    });

    await registerTransaction({
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
    });

    res.status(201).json(sanitizeAccount(account.toObject()));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo crear la cuenta.' });
  }
});

app.get('/api/accounts', authMiddleware, async (req, res) => {
  try {
    const accounts = await Account.find({ userId: req.authUser._id }).sort({ createdAt: -1 }).lean();
    res.json(accounts.map(sanitizeAccount));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudieron obtener las cuentas.' });
  }
});

app.get('/api/accounts/:accountNumber', authMiddleware, async (req, res) => {
  try {
    const account = await findOwnedAccount(req.authUser._id, req.params.accountNumber).lean();
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
    const account = await findOwnedAccount(req.authUser._id, req.params.accountNumber).lean();
    if (!account) {
      return res.status(404).json({ message: 'Cuenta no encontrada.' });
    }

    const txs = await Transaction.find({
      userId: req.authUser._id,
      accountNumber: String(req.params.accountNumber),
    })
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    res.json(txs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo obtener el historial de transacciones.' });
  }
});

app.patch('/api/accounts/:accountNumber', authMiddleware, async (req, res) => {
  const { currency, balance, addBalance } = req.body || {};

  try {
    const account = await findOwnedAccount(req.authUser._id, req.params.accountNumber);
    if (!account) {
      return res.status(404).json({ message: 'Cuenta no encontrada.' });
    }

    if (currency) {
      if (!allowedCurrencies.includes(currency)) {
        return res.status(400).json({ message: 'Moneda no soportada. Usa USD, MXN, JPY o EUR.' });
      }
      account.currency = currency;
    }

    if (balance !== undefined && addBalance !== undefined) {
      return res
        .status(400)
        .json({ message: 'Usa "balance" (establecer) o "addBalance" (sumar), no ambos.' });
    }

    if (balance !== undefined) {
      const numericBalance = Number(balance);
      if (!Number.isFinite(numericBalance) || numericBalance < 0) {
        return res.status(400).json({ message: 'Saldo invalido.' });
      }

      account.balance = numericBalance;
      await account.save();

      await registerTransaction({
        userId: req.authUser._id,
        accountNumber: account.accountNumber,
        type: 'credit',
        status: 'approved',
        amount: numericBalance,
        currency: account.currency,
        description: 'Saldo establecido manualmente',
        source: 'balance_set',
        transactionId: buildTransactionId('POVY-BAL'),
        balanceAfter: account.balance,
        merchantName: 'Povy Sandbox',
      });

      return res.json(account.toObject());
    }

    if (addBalance !== undefined) {
      const numericAdd = Number(addBalance);
      if (!Number.isFinite(numericAdd)) {
        return res.status(400).json({ message: 'Monto invalido.' });
      }

      const nextBalance = account.balance + numericAdd;
      if (nextBalance < 0) {
        return res.status(400).json({ message: 'El ajuste dejaria el saldo negativo.' });
      }

      account.balance = nextBalance;
      await account.save();

      await registerTransaction({
        userId: req.authUser._id,
        accountNumber: account.accountNumber,
        type: numericAdd >= 0 ? 'credit' : 'debit',
        status: 'approved',
        amount: Math.abs(numericAdd),
        currency: account.currency,
        description: numericAdd >= 0 ? 'Recarga manual de saldo' : 'Descuento manual de saldo',
        source: 'manual_topup',
        transactionId: buildTransactionId('POVY-TOPUP'),
        balanceAfter: account.balance,
        merchantName: 'Povy Sandbox',
      });

      return res.json(account.toObject());
    }

    await account.save();
    res.json(account.toObject());
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo actualizar la cuenta.' });
  }
});

app.delete('/api/accounts/:accountNumber', authMiddleware, async (req, res) => {
  try {
    const deleted = await Account.findOneAndDelete({
      userId: req.authUser._id,
      accountNumber: String(req.params.accountNumber),
    });

    if (!deleted) {
      return res.status(404).json({ message: 'Cuenta no encontrada.' });
    }

    await Transaction.deleteMany({
      userId: req.authUser._id,
      accountNumber: deleted.accountNumber,
    });

    res.json({ message: 'Cuenta eliminada correctamente.', accountNumber: deleted.accountNumber });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo eliminar la cuenta.' });
  }
});

app.post('/api/payments', authMiddleware, async (req, res) => {
  const { accountNumber, amount, currency, description, merchantName } = req.body || {};

  if (!accountNumber || amount === undefined || amount === null) {
    return res.status(400).json({
      status: 'error',
      message: 'Faltan datos obligatorios: accountNumber y amount.',
    });
  }

  try {
    const account = await findOwnedAccount(req.authUser._id, accountNumber);
    if (!account) {
      return res.status(404).json({ status: 'error', message: 'Cuenta no encontrada.' });
    }

    const numericAmount = Number(amount);
    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ status: 'error', message: 'Monto invalido.' });
    }

    const finalCurrency = allowedCurrencies.includes(currency) ? currency : account.currency;
    const approved = numericAmount <= account.balance;

    if (approved) {
      account.balance -= numericAmount;
      await account.save();
    }

    const tx = await registerTransaction({
      userId: req.authUser._id,
      accountNumber: account.accountNumber,
      type: 'debit',
      status: approved ? 'approved' : 'declined',
      amount: numericAmount,
      currency: finalCurrency,
      description: description || 'Pago de prueba por numero de cuenta',
      source: 'account_payment',
      transactionId: buildTransactionId('POVY'),
      balanceAfter: account.balance,
      merchantName: merchantName || 'Povy Test',
      failureReason: approved ? undefined : 'Fondos insuficientes en la cuenta.',
    });

    res.json(
      paymentResponse(tx, account, {
        message: approved ? 'Pago aprobado.' : 'Fondos insuficientes en la cuenta.',
      })
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: 'Error interno al procesar el pago.' });
  }
});

app.post('/api/payments/card', authMiddleware, async (req, res) => {
  const { cardNumber, expMonth, expYear, cvv, amount, currency, description, merchantName } =
    req.body || {};

  if (!cardNumber || !expMonth || !expYear || !cvv || amount === undefined || amount === null) {
    return res.status(400).json({
      status: 'error',
      message: 'Faltan datos obligatorios para el pago con tarjeta.',
    });
  }

  try {
    const cleanCardNumber = String(cardNumber).replace(/\s+/g, '');
    const account = await Account.findOne({
      userId: req.authUser._id,
      'card.cardNumber': cleanCardNumber,
    });

    if (!account) {
      return res.status(404).json({ status: 'error', message: 'Tarjeta no encontrada.' });
    }

    if (
      account.card.expMonth !== String(expMonth) ||
      account.card.expYear !== String(expYear) ||
      account.card.cvv !== String(cvv)
    ) {
      return res.status(400).json({ status: 'error', message: 'Datos de tarjeta invalidos.' });
    }

    const numericAmount = Number(amount);
    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ status: 'error', message: 'Monto invalido.' });
    }

    const finalCurrency = allowedCurrencies.includes(currency) ? currency : account.currency;
    const approved = numericAmount <= account.balance;

    if (approved) {
      account.balance -= numericAmount;
      await account.save();
    }

    const tx = await registerTransaction({
      userId: req.authUser._id,
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
    });

    res.json(
      paymentResponse(tx, account, {
        cardLast4: account.card.cardNumber.slice(-4),
        message: approved ? 'Pago aprobado.' : 'Fondos insuficientes en la cuenta.',
      })
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({
      status: 'error',
      message: 'Error interno al procesar el pago con tarjeta.',
    });
  }
});

app.post('/api/payments/:transactionId/refund', authMiddleware, async (req, res) => {
  const { amount, description } = req.body || {};

  try {
    const original = await Transaction.findOne({
      userId: req.authUser._id,
      transactionId: String(req.params.transactionId),
    });

    if (!original) {
      return res.status(404).json({ message: 'Transaccion no encontrada.' });
    }

    if (!['account_payment', 'card_payment'].includes(original.source)) {
      return res.status(400).json({ message: 'Solo se pueden devolver pagos.' });
    }

    if (original.status !== 'approved') {
      return res.status(400).json({ message: 'Solo se pueden devolver pagos aprobados.' });
    }

    if (original.refundTransactionId) {
      return res.status(400).json({ message: 'La transaccion ya fue devuelta.' });
    }

    const account = await findOwnedAccount(req.authUser._id, original.accountNumber);
    if (!account) {
      return res.status(404).json({ message: 'Cuenta no encontrada para la devolucion.' });
    }

    const requestedAmount = amount === undefined || amount === null ? original.amount : Number(amount);
    if (!Number.isFinite(requestedAmount) || requestedAmount <= 0) {
      return res.status(400).json({ message: 'Monto de devolucion invalido.' });
    }

    if (requestedAmount > original.amount) {
      return res.status(400).json({ message: 'La devolucion no puede superar el pago original.' });
    }

    account.balance += requestedAmount;
    await account.save();

    const refundTx = await registerTransaction({
      userId: req.authUser._id,
      accountNumber: account.accountNumber,
      type: 'credit',
      status: 'approved',
      amount: requestedAmount,
      currency: original.currency,
      description: description || `Devolucion de ${original.transactionId}`,
      source: 'refund',
      transactionId: buildTransactionId('POVY-RFD'),
      balanceAfter: account.balance,
      merchantName: original.merchantName || 'Povy Test',
      relatedTransactionId: original.transactionId,
    });

    original.status = 'refunded';
    original.refundTransactionId = refundTx.transactionId;
    original.refundedAt = new Date();
    await original.save();

    res.json({
      message: 'Devolucion aplicada correctamente.',
      transactionId: refundTx.transactionId,
      relatedTransactionId: original.transactionId,
      accountNumber: account.accountNumber,
      amount: refundTx.amount,
      currency: refundTx.currency,
      remainingBalance: account.balance,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo procesar la devolucion.' });
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

app.listen(PORT, () => {
  console.log(`Povy backend sandbox corriendo en http://localhost:${PORT}`);
});
