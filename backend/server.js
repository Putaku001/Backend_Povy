require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error(
    'Falta la variable de entorno MONGODB_URI con la cadena de conexión de MongoDB. Las cuentas no se persistirán hasta que la definas.'
  );
} else {
  mongoose
    .connect(MONGODB_URI, { dbName: 'povy_sandbox' })
    .then(() => {
      console.log('Conectado a MongoDB (Povy sandbox)');
    })
    .catch((err) => {
      console.error('Error al conectar con MongoDB. Verifica tu cadena de conexión.', err);
    });
}

const accountSchema = new mongoose.Schema(
  {
    accountNumber: { type: String, unique: true, index: true },
    ownerName: { type: String, required: true },
    balance: { type: Number, required: true },
    currency: { type: String, required: true, enum: ['USD', 'MXN', 'JPY'] },
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
    accountNumber: { type: String, index: true },
    type: { type: String, enum: ['debit', 'credit'], required: true },
    amount: { type: Number, required: true },
    currency: { type: String, required: true },
    description: { type: String },
    source: { type: String }, // account_payment, card_payment, manual_topup
    transactionId: { type: String },
    balanceAfter: { type: Number },
    merchantName: { type: String },
  },
  { timestamps: true }
);

const Account = mongoose.models.Account || mongoose.model('Account', accountSchema);
const Transaction =
  mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);

const allowedCurrencies = ['USD', 'MXN', 'JPY'];

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
  for (let i = 0; i < 10; i++) {
    const random = Math.floor(1 + Math.random() * 99999999);
    const accountNumber = `001-${String(random).padStart(8, '0')}`;
    const exists = await Account.exists({ accountNumber });
    if (!exists) return accountNumber;
  }
  throw new Error('No se pudo generar un número de cuenta único.');
}

async function registerTransaction({
  accountNumber,
  type,
  amount,
  currency,
  description,
  source,
  transactionId,
  balanceAfter,
  merchantName,
}) {
  try {
    await Transaction.create({
      accountNumber,
      type,
      amount,
      currency,
      description,
      source,
      transactionId,
      balanceAfter,
      merchantName,
    });
  } catch (err) {
    console.error('No se pudo registrar la transacción en el historial.', err);
  }
}

// Crear cuenta de prueba (persistida en MongoDB)
app.post('/api/accounts', async (req, res) => {
  const { ownerName, currency, initialBalance } = req.body || {};

  const normalizedCurrency = allowedCurrencies.includes(currency) ? currency : 'USD';
  const balance =
    typeof initialBalance === 'number' && initialBalance >= 0 ? initialBalance : 10000;
  const finalOwnerName = ownerName && ownerName.trim() ? ownerName.trim() : 'Usuario de prueba';

  try {
    const accountNumber = await generateUniqueAccountNumber();
    const card = generateCardForAccount();

    const account = await Account.create({
      accountNumber,
      ownerName: finalOwnerName,
      balance,
      currency: normalizedCurrency,
      card,
    });

    res.status(201).json(account);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo crear la cuenta.' });
  }
});

// Historial de transacciones de una cuenta
app.get('/api/accounts/:accountNumber/transactions', async (req, res) => {
  const { accountNumber } = req.params;

  try {
    const txs = await Transaction.find({ accountNumber: String(accountNumber) })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    res.json(txs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo obtener el historial de transacciones.' });
  }
});

// Listar cuentas de prueba
app.get('/api/accounts', async (req, res) => {
  try {
    const accounts = await Account.find({}).sort({ createdAt: -1 }).lean();
    res.json(accounts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudieron obtener las cuentas.' });
  }
});

// Obtener cuenta específica por número de cuenta
app.get('/api/accounts/:accountNumber', async (req, res) => {
  const { accountNumber } = req.params;

  try {
    const account = await Account.findOne({ accountNumber: String(accountNumber) }).lean();

    if (!account) {
      return res.status(404).json({ message: 'Cuenta no encontrada.' });
    }

    res.json(account);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo obtener la cuenta.' });
  }
});

// Actualizar datos de una cuenta (moneda y saldo / recargas)
app.patch('/api/accounts/:accountNumber', async (req, res) => {
  const { accountNumber } = req.params;
  const { currency, balance, addBalance } = req.body || {};

  try {
    const account = await Account.findOne({ accountNumber: String(accountNumber) });

    if (!account) {
      return res.status(404).json({ message: 'Cuenta no encontrada.' });
    }

    if (currency) {
      if (!allowedCurrencies.includes(currency)) {
        return res
          .status(400)
          .json({ message: 'Moneda no soportada. Usa USD, MXN o JPY.' });
      }
      account.currency = currency;
    }

    if (balance !== undefined && addBalance !== undefined) {
      return res
        .status(400)
        .json({ message: 'Usa "balance" (establecer) o "addBalance" (sumar), no ambos.' });
    }

    // Establecer saldo exacto (modo avanzado)
    if (balance !== undefined) {
      const numericBalance = Number(balance);
      if (!Number.isFinite(numericBalance) || numericBalance < 0) {
        return res.status(400).json({ message: 'Saldo inválido.' });
      }
      account.balance = numericBalance;
    }

    // Sumar saldo (recarga ficticia para pruebas)
    if (addBalance !== undefined) {
      const numericAdd = Number(addBalance);
      if (!Number.isFinite(numericAdd)) {
        return res.status(400).json({ message: 'Monto de recarga inválido.' });
      }
      account.balance += numericAdd;
      await account.save();

      await registerTransaction({
        accountNumber: account.accountNumber,
        type: numericAdd >= 0 ? 'credit' : 'debit',
        amount: Math.abs(numericAdd),
        currency: account.currency,
        description: 'Ajuste manual de saldo (recarga ficticia)',
        source: 'manual_topup',
        balanceAfter: account.balance,
        merchantName: 'Povy Test',
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

// Eliminar una cuenta
app.delete('/api/accounts/:accountNumber', async (req, res) => {
  const { accountNumber } = req.params;

  try {
    const deleted = await Account.findOneAndDelete({ accountNumber: String(accountNumber) });

    if (!deleted) {
      return res.status(404).json({ message: 'Cuenta no encontrada.' });
    }

    res.json({ message: 'Cuenta eliminada correctamente.', accountNumber: deleted.accountNumber });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'No se pudo eliminar la cuenta.' });
  }
});

// Endpoint de pago simulado usando número de cuenta
app.post('/api/payments', async (req, res) => {
  const { accountNumber, amount, currency, description, merchantName } = req.body || {};

  if (!accountNumber || amount === undefined || amount === null) {
    return res.status(400).json({
      status: 'error',
      message: 'Faltan datos obligatorios: accountNumber y amount.',
    });
  }

  try {
    const account = await Account.findOne({ accountNumber: String(accountNumber) });

    if (!account) {
      return res.status(404).json({
        status: 'error',
        message: 'Cuenta no encontrada.',
      });
    }

    const numericAmount = Number(amount);

    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({
        status: 'error',
        message: 'Monto inválido.',
      });
    }

    let status = 'approved';
    let reason = 'Pago aprobado.';

    if (numericAmount > account.balance) {
      status = 'declined';
      reason = 'Fondos insuficientes en la cuenta.';
    }

    if (status === 'approved') {
      account.balance -= numericAmount;
      await account.save();
    }

    const transactionId = `POVY-${Date.now()}`;

    await registerTransaction({
      accountNumber: account.accountNumber,
      type: status === 'approved' ? 'debit' : 'debit',
      amount: numericAmount,
      currency: currency || account.currency,
      description: description || 'Pago de prueba por número de cuenta',
      source: 'account_payment',
      transactionId,
      balanceAfter: account.balance,
      merchantName: merchantName || 'Povy Test',
    });

    res.json({
      status,
      transactionId,
      message: reason,
      amount: numericAmount,
      currency: currency || account.currency,
      description: description || 'Pago de prueba',
      accountNumber: account.accountNumber,
      remainingBalance: account.balance,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      status: 'error',
      message: 'Error interno al procesar el pago.',
    });
  }
});

// Endpoint de pago simulado usando tarjeta asociada a una cuenta
app.post('/api/payments/card', async (req, res) => {
  const { cardNumber, expMonth, expYear, cvv, amount, currency, description, merchantName } =
    req.body || {};

  if (
    !cardNumber ||
    !expMonth ||
    !expYear ||
    !cvv ||
    amount === undefined ||
    amount === null
  ) {
    return res.status(400).json({
      status: 'error',
      message: 'Faltan datos obligatorios para el pago con tarjeta.',
    });
  }

  const cleanCardNumber = String(cardNumber).replace(/\s+/g, '');

  try {
    const account = await Account.findOne({ 'card.cardNumber': cleanCardNumber });

    if (!account) {
      return res.status(404).json({
        status: 'error',
        message: 'Tarjeta no encontrada.',
      });
    }

    if (
      account.card.expMonth !== String(expMonth) ||
      account.card.expYear !== String(expYear) ||
      account.card.cvv !== String(cvv)
    ) {
      return res.status(400).json({
        status: 'error',
        message: 'Datos de tarjeta inválidos.',
      });
    }

    const numericAmount = Number(amount);

    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({
        status: 'error',
        message: 'Monto inválido.',
      });
    }

    let status = 'approved';
    let reason = 'Pago aprobado.';

    if (numericAmount > account.balance) {
      status = 'declined';
      reason = 'Fondos insuficientes en la cuenta.';
    }

    if (status === 'approved') {
      account.balance -= numericAmount;
      await account.save();
    }

    const transactionId = `POVY-CARD-${Date.now()}`;

    await registerTransaction({
      accountNumber: account.accountNumber,
      type: status === 'approved' ? 'debit' : 'debit',
      amount: numericAmount,
      currency: currency || account.currency,
      description: description || 'Pago de prueba con tarjeta',
      source: 'card_payment',
      transactionId,
      balanceAfter: account.balance,
      merchantName: merchantName || 'Povy Test',
    });

    res.json({
      status,
      transactionId,
      message: reason,
      amount: numericAmount,
      currency: currency || account.currency,
      description: description || 'Pago de prueba con tarjeta',
      accountNumber: account.accountNumber,
      cardLast4: account.card.cardNumber.slice(-4),
      remainingBalance: account.balance,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      status: 'error',
      message: 'Error interno al procesar el pago con tarjeta.',
    });
  }
});

app.get('/', (req, res) => {
  res.json({ message: 'Povy API operativa (sandbox)' });
});

app.listen(PORT, () => {
  console.log(`Povy backend sandbox corriendo en http://localhost:${PORT}`);
});
