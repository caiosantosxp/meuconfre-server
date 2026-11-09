// Servidor de sincronizacao ZERO-KNOWLEDGE do MeuCofre.
// Guarda apenas o cofre CIFRADO (blob). Nunca ve a chave-mestra nem o conteudo.
const express = require('express');
const cors = require('cors');
const { pool, migrate } = require('./db');
const { hashPassword, verifyPassword, signToken, authMiddleware } = require('./auth');

const app = express();
app.use(cors());                          // Bearer token, sem cookies -> CORS liberado
app.use(express.json({ limit: '25mb' })); // cofre cifrado pode crescer

const ALLOW_REG = process.env.ALLOW_REGISTRATION !== 'false';
const h = (fn) => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'erro interno' }); });

app.get('/api/health', (req, res) => res.json({ ok: true, time: Date.now() }));

// ---- registro (desligue com ALLOW_REGISTRATION=false depois de criar sua conta) ----
app.post('/api/register', h(async (req, res) => {
  if (!ALLOW_REG) return res.status(403).json({ error: 'registro desabilitado' });
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 8)
    return res.status(400).json({ error: 'email e senha (min 8) obrigatorios' });
  try {
    const r = await pool.query(
      'INSERT INTO users(email, pass) VALUES($1,$2) RETURNING id, email',
      [String(email).toLowerCase().trim(), hashPassword(password)]
    );
    const u = r.rows[0];
    await pool.query('INSERT INTO vaults(user_id, blob, rev) VALUES($1, NULL, 0) ON CONFLICT DO NOTHING', [u.id]);
    res.json({ token: signToken(u), email: u.email });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'email ja cadastrado' });
    throw e;
  }
}));

app.post('/api/login', h(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'dados invalidos' });
  const r = await pool.query('SELECT id, email, pass FROM users WHERE email=$1', [String(email).toLowerCase().trim()]);
  const u = r.rows[0];
  if (!u || !verifyPassword(password, u.pass)) return res.status(401).json({ error: 'email ou senha incorretos' });
  res.json({ token: signToken(u), email: u.email });
}));

// ---- cofre (sempre cifrado) ----
app.get('/api/vault', authMiddleware, h(async (req, res) => {
  const r = await pool.query('SELECT blob, rev FROM vaults WHERE user_id=$1', [req.user.uid]);
  if (!r.rows[0]) return res.json({ blob: null, rev: 0 });
  res.json({ blob: r.rows[0].blob, rev: r.rows[0].rev });
}));

// PUT com controle de versao (rev): evita um cliente sobrescrever o outro sem querer.
app.put('/api/vault', authMiddleware, h(async (req, res) => {
  const { blob, baseRev } = req.body || {};
  if (!blob || typeof blob !== 'object' || !blob.ct || !blob.salt)
    return res.status(400).json({ error: 'blob invalido (precisa ser o cofre cifrado)' });
  const cur = await pool.query('SELECT blob, rev FROM vaults WHERE user_id=$1', [req.user.uid]);
  const curRev = cur.rows[0] ? cur.rows[0].rev : 0;
  if (typeof baseRev === 'number' && baseRev !== curRev)
    return res.status(409).json({ error: 'conflito de versao', rev: curRev, blob: cur.rows[0] ? cur.rows[0].blob : null });
  const newRev = curRev + 1;
  await pool.query(
    `INSERT INTO vaults(user_id, blob, rev, updated_at) VALUES($1,$2,$3,now())
     ON CONFLICT (user_id) DO UPDATE SET blob=$2, rev=$3, updated_at=now()`,
    [req.user.uid, blob, newRev]
  );
  res.json({ rev: newRev });
}));

const PORT = process.env.PORT || 3000;
migrate()
  .then(() => app.listen(PORT, () => console.log('MeuCofre server ouvindo na porta ' + PORT)))
  .catch(e => { console.error('Falha ao migrar/conectar no Postgres:', e.message); process.exit(1); });
