const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET || 'troque-este-segredo';

// Hash de senha de LOGIN (nao e a chave-mestra). scrypt, sem dependencia nativa.
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64);
  return 's2$' + salt.toString('hex') + '$' + hash.toString('hex');
}
function verifyPassword(pw, stored) {
  try {
    const [, saltHex, hashHex] = stored.split('$');
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(pw, salt, expected.length);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch { return false; }
}

function signToken(u) {
  return jwt.sign({ uid: String(u.id), email: u.email }, SECRET, { expiresIn: '30d' });
}
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  try { req.user = jwt.verify(t, SECRET); next(); }
  catch { res.status(401).json({ error: 'token invalido ou expirado' }); }
}

module.exports = { hashPassword, verifyPassword, signToken, authMiddleware };
