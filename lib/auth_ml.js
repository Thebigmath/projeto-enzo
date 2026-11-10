// Autenticacao Mercado Livre (OAuth 2.0) para o Clonagem Enzo.
// Gerencia token em storage/token.json (cria/renova automaticamente).
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const STORAGE = process.env.STORAGE_PATH || path.join(__dirname, '../storage');
const ARQ = path.join(STORAGE, 'token.json');
const CFG = path.join(STORAGE, 'config.json');

function lerCfg() {
  try { return JSON.parse(fs.readFileSync(CFG, 'utf8')); } catch { return {}; }
}
function salvarCfg(c) { fs.mkdirSync(STORAGE, { recursive: true }); fs.writeFileSync(CFG, JSON.stringify(c, null, 2), 'utf8'); }
function lerToken() { try { return JSON.parse(fs.readFileSync(ARQ, 'utf8')); } catch { return null; } }
function salvarToken(t) { fs.mkdirSync(STORAGE, { recursive: true }); fs.writeFileSync(ARQ, JSON.stringify(t, null, 2), 'utf8'); }

function cfg() {
  return {
    client_id: process.env.ML_CLIENT_ID || lerCfg().client_id || '',
    client_secret: process.env.ML_CLIENT_SECRET || lerCfg().client_secret || '',
    redirect_uri: process.env.ML_REDIRECT_URI || lerCfg().redirect_uri || 'http://localhost:3000/callback',
  };
}

function urlAuth() {
  const c = cfg();
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: c.client_id,
    redirect_uri: c.redirect_uri,
  });
  return `https://auth.mercadolivre.com.br/authorization?${params}`;
}

async function trocarCode(code) {
  const c = cfg();
  const { data } = await axios.post('https://api.mercadolibre.com/oauth/token', new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: c.client_id,
    client_secret: c.client_secret,
    code,
    redirect_uri: c.redirect_uri,
  }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 30000 });
  data.created_at = Math.floor(Date.now() / 1000);
  salvarToken(data);
  return data;
}

let renovando = null;
async function token() {
  const t = lerToken();
  if (!t) throw new Error('Nao autenticado. Acesse /auth para conectar a conta ML.');
  // renova se estiver vencendo (menos de 10 min)
  if ((t.created_at + t.expires_in) - Date.now() / 1000 > 600) return t;
  if (renovando) return renovando;
  renovando = (async () => {
    const c = cfg();
    const { data } = await axios.post('https://api.mercadolibre.com/oauth/token', new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: c.client_id,
      client_secret: c.client_secret,
      refresh_token: t.refresh_token,
    }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 30000 });
    data.created_at = Math.floor(Date.now() / 1000);
    data.user_id = data.user_id || t.user_id;
    salvarToken(data);
    return data;
  })().finally(() => { renovando = null; });
  return renovando;
}

async function headers() {
  const t = await token();
  return { Authorization: `Bearer ${t.access_token}`, 'Content-Type': 'application/json' };
}

function conectado() {
  return !!lerToken();
}

function desconectar() {
  try { fs.unlinkSync(ARQ); } catch {}
}

module.exports = { cfg, salvarCfg, urlAuth, trocarCode, token, headers, conectado, desconectar };
