// Login do Clonagem Enzo (11/11/2026).
// - Usuário e senha. A senha é guardada só em hash (bcrypt, custo 12).
// - Sessão em cookie assinado (HMAC), válida por 2 horas, sem renovação automática.
// - Cookie HttpOnly, Secure e SameSite=Lax. Sair e trocar a senha derrubam as sessões antigas.
// - Bloqueio: 8 erros seguidos travam a conta por 15 min (venha de onde vier) e 8 erros do mesmo IP também.
// Arquivos (no STORAGE, fora do git): usuarios.json (hashes) e segredo.txt (chave do cookie).
// Se ENZO_SEGREDO estiver definido (32+ caracteres), ele tem prioridade sobre o segredo.txt.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const STORAGE = () => process.env.STORAGE_PATH || path.join(__dirname, '../storage');
const ARQ_USUARIOS = () => path.join(STORAGE(), 'usuarios.json');
const ARQ_SEGREDO = () => path.join(STORAGE(), 'segredo.txt');
const COOKIE = 'enzo_sessao';
const VALIDADE_MS = 2 * 3600 * 1000;
const MIN_SENHA = 10;
const JANELA_MS = 15 * 60 * 1000;
const MAX_ERROS = 8;

const lerJson = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return d; } };
const gravarJson = (f, v) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, JSON.stringify(v, null, 2), 'utf8'); };
// hash real (sem usuário), para o tempo de resposta não revelar se a conta existe
const HASH_FALSO = bcrypt.hashSync('senha-falsa-para-tempo-constante', 12);
const normUsuario = (u) => String(u || '').trim().toLowerCase().slice(0, 60);

// ---- segredo do cookie ----
let _segredo = null;
function segredo() {
  if (_segredo) return _segredo;
  if (process.env.ENZO_SEGREDO && process.env.ENZO_SEGREDO.length >= 32) return (_segredo = process.env.ENZO_SEGREDO);
  try { const s = fs.readFileSync(ARQ_SEGREDO(), 'utf8').trim(); if (s.length >= 32) return (_segredo = s); } catch {}
  const novo = crypto.randomBytes(48).toString('hex');
  fs.mkdirSync(STORAGE(), { recursive: true });
  fs.writeFileSync(ARQ_SEGREDO(), novo, { encoding: 'utf8', mode: 0o600 });
  return (_segredo = novo);
}
const assinatura = (txt) => crypto.createHmac('sha256', segredo()).update(txt).digest('base64url');
const iguais = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

// ---- usuários ----
const usuarios = () => lerJson(ARQ_USUARIOS(), []);
const temUsuarios = () => usuarios().length > 0;
function listar() {
  return usuarios().map(u => ({ usuario: u.usuario, nome: u.nome || u.usuario, criado_em: u.criado_em || null, bloqueado: !!u.bloqueado }));
}
function validarSenha(senha) {
  const s = String(senha || '');
  if (s.length < MIN_SENHA) throw new Error(`A senha precisa ter pelo menos ${MIN_SENHA} caracteres.`);
  return s;
}
// cria o usuário, ou atualiza nome e senha se ele já existir (nova senha derruba as sessões antigas)
async function salvarUsuario({ usuario, nome, senha }) {
  const u = normUsuario(usuario);
  if (!/^[a-z0-9._-]{3,60}$/.test(u)) throw new Error('Usuário inválido: use de 3 a 60 letras, números, ponto, traço ou underline.');
  const lista = usuarios();
  const existente = lista.find(x => x.usuario === u);
  const senhaOk = validarSenha(senha);
  const hash = await bcrypt.hash(senhaOk, 12);
  if (existente) {
    existente.hash = hash; existente.versao = (existente.versao || 0) + 1;
    if (nome) existente.nome = String(nome).slice(0, 80);
    existente.bloqueado = false;
  } else {
    lista.push({ usuario: u, nome: String(nome || u).slice(0, 80), hash, versao: 1, criado_em: new Date().toISOString() });
  }
  gravarJson(ARQ_USUARIOS(), lista);
  return { ok: true, usuario: u, novo: !existente };
}

// ---- bloqueio (conta e IP) ----
const erros = new Map();   // chave -> { n, ini }
function bloqueadoEm(chave) {
  const t = erros.get(chave); if (!t) return false;
  if (Date.now() - t.ini > JANELA_MS) { erros.delete(chave); return false; }
  return t.n >= MAX_ERROS;
}
function errouEm(chave) {
  const t = erros.get(chave);
  if (!t || Date.now() - t.ini > JANELA_MS) erros.set(chave, { n: 1, ini: Date.now() }); else t.n++;
}
const chaveConta = (u) => 'conta:' + normUsuario(u);
const chaveIp = (ip) => 'ip:' + String(ip || '');

// confere usuário e senha. Mesma resposta para usuário inexistente e senha errada (não revela qual).
async function verificar(usuario, senha, ip) {
  if (bloqueadoEm(chaveConta(usuario)) || bloqueadoEm(chaveIp(ip))) return { ok: false, motivo: 'bloqueado' };
  const u = usuarios().find(x => x.usuario === normUsuario(usuario));
  // compara mesmo sem usuário, para o tempo de resposta não revelar a existência da conta
  const hash = u ? u.hash : HASH_FALSO;
  const confere = await bcrypt.compare(String(senha || ''), hash);
  if (!u || !confere || u.bloqueado) {
    errouEm(chaveConta(usuario)); errouEm(chaveIp(ip));
    return { ok: false, motivo: 'errado' };
  }
  erros.delete(chaveConta(usuario)); erros.delete(chaveIp(ip));
  return { ok: true, usuario: u };
}

// ---- sessão ----
function lerCookie(req) {
  const cab = String(req.headers.cookie || '');
  const par = cab.split(';').map(c => c.trim()).find(c => c.startsWith(COOKIE + '='));
  return par ? decodeURIComponent(par.slice(COOKIE.length + 1)) : '';
}
function sessaoDe(req) {
  const v = lerCookie(req); if (!v || v.indexOf('.') < 0) return null;
  const [corpo, sig] = v.split('.');
  if (!iguais(assinatura(corpo), sig)) return null;
  let d; try { d = JSON.parse(Buffer.from(corpo, 'base64url').toString('utf8')); } catch { return null; }
  if (!d || !d.u || !d.exp || Date.now() > d.exp) return null;
  const u = usuarios().find(x => x.usuario === d.u);
  if (!u || u.bloqueado || (u.versao || 0) !== (d.v || 0)) return null;   // conta bloqueada, senha trocada ou sair
  return { usuario: u.usuario, nome: u.nome || u.usuario };
}
function ligarSessao(res, u) {
  const corpo = Buffer.from(JSON.stringify({ u: u.usuario, v: u.versao || 0, exp: Date.now() + VALIDADE_MS })).toString('base64url');
  const v = corpo + '.' + assinatura(corpo);
  // sem Max-Age: o cookie vale só até fechar o navegador ou vencer o exp (2 h)
  res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(v)}; Path=/; HttpOnly; Secure; SameSite=Lax`);
}
// sair: apaga o cookie e sobe a versão do usuário (cookie copiado deixa de valer)
function sairSessao(res, usuario) {
  if (usuario) {
    const lista = usuarios(); const u = lista.find(x => x.usuario === usuario);
    if (u) { u.versao = (u.versao || 0) + 1; gravarJson(ARQ_USUARIOS(), lista); }
  }
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
}

// middleware: sem sessão, /api responde 401 e o resto vai para o login
function exigeSessao(req, res, next) {
  const s = sessaoDe(req);
  if (s) { req.usuario = s; return next(); }
  if (req.path.startsWith('/api/')) return res.status(401).json({ erro: 'Entre com usuário e senha.' });
  return res.redirect('/login?volta=' + encodeURIComponent(req.originalUrl));
}

module.exports = { temUsuarios, listar, salvarUsuario, verificar, sessaoDe, ligarSessao, sairSessao, exigeSessao, normUsuario, validarSenha, MIN_SENHA };
