const express = require('express');
const path = require('path');
const fs = require('fs');
const auth = require('./lib/auth_ml');
const clonagem = require('./lib/clonagem');
const login = require('./lib/login');

const app = express();
const PORT = process.env.PORT || 3000;
const STORAGE = process.env.STORAGE_PATH || path.join(__dirname, 'storage');
// tela de administração escondida (não aparece em nenhum menu). Troque por um caminho aleatório no ambiente.
const ADMIN_PATH = process.env.ENZO_ADMIN_PATH || '/_ajustes-enzo';

// storage path env
process.env.STORAGE_PATH = STORAGE;

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (req.secure || String(req.headers['x-forwarded-proto'] || '') === 'https') res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});
app.use(express.json());

// assets (CSS, JS, imagens) ficam em public/ e não têm dado. Páginas HTML ficam em paginas/ (nunca em public/).
app.use(express.static(path.join(__dirname, 'public')));

const pagina = (nome) => (req, res) => res.sendFile(path.join(__dirname, 'paginas', nome));

// ---- rotas abertas (sem sessão) ----
app.get('/login', pagina('login.html'));
app.get('/api/sessao', (req, res) => {
  const s = login.sessaoDe(req);
  res.json(s ? { logado: true, usuario: s.usuario, nome: s.nome } : { logado: false, tem_usuarios: login.temUsuarios() });
});
app.post('/api/login', async (req, res) => {
  const { usuario, senha } = req.body || {};
  const r = await login.verificar(usuario, senha, req.ip);
  if (!r.ok) {
    const msg = r.motivo === 'bloqueado' ? 'Muitas tentativas erradas. Tente de novo em 15 minutos.' : 'Usuário ou senha incorretos.';
    return res.status(r.motivo === 'bloqueado' ? 429 : 401).json({ erro: msg });
  }
  login.ligarSessao(res, r.usuario);
  res.json({ ok: true, nome: r.usuario.nome || r.usuario.usuario });
});
app.post('/api/logout', (req, res) => {
  const s = login.sessaoDe(req);
  login.sairSessao(res, s && s.usuario);
  res.json({ ok: true });
});

// ---- tela de administração escondida ----
app.get(ADMIN_PATH, (req, res, next) => {
  if (!login.temUsuarios()) return res.sendFile(path.join(__dirname, 'paginas', 'admin.html'));   // primeiro acesso: criar o usuário
  if (!login.sessaoDe(req)) return res.redirect('/login?volta=' + encodeURIComponent(ADMIN_PATH));
  res.sendFile(path.join(__dirname, 'paginas', 'admin.html'));
});
// criar/alterar usuário: livre só enquanto não existe nenhum (primeiro acesso); depois exige sessão
app.get('/api/admin/usuarios', login.exigeSessao, (req, res) => res.json({ usuarios: login.listar() }));
app.post('/api/admin/usuarios', async (req, res) => {
  if (login.temUsuarios() && !login.sessaoDe(req)) return res.status(401).json({ erro: 'Entre com usuário e senha.' });
  try {
    const r = await login.salvarUsuario(req.body || {});
    // trocou a senha de quem está logado: a sessão antiga deixa de valer (é preciso entrar de novo)
    res.json({ ...r, usuarios: login.listar() });
  } catch (e) { res.status(400).json({ erro: e.message }); }
});

// ---- tudo abaixo exige sessão ----
app.use(login.exigeSessao);

app.get('/', pagina('index.html'));

// OAuth ML
app.get('/auth', (req, res) => {
  if (!auth.cfg().client_id) return res.status(400).send('Configure ML_CLIENT_ID e ML_CLIENT_SECRET no ambiente.');
  res.redirect(auth.urlAuth());
});
app.get('/callback', async (req, res) => {
  try {
    await auth.trocarCode(req.query.code);
    res.redirect('/');
  } catch (e) {
    res.status(500).send('Erro ao autenticar: ' + e.message);
  }
});
app.get('/api/status', (req, res) => {
  res.json({ conectado: auth.conectado(), cfg: { client_id: !!auth.cfg().client_id } });
});
app.post('/api/desconectar', (req, res) => { auth.desconectar(); res.json({ ok: true }); });

// Config (salvar client_id/secret via tela)
app.post('/api/config', (req, res) => {
  const c = auth.cfg();
  if (req.body.client_id) c.client_id = req.body.client_id;
  if (req.body.client_secret) c.client_secret = req.body.client_secret;
  if (req.body.redirect_uri) c.redirect_uri = req.body.redirect_uri;
  auth.salvarCfg(c);
  res.json({ ok: true });
});

// Clonagem
app.get('/api/clonagem', async (req, res) => {
  try { res.json(clonagem.lista()); }
  catch (e) { res.status(500).json({ erro: e.message }); }
});
app.post('/api/clonagem', async (req, res) => {
  try { res.json(await clonagem.adicionar(req.body.texto)); }
  catch (e) { res.status(500).json({ erro: e.message }); }
});
app.post('/api/clonagem/:mlb/editar', (req, res) => {
  try { res.json(clonagem.editar(req.params.mlb, req.body || {})); }
  catch (e) { res.status(500).json({ erro: e.message }); }
});
app.delete('/api/clonagem/:mlb', (req, res) => {
  try { res.json(clonagem.remover(req.params.mlb)); }
  catch (e) { res.status(500).json({ erro: e.message }); }
});
app.post('/api/clonagem/:mlb/validar', async (req, res) => {
  try { res.json(await clonagem.validar(req.params.mlb)); }
  catch (e) { res.status(500).json({ erro: e.message }); }
});
app.post('/api/clonagem/:mlb/clonar', async (req, res) => {
  try { res.json(await clonagem.clonar(req.params.mlb)); }
  catch (e) { res.status(500).json({ erro: e.message }); }
});

// rota desconhecida: API responde 404 em JSON; o resto volta para a tela principal
app.use('/api', (req, res) => res.status(404).json({ erro: 'Rota não encontrada.' }));
app.get('*', pagina('index.html'));

app.listen(PORT, () => console.log(`Clonagem Enzo rodando em http://localhost:${PORT}`));
