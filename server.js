const express = require('express');
const path = require('path');
const fs = require('fs');
const auth = require('./lib/auth_ml');
const clonagem = require('./lib/clonagem');

const app = express();
const PORT = process.env.PORT || 3000;
const STORAGE = process.env.STORAGE_PATH || path.join(__dirname, 'storage');

// storage path env
process.env.STORAGE_PATH = STORAGE;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// OAuth ML
app.get('/auth', (req, res) => {
  if (!auth.cfg().client_id) return res.status(400).send('Configure ML_CLIENT_ID e ML_CLIENT_SECRET no .env ou storage/config.json');
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

// fallback SPA
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Clonagem Enzo rodando em http://localhost:${PORT}`));
