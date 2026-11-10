# Clonagem Enzo

Programa independente de clonagem de anuncios no Mercado Livre. Copia um anuncio existente como anuncio NOVO na mesma conta (com edicao de titulo, preco, estoque, SKU, tipo e descricao), validando antes de publicar.

## Como rodar

1. Instalar dependencias:
   ```
   npm install
   ```
2. Configurar credenciais do app ML (crie em https://developers.mercadolivre.com.br):
   - Copie `.env.example` para `.env` e preencha `ML_CLIENT_ID`, `ML_CLIENT_SECRET`, `ML_REDIRECT_URI`
   - Ou configure pela tela do app (Configurar).
3. Rodar:
   ```
   npm start
   ```
4. Abrir http://localhost:3000 e clicar em "Conectar conta ML" para autorizar.

## Funcionalidades

- Adicionar anuncios a fila (por MLB ou link, varios de uma vez)
- Editar titulo, preco, estoque, SKU, tipo (Classico/Premium) e descricao
- Validar com o Mercado Livre (sem criar nada)
- Clonar (cria o anuncio de verdade, com descricao e compatibilidades)
- Vendas, avaliacoes e perguntas NAO vao junto (ficam no anuncio original)

## Estrutura

- `server.js` — servidor Express
- `lib/auth_ml.js` — autenticacao OAuth ML + refresh de token
- `lib/clonagem.js` — logica de clonagem (fila, validar, clonar)
- `public/index.html` — interface web

## Notas

- Storage (fila de clonagem + token) fica em `./storage` (ou `STORAGE_PATH`).
- Nao commitar `.env` nem `storage/` (contem tokens).
- App criado para Enzo. Adaptado do modulo de clonagem do SEVEN Cordeiro.
