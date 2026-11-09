# MeuCofre — Servidor de sincronização (zero-knowledge)

Guarda **apenas o cofre cifrado**. Nunca vê a chave-mestra nem o conteúdo.
`password.desbug.pro` · Docker Swarm + Portainer + Traefik · Postgres.

## API
- `POST /api/register {email,password}` → `{token}` (desligável)
- `POST /api/login {email,password}` → `{token}`
- `GET /api/vault` (Bearer) → `{blob, rev}` — blob = cofre cifrado
- `PUT /api/vault {blob, baseRev}` (Bearer) → `{rev}` (409 em conflito de versão)
- `GET /api/health`

**Login (email+senha)** autentica no servidor. A **chave-mestra** descriptografa só no app. São dois segredos distintos.

## Passo a passo do deploy

### 1. Criar o banco dedicado no seu Postgres
```sql
CREATE DATABASE password;
```

### 2. Publicar a imagem no ghcr.io
**Opção A — GitHub Actions:** coloque este `server/` num repo (com `.github/workflows/deploy.yml`) e dê push na `main`.

**Opção B — manual (precisa de um token do GitHub com `write:packages`):**
```bash
echo SEU_TOKEN | docker login ghcr.io -u caiosantosxp --password-stdin
docker build -t ghcr.io/caiosantosxp/meuconfre-server:latest .
docker push ghcr.io/caiosantosxp/meuconfre-server:latest
```

### 3. Deploy no Portainer
Stacks → Add stack → Web editor → cole o `stack.yml` → preencha as Environment variables:
- `DATABASE_URL=postgres://postgres:SENHA@HOST:5432/password`
- `JWT_SECRET=` (gere: `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`)
- `PGSSL=false` (ou `true` se exigir SSL)
- `ALLOW_REGISTRATION=true`
→ Deploy.

> Se o Postgres estiver em outra rede overlay do swarm, descomente o bloco de rede no `stack.yml`.

### 4. Testar
```bash
curl https://password.desbug.pro/api/health      # {"ok":true,...}
```

### 5. Criar sua conta e travar o registro
- Faça o registro pelo app (ou curl `POST /api/register`).
- Depois mude `ALLOW_REGISTRATION=false` e redeploy (ninguém mais cria conta).

## Segurança
- Senha de login: hash scrypt + salt. Cofre: cifrado no cliente (AES-256-GCM/PBKDF2).
- Mesmo um vazamento do Postgres **não** revela suas senhas (estão cifradas com a chave-mestra, que o servidor nunca recebe).
