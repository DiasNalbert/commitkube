# CommitKube

Plataforma de automação DevOps que integra Bitbucket e ArgoCD para criar e gerenciar repositórios, pipelines e deploys no Kubernetes de forma padronizada e centralizada.

## O que faz

- Cria repositórios no Bitbucket automaticamente com estrutura padronizada
- Gera e commita arquivos de pipeline (`bitbucket-pipelines.yml`) e manifests Kubernetes
- Registra o repositório no ArgoCD e cria a Application para sync automático com o cluster
- Suporte a branch adicional de trabalho separada da `main`
- Gerenciamento de templates YAML reutilizáveis por workspace/projeto
- Variáveis globais e por projeto injetadas automaticamente nos templates
- Autenticação com MFA obrigatório e controle de acesso por papel (root, admin, user)

## Tecnologias

| Camada | Tecnologia |
|---|---|
| Backend | Go + Fiber + GORM |
| Banco de dados | SQLite |
| Frontend | Next.js 14 (App Router) + TypeScript + Tailwind CSS |
| Proxy | nginx |
| Infraestrutura | Docker (single container) |
| Autenticação | JWT + TOTP (MFA) |

## Arquitetura

Tudo roda em um único container Docker:

```
[ Browser ] → nginx :80 → /api/* → Go (Fiber) :8080
                        → /*     → Next.js     :3000
```

## Rodando

```bash
docker run -d \
  --name commitkube \
  -p 80:80 \
  -v commitkube_data:/app/data \
  -e JWT_SECRET=$(openssl rand -hex 32) \
  commitkube/commitkube:latest
```

Acesse: `http://localhost`

## Variáveis de ambiente

| Variável | Obrigatória | Descrição |
|---|---|---|
| `JWT_SECRET` | **Sim** | Chave secreta para assinar os tokens JWT. Gere com `openssl rand -hex 32` |
| `DB_PATH` | Não | Caminho do banco SQLite (padrão: `/app/data/kubecommit.db`) |
| `CORS_ORIGIN` | Não | Origem permitida no CORS (padrão: `*`) |

> Bitbucket e ArgoCD são configurados dentro da própria plataforma em **Settings**.

## Primeiro acesso

1. Acesse `http://localhost/login`
2. Entre com `admin` / `admin`
3. Você será redirecionado para `/setup`
4. Defina seu e-mail, senha e configure o MFA com um app autenticador (Google Authenticator, Authy, etc.)
5. Escaneie o QR Code e confirme com o código de 6 dígitos
6. Pronto — você está logado como usuário **root**

## Persistência de dados

Os dados ficam no volume Docker. Para backup:

```bash
docker cp commitkube:/app/data/kubecommit.db ./backup.db
```

## Configuração inicial

Após o primeiro login, acesse **Settings** para configurar:

1. **Workspace Bitbucket** — slug do workspace, project key e App Password com permissões de leitura/escrita em repositórios
2. **Chave SSH** — gerada automaticamente pela plataforma; adicione a chave pública nas SSH keys do Bitbucket
3. **ArgoCD** — URL e token da instância para sync automático com o cluster Kubernetes
