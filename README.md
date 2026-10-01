# CommitKube

Plataforma DevOps que cobre o ciclo inteiro de um serviço no Kubernetes: cria o
repositório e a pipeline, registra no ArgoCD, e depois monitora o que subiu —
uptime, recursos, vulnerabilidades e as dependências entre os serviços.

Roda em um único container, sem Prometheus, sem OpenTelemetry e sem agente
dentro das suas aplicações.

## O que faz

### Provisionamento

- Cria repositórios no Bitbucket com estrutura padronizada
- Gera e commita `bitbucket-pipelines.yml` e os manifests Kubernetes
- Registra o repositório no ArgoCD e cria a Application para sync automático
- Suporte a branch de trabalho separada da `main`
- **Golden paths** — formulários que geram um serviço novo já dentro do padrão
- Templates YAML reutilizáveis por workspace/projeto
- Variáveis globais e por projeto injetadas nos templates

### Kubernetes e observabilidade

- **Service Map** — descobre automaticamente quais serviços conversam entre si,
  lendo o que o próprio cluster declara: selectors de Service, env vars e
  ConfigMaps que citam um Service, backends de Ingress, peers de NetworkPolicy
  e gateways do Istio. Nenhuma instrumentação, nenhum agente, nenhum cadastro
  manual. São dependências *declaradas*, não tráfego medido
- **Uptime e histórico de mudanças** por workload, amostrados da API `apps` do
  Kubernetes. Workload escalado a zero conta como desligado, não como queda
- **Métricas de pod** (CPU, memória, throttling de CFS) vindas do
  `metrics.k8s.io` e do cadvisor de cada kubelet
- **Problemas de pod** com ciclo de vida — OOMKilled, CrashLoopBackOff,
  unschedulable: abrem uma vez, acumulam ocorrências e fecham quando passam
- Nodes: capacidade, condições e alertas
- Navegador de recursos: Deployments, ReplicaSets, DaemonSets, StatefulSets,
  Pods, Services, Ingresses, PVCs, Namespaces — com o manifest de cada um
- Logs de container, com streaming ao vivo
- Restart, scale e delete de pods direto da interface

### Entrega (DORA)

As quatro métricas de DORA, medidas pelo cluster e não pela pipeline. **Um
deploy é uma imagem que passou a rodar** — então uma pipeline que passou sem
trocar a imagem não é um deploy, e uma imagem trocada na mão é.

- **Deployment frequency** — contagem dos `image_change` observados nos
  workloads
- **Lead time for changes** — do commit até a imagem rodando. O commit é lido
  da tag da imagem (`api:abc1234`, `api:main-abc1234`, `api:1.4.2-deadbeef`) e
  conferido contra o histórico do repositório. Um deploy cujo commit não
  resolve fica **fora da mediana** e aparece na cobertura, com o motivo; nunca
  recebe um lead time chutado
- **Change failure rate** — um deploy é falho se, na janela seguinte, o mesmo
  workload abre problema, degrada ou sofre rollback. Problemas que o Triage
  atribuiu a uma **dependência não contam**: o outage de um terceiro não é
  falha de quem entregou, e a exclusão fica visível na tela
- **Failed deployment recovery** — de quando quebrou até o problema fechar, o
  workload voltar a healthy, ou a imagem antiga voltar

Sem instrumentação e sem depender do provedor de CI. Os deploys são guardados
por 180 dias, mais que os snapshots de workload, porque as faixas do DORA são
definidas sobre meses.

### Segurança

- Scan de vulnerabilidades com Trivy, com histórico e dashboard por repositório,
  e uma linha do tempo de quanto os achados de código e de imagem caíram
- Postura de segurança do cluster: 34 regras (RBAC, workloads, rede, secrets)
  avaliadas a cada 6 h e guardadas por um ano, com nota, regras que falham por
  severidade, os recursos que falham e como corrigir
- Uma deploy key SSH própria para cada repositório criado, a mesma registrada
  no ArgoCD; a chave privada é mostrada uma única vez na criação
- Secrets do cluster e ExternalSecrets, com o valor atrás de dupla checagem:
  re-confirmação da senha do próprio usuário e papel admin ou root
- Credenciais de registry (Docker Hub, ECR, GCR) cifradas em AES-GCM
- MFA obrigatório (TOTP) e controle de acesso por papel: root, admin, user
- Grupos de usuários com escopo por workspace
- Audit log de toda ação sensível

### Automação

- Review de código por IA (Claude) em arquivos e repositórios
- Webhooks de saída por evento
- Notificações por e-mail e webhook em eventos como workload degradado

## Tecnologias

| Camada | Tecnologia |
|---|---|
| Backend | Go + Fiber + GORM |
| Banco de dados | SQLite |
| Frontend | Next.js 14 (App Router) + TypeScript + Tailwind CSS |
| Proxy | nginx |
| Cluster | client-go (typed + dynamic), `metrics.k8s.io`, cadvisor |
| Infraestrutura | Docker (single container) |
| Autenticação | JWT + TOTP (MFA) |
| Criptografia | AES-256-GCM para credenciais em repouso |

## Arquitetura

Tudo em um único container:

```
[ Browser ] → nginx :80 → /api/* → Go (Fiber) :8080
                        → /*     → Next.js     :3000
```

Oito pollers rodam em background no processo Go: rescans de vulnerabilidade,
workloads (5 min), métricas de pod (2 min), alertas de node (5 min), o service
map (10 min), os erros de aplicação (2 min), a entrega (5 min) e a postura de
segurança (6 h).

## Rodando

```bash
docker run -d \
  --name commitkube \
  -p 80:80 \
  -v commitkube_data:/app/data \
  -e JWT_SECRET=$(openssl rand -hex 32) \
  -e ENCRYPTION_KEY=$(openssl rand -hex 32) \
  commitkube/commitkube:latest
```

Acesse `http://localhost`.

> `ENCRYPTION_KEY` não é opcional na prática: sem ela as credenciais do
> Bitbucket, do ArgoCD e dos registries são gravadas **em texto puro** no
> banco. E ela não pode ser trocada depois sem perder o que já foi cifrado —
> gere e guarde antes da primeira subida.

### Rodando dentro do cluster

Os módulos de Kubernetes precisam de permissão de leitura no cluster. Rodando
in-cluster, crie um ServiceAccount no namespace onde o CommitKube roda e ligue
nele um ClusterRole somente-leitura, depois aponte o Deployment para ele:

```bash
kubectl -n <seu-namespace> patch deploy commitkube \
  -p '{"spec":{"template":{"spec":{"serviceAccountName":"commitkube"}}}}'
```

O ClusterRole precisa de `get`/`list`/`watch` em: `pods`, `nodes`,
`namespaces`, `services`, `endpoints`, `persistentvolumeclaims`,
`resourcequotas`, `limitranges`, `configmaps` e `secrets` (core);
`deployments`, `replicasets`, `daemonsets`, `statefulsets` (apps);
`ingresses`, `ingressclasses`, `networkpolicies` (networking.k8s.io);
`cronjobs` e `jobs` (batch). Além disso: `pods/log` e `nodes/proxy` com `get`,
`pods` com `delete` e `*/scale` com `get`/`update` (restart e scale pela
página de Pods), e `metrics.k8s.io` com `get`/`list`.

Dá pra cortar o que você não quer: sem `configmaps` o service map perde a
maioria das arestas, sem `networkpolicies` perde as de permissão, sem
`nodes/proxy` perde a detecção de throttling de CPU, e sem `resourcequotas` o
painel de namespace omite as seções de quota.

Rodando fora do cluster, as permissões vêm do `KUBECONFIG` do usuário.

## Variáveis de ambiente

### Obrigatórias

| Variável | Descrição |
|---|---|
| `JWT_SECRET` | Assina os tokens JWT. O processo não sobe sem ela. Gere com `openssl rand -hex 32` |
| `ENCRYPTION_KEY` | Exatamente 64 caracteres hex (32 bytes). Sem ela, credenciais ficam em texto puro; malformada, o processo aborta |

### Opcionais

| Variável | Padrão | Descrição |
|---|---|---|
| `DB_PATH` | `/app/data/kubecommit.db` | Caminho do SQLite |
| `CORS_ORIGIN` | `*` | Origem permitida no CORS |
| `KUBECONFIG` | `~/.kube/config` | Só usado quando não há config in-cluster |
| `ADMIN_EMAIL` | `admin@commitkube.local` | E-mail do root criado no primeiro boot |
| `ADMIN_PASSWORD` | `admin123` | Senha desse root. **Defina em qualquer deploy real** |
| `ANTHROPIC_API_KEY` | — | Habilita o review por IA |
| `ANTHROPIC_REVIEW_MODEL` | `claude-haiku-4-5-20251001` | Modelo usado no review |
| `WORKLOAD_MONITORING_INTERVAL` | `5m` | Intervalo do poller de workloads |
| `WORKLOAD_RETENTION_DAYS` | `30` | Retenção de snapshots e eventos de workload |
| `POD_MONITORING_INTERVAL` | `2m` | Intervalo do poller de métricas de pod |
| `POD_RETENTION_DAYS` | `3` | Retenção das amostras de pod |
| `TOPOLOGY_INTERVAL` | `10m` | Intervalo da descoberta do service map |
| `TOPOLOGY_RETENTION_DAYS` | `7` | Quanto tempo uma dependência que sumiu continua no mapa |
| `DELIVERY_INTERVAL` | `5m` | Intervalo do poller de entrega (liga deploy a commit e liquida os resultados) |
| `DORA_FAILURE_WINDOW` | `1h` | Janela depois de um deploy em que um problema conta como falha da mudança |
| `DORA_RETENTION_DAYS` | `180` | Retenção dos deploys usados nas métricas de DORA |
| `POSTURE_INTERVAL` | `6h` | Intervalo da avaliação de postura de segurança do cluster |
| `POSTURE_RETENTION_DAYS` | `365` | Retenção das avaliações de postura |
| `SMTP_HOST` `SMTP_PORT` `SMTP_USER` `SMTP_PASS` `SMTP_FROM` | — | Fallback de SMTP, usado só quando não há configuração salva em **Settings** |

> Bitbucket, ArgoCD, registries e SMTP são configurados dentro da própria
> plataforma, em **Settings** — as variáveis acima existem apenas como
> alternativa para o envio de e-mail.

## Primeiro acesso

1. Acesse `http://localhost/login`
2. Entre com o root criado no primeiro boot — por padrão
   `admin@commitkube.local` / `admin123`, ou o que você definiu em
   `ADMIN_EMAIL` / `ADMIN_PASSWORD`
3. Você é redirecionado para `/setup`
4. Defina e-mail e senha próprios e configure o MFA num app autenticador
5. Escaneie o QR Code e confirme com o código de 6 dígitos

O root padrão só é criado quando a tabela de usuários está vazia, ou seja,
apenas na primeira subida com um banco novo.

## Persistência

Os dados ficam no volume Docker:

```bash
docker cp commitkube:/app/data/kubecommit.db ./backup.db
```

O banco guarda hashes de senha, seeds de MFA e credenciais cifradas — trate o
backup como um segredo, e note que ele só é recuperável com o mesmo
`ENCRYPTION_KEY`.

## Configuração inicial

Depois do primeiro login, em **Settings**:

1. **Workspace Bitbucket** — slug do workspace, project key e um App Password
   com leitura e escrita em repositórios
2. **Chave SSH** — gerada pela plataforma; adicione a pública nas SSH keys do
   Bitbucket
3. **ArgoCD** — URL e token da instância
4. **Registries** — credenciais usadas pelo scan de imagens
5. **SMTP** — para as notificações por e-mail

## Desenvolvimento

```bash
# backend
cd backend
JWT_SECRET=dev ENCRYPTION_KEY=$(openssl rand -hex 32) go run .

# frontend
cd frontend
npm install && npm run dev
```

Testes do backend precisam das duas variáveis, senão o pacote aborta na
inicialização:

```bash
cd backend
JWT_SECRET=test ENCRYPTION_KEY=$(openssl rand -hex 32) go test ./...
```
