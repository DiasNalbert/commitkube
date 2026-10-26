# CommitKube

Plataforma DevOps e de segurança para quem roda serviços no Kubernetes. Cria o
repositório e a pipeline, registra no ArgoCD e depois acompanha o que subiu:
saúde e recursos dos workloads, erros de aplicação, vulnerabilidades, postura
do cluster, métricas de entrega (DORA) e a borda na Cloudflare. Inclui um vault
com criptografia ponta a ponta e controle de acesso por permissão.

Roda em um único container, sem Prometheus, sem OpenTelemetry e sem agente
dentro das suas aplicações.

## O que faz

### Repositórios e entrega

- **Criação de repositório** no Bitbucket com estrutura padronizada: commita
  `bitbucket-pipelines.yml`, manifests e templates, configura variáveis e
  pipelines, registra no ArgoCD e cria a Application
- **Uma deploy key SSH por repositório** (ed25519), a mesma registrada no
  ArgoCD. A chave privada é mostrada uma única vez na criação e guardada
  cifrada para clonar e escanear
- **Import** de um repositório ou de todos os repositórios de um projeto
- **Detalhe do repositório**: navegador de código com edição e commit,
  branches, commits, pipelines do Bitbucket (disparar, parar, ver steps e logs),
  scans e análise por IA
- **GitOps próprio**: um caminho de um repositório mantido aplicado num
  namespace, sem ArgoCD. A cada poucos minutos o CommitKube compara a branch
  com o cluster usando o dry-run do próprio API server (server-side apply),
  mostra o diff de cada objeto, aplica commits novos com auto-sync, desfaz
  edições manuais com self-heal e apaga o que saiu do Git com prune — só o
  que ele mesmo aplicou e que ainda carrega a marca da aplicação. Manifestos
  inválidos voltam com a mensagem do API server antes de qualquer escrita.
  Escopo desta versão: manifestos YAML puros e objetos dentro do namespace da
  aplicação (Kustomize, Helm e objetos de cluster ficam com quem instala a
  plataforma). A escrita é concedida namespace a namespace; a tela mostra o
  que falta e o RBAC exato. Um repositório novo pode nascer já com a
  aplicação, no lugar do ArgoCD
- **Templates** YAML por workspace ou projeto, com variáveis globais e por
  projeto (inclusive secured)
- **Golden paths**: um jeito pronto de criar um tipo de serviço. Cada um traz
  arquivos próprios (renderizados com Go templates: `{{.Name}}`,
  `{{.Namespace}}`, `{{.Inputs.campo}}`, `{{if .Inputs.expor}}`), perguntas com
  tipo, padrão e validação, e regras: namespaces permitidos (com curinga),
  labels obrigatórias e teto de CPU e memória por container. Os manifestos
  gerados são conferidos antes de qualquer coisa ser criada, e o que quebra a
  regra é recusado com o motivo por arquivo. Com aprovação manual, o pedido cai
  numa fila e é criado ao ser aprovado. Tem preview na própria tela
- **Entrega (DORA)**, medida pelo cluster e não pela pipeline. Um deploy é uma
  imagem que passou a rodar:
  - *Deployment frequency*: contagem de trocas de imagem nos workloads
  - *Lead time*: do commit até a imagem rodando. O commit é lido da tag
    (`api:abc1234`, `api:main-abc1234`, `api:1.4.2-deadbeef`) e conferido no
    histórico do repositório; o que não resolve fica fora da mediana, com o motivo
  - *Change failure rate*: o deploy é falho se o workload abre problema,
    degrada ou sofre rollback na janela seguinte. Problemas atribuídos a uma
    dependência não contam, e a exclusão fica visível
  - *Failed deployment recovery*: de quando quebrou até voltar ao normal

> **Provedores de SCM:** só o Bitbucket está implementado. GitHub e GitLab
> existem como esqueleto (*preview*) e respondem "not yet implemented".

### Kubernetes

- **Cluster Overview**: capacidade, alocável, requests e uso; o que está
  quebrado agora; onde o consumo se concentra
- **Navegador de recursos**: Deployments, ReplicaSets, DaemonSets,
  StatefulSets, Pods, Services, Ingresses, PVCs e Namespaces, com manifest e
  painel de detalhe (nunca serve o manifest de Secrets)
- **Pods**: CPU, memória e throttling de CFS (do `metrics.k8s.io` e do
  cadvisor de cada kubelet) com histórico; logs com streaming ao vivo;
  restart, scale e delete
- **Nodes**: condições, capacidade e os pods que mais consomem em cada um
- **Workloads**: uptime e histórico de mudanças, amostrados da API `apps`.
  Escalado a zero conta como desligado, não como queda
- **Triage**: problemas com ciclo de vida — abrem uma vez, acumulam
  ocorrências e fecham sozinhos:
  - de pod: OOMKilled, CrashLoopBackOff, image pull, config faltando,
    unschedulable, evicted, pressão de memória, throttling e saturação de CPU
  - de aplicação: respostas 5xx (do access log do ingress controller), erros
    no log dos containers agrupados por padrão, e falhas de dependência
- **Service Map**: quais serviços conversam entre si, lido do que o cluster
  declara — selectors de Service, env vars e ConfigMaps que citam um Service,
  backends de Ingress, NetworkPolicy e Istio. São dependências *declaradas*,
  não tráfego medido
- **Secrets**: lista nomes e chaves; revelar e editar valores exige
  reconfirmar a senha, ter a permissão correspondente e o namespace no escopo.
  Secrets gerenciados por ExternalSecrets e de sistema são sinalizados
- **Multi-cluster**: o cluster onde o CommitKube roda é registrado sozinho;
  outros são adicionados com API server, CA e token. Por cluster dá para ligar
  *impersonation* (as chamadas rodam com a identidade do usuário) e a gestão de
  RBAC pela plataforma

### Segurança

- **Code Security**: Trivy no código (vulnerabilidades, misconfiguração e
  segredos) com histórico, dashboard e linha do tempo. Segredos entram na
  contagem com arquivo e linha, nunca com o trecho que casou
- **Findings com identidade**: cada CVE, misconfiguração ou segredo é uma
  linha que sobrevive ao rescan — quando apareceu, quando sumiu, o que é novo
  desde o último scan e quantos foram resolvidos nos últimos 30 dias
- **Triagem**: um finding pode ser suprimido como falso positivo, não
  afetado, risco aceito ou correção planejada, por repositório ou global, por
  pacote ou qualquer, com motivo, autor e validade. Suprimido sai da contagem
  na hora, aparece separado no e-mail e exige `security.triage`
- **Container Security**: Trivy na imagem que está rodando; sem ela, na
  imagem base do Dockerfile. Base de vulnerabilidades atualizada de forma
  central e rescans automáticos
- **Workload Security**: riscos do spec dos pods — root, namespaces do host,
  capabilities perigosas, hostPath, ferramentas de download
- **Security Posture**: as 33 regras do padrão Security Essentials para
  Kubernetes (cada uma com o id DTSE correspondente) e 11 boas práticas com nota
  separada, avaliadas a cada 6 h e guardadas por um ano. Cada recurso que
  falha tem o comando que o corrige, gerado do objeto vivo: `kubectl patch`
  para workloads e a versão estreitada da Role para RBAC, conferidos pela
  própria regra antes de aparecer, com o que a mudança pode quebrar e o aviso
  quando o objeto é de um Helm, ArgoCD ou operador. Nada é aplicado pela tela
- **Review por IA** de um repositório inteiro (Claude, via `ANTHROPIC_API_KEY`)
- **Credenciais de registry** (genérico, ECR, GCR) cifradas, usadas no scan de
  imagens privadas

### Cloudflare

Monitoramento de segurança por zona, a partir do zone ID, account ID e um API
token da própria zona. O acesso é concedido no IAM, à parte da segurança:
`cloudflare.read` para ver e `cloudflare.manage` para gerenciar zonas e
tokens e disparar verificações. Root e admin têm as duas; o papel user não
vê a Cloudflare sem uma concessão:

- **Analytics**: requisições, ameaças mitigadas, 4xx/5xx, cache, tráfego
  automatizado; paths, hosts, países, IPs, métodos e user agents
- **Security**: o que foi bloqueado ou desafiado, por ação e por recurso (WAF,
  custom rules, rate limiting, DDoS L7…), IPs e paths atacados, regras que
  dispararam e *probing* — paths que scanners procuram (`.env`, `.git`,
  `wp-login`, credenciais de cloud, web shells)
- **Bots**: bot score quando o plano tem Bot Management; senão, classificação
  pelo user agent declarado
- **Mapa** de onde vêm as requisições e os ataques, com detalhamento por país
  (regiões e cidades; o Brasil com mapa por estado)
- **WAF rules**: as regras custom, de rate limiting e managed da zona, com
  quantos eventos cada uma pegou, e **sugestões** de regras com a expressão
  pronta, calculadas do tráfego malicioso real e descontando o que as regras
  atuais já cobrem. Nada é escrito na Cloudflare: a expressão é para copiar
- **Exposure**: o que fica exposto por baixo do proxy — origem acessível sem
  passar pela Cloudflare, portas abertas para a internet (via Shodan
  InternetDB, com um teste de conexão direto que fecha o alerta assim que a
  porta é bloqueada, sem esperar o InternetDB atualizar), CVEs, CNAMEs pendurados e risco de *subdomain takeover*,
  registros DNS-only e SPF/DMARC
- **Alertas**: DDoS L7, pico de ameaças, taxa de 5xx e pico de tráfego,
  avaliados a cada 5 min com limites por zona; cada exposição vira um alerta
  próprio que fecha sozinho quando some. Os alertas que a própria Cloudflare
  envia para a conta entram no mesmo log

Cada seção é uma consulta separada: um recurso que o plano da zona não tem
apaga só o card dele, com o motivo.

### Vault

Cofre de segredos com **criptografia ponta a ponta no navegador**: a senha é
derivada com Argon2id, um keyring P-256 (ECDH) embrulha as chaves dos cofres e
os itens são selados com AES-GCM. O servidor guarda só blobs selados. Acessar
material selado exige um segundo TOTP, separado do login. Tem cofres pessoais
e de time, com membros, papéis e acesso por grupo.

### Acesso e auditoria

- **MFA obrigatório** (TOTP) desde o primeiro acesso
- **Sessão que morre com o navegador**: o refresh token é um cookie httpOnly
  de sessão, guardado como hash no servidor, e o access token só existe na
  memória da página. Cada página valida a sessão no servidor antes de
  renderizar. A sessão expira por inatividade e por duração máxima, gira a
  cada uso (reuso de um token gasto encerra a sessão inteira) e é revogada no
  logout, na troca de senha, de papel ou de MFA
- **Permissões granulares** (29 concedíveis, de `k8s.read` a `audit.read`),
  liberadas ou negadas por usuário ou grupo, em cima dos papéis root, admin e
  user. `iam.manage` é exclusiva de root e há no máximo 2 contas root
- **Escopo de namespace** por cluster: quem tem escopo só vê os seus
- **RBAC do cluster** gerado pela plataforma: preview do YAML, ou aplicar
  direto onde o cluster permite
- Toda rota da API declara a permissão que exige, e o servidor **não sobe** se
  alguma esquecer
- **Audit log** de toda ação sensível

### Notificações

- Canais de **Microsoft Teams, webhook e e-mail**, cada um inscrito nos
  eventos que interessam: scans críticos, segredo vazado, workload degradado, node fora,
  problemas de pod e de aplicação, repositório criado ou removido, alertas da
  Cloudflare
- **Webhooks de saída** assinados com HMAC (`X-Hub-Signature-256`)

## Tecnologias

| Camada | Tecnologia |
|---|---|
| Backend | Go 1.22 + Fiber + GORM |
| Banco de dados | SQLite (WAL) |
| Frontend | Next.js 14 (App Router) + TypeScript + Tailwind CSS + Recharts |
| Vault | WebCrypto (P-256, AES-GCM) + Argon2id (hash-wasm) |
| Proxy | nginx |
| Cluster | client-go (typed + dynamic), `metrics.k8s.io`, cadvisor |
| Scans | Trivy |
| Autenticação | JWT + TOTP |
| Criptografia em repouso | AES-256-GCM |

## Arquitetura

```
[ Browser ] → nginx :80 → /api/* → Go (Fiber) :8080
                        → /*     → Next.js     :3000
```

Em background, no processo Go, rodam a atualização da base do Trivy, um pool de
workers de scan e dez pollers: rescans, workloads, métricas de pod, alertas de
node, service map, erros de aplicação, entrega, postura, Cloudflare e exposição
na Cloudflare.

## Rodando

### Um container

```bash
docker build -t commitkube .
docker run -d \
  --name commitkube \
  -p 80:80 \
  -v commitkube_data:/app/data \
  -e JWT_SECRET=$(openssl rand -hex 32) \
  -e ENCRYPTION_KEY=$(openssl rand -hex 32) \
  commitkube
```

Acesse `http://localhost`.

### docker compose

Backend e frontend em containers separados:

```bash
export JWT_SECRET=$(openssl rand -hex 32)
export ENCRYPTION_KEY=$(openssl rand -hex 32)
docker compose up -d --build
```

O frontend fica em `:3000` e a API em `:8080`. O compose recusa subir sem as
duas variáveis.

> `ENCRYPTION_KEY` não é opcional na prática: sem ela, as credenciais
> (Bitbucket, tokens do ArgoCD e da Cloudflare, registries, deploy keys) são
> gravadas **em texto puro** no banco. E ela não pode ser trocada depois sem
> perder o que já foi cifrado — gere e guarde antes da primeira subida.

### Rodando dentro do cluster

Os módulos de Kubernetes precisam de permissão no cluster. Rodando
in-cluster, crie um ServiceAccount no namespace do CommitKube, ligue nele um
ClusterRole e aponte o Deployment para ele:

```bash
kubectl -n <seu-namespace> patch deploy commitkube \
  -p '{"spec":{"template":{"spec":{"serviceAccountName":"commitkube"}}}}'
```

O ClusterRole precisa de `get`/`list`/`watch` em: `pods`, `nodes`,
`namespaces`, `services`, `endpoints`, `persistentvolumeclaims`,
`resourcequotas`, `limitranges`, `configmaps` e `secrets` (core);
`deployments`, `replicasets`, `daemonsets`, `statefulsets` (apps);
`ingresses`, `ingressclasses`, `networkpolicies` (networking.k8s.io);
`cronjobs` e `jobs` (batch). A postura de segurança precisa ainda de
`get`/`list` em `serviceaccounts` (core) e em `roles`, `clusterroles`,
`rolebindings` e `clusterrolebindings` (rbac.authorization.k8s.io) — sem elas
a avaliação falha inteira, em vez de reportar as regras de RBAC como aprovadas.
Além disso: `pods/log` e `nodes/proxy` com `get`; `secrets` com `update`
(editar valores; sem ela a página fica só leitura); `pods` com `delete` e
`*/scale` com `get`/`update` (restart e scale); e `metrics.k8s.io` com
`get`/`list`. Com impersonation ligada, o ServiceAccount precisa de
`impersonate` em users e groups; com a gestão de RBAC ligada, de escrita em
roles e bindings.

Dá para cortar o que você não quer: sem `configmaps` o service map perde a
maioria das arestas, sem `networkpolicies` perde as de permissão, sem
`nodes/proxy` perde a detecção de throttling de CPU, e sem `resourcequotas` o
painel de namespace omite as seções de quota.

Rodando fora do cluster, as permissões vêm do `KUBECONFIG`.

## Primeiro acesso

1. Acesse `/login` e entre com o root criado no primeiro boot — por padrão
   `admin@commitkube.local` / `admin123`, ou o que você definiu em
   `ADMIN_EMAIL` / `ADMIN_PASSWORD`
2. Em `/setup`, defina e-mail e senha próprios e configure o MFA num app
   autenticador

O root padrão só é criado quando a tabela de usuários está vazia.

## Configuração

Quase tudo é configurado dentro da plataforma.

**Profile** (`/profile`):

1. **Workspace do Bitbucket**: slug, project key, usuário e App Password ou API
   token. A credencial precisa de **Repositories: Read, Write e Admin** — Admin
   cria o repositório, mas não inclui escrita, e sem Write o primeiro commit
   falha. Para variáveis de pipeline, também **Pipelines** e **Variables**
2. **ArgoCD**: um admin cadastra a instância (URL, namespace e project
   padrão). **Cada pessoa cadastra o próprio token** da instância, que é
   conferido no ArgoCD antes de salvar; o CommitKube só fala com o ArgoCD como
   quem está agindo, nunca com uma conta compartilhada. Cada pessoa precisa de
   uma conta local no ArgoCD com capacidade `apiKey` e RBAC para registrar
   repositórios e criar e apagar Applications
3. **Registries**: credenciais para o scan de imagens privadas

**Settings** (`/settings`): SMTP e webhooks de saída.
**Notifications** (`/notifications`): canais e eventos.
**IAM** (`/iam`): usuários, grupos, permissões, escopos, clusters e RBAC.

**Cloudflare** (`/cloudflare`): cada zona com seu próprio API token.

| Permissão do token | Para quê |
|---|---|
| Zone › Zone: Read | obrigatória |
| Zone › Analytics: Read | obrigatória: analytics, mapa e alertas |
| Zone › WAF: Read | aba WAF rules e sugestões |
| Zone › DNS: Read | aba Exposure |
| Account › Notifications: Read | alertas enviados pela própria Cloudflare |

O botão *Test connection* diz qual delas está faltando.

## Variáveis de ambiente

### Obrigatórias

| Variável | Descrição |
|---|---|
| `JWT_SECRET` | Assina os tokens. O processo não sobe sem ela |
| `ENCRYPTION_KEY` | 64 caracteres hex (32 bytes). Sem ela, credenciais ficam em texto puro; malformada, o processo aborta |

### Gerais

| Variável | Padrão | Descrição |
|---|---|---|
| `DB_PATH` | `kubecommit.db` (o container usa `/app/data/kubecommit.db`) | Caminho do SQLite; o cache do Trivy fica ao lado |
| `CORS_ORIGIN` | `http://localhost:3000` | Origem permitida no CORS. Precisa ser explícita: a sessão é um cookie, e `*` não aceita credenciais |
| `ACCESS_TOKEN_TTL` | `10m` | Vida do access token |
| `SESSION_IDLE_TIMEOUT` | `20m` | Sessão sem uso por esse tempo exige login de novo |
| `SESSION_MAX_AGE` | `12h` | Duração máxima de uma sessão, mesmo em uso |
| `COOKIE_SECURE` | automático | Força o atributo `Secure` do cookie; por padrão segue o esquema da requisição (`X-Forwarded-Proto` atrás do nginx) |
| `KUBECONFIG` | `~/.kube/config` | Só usado fora do cluster |
| `DEFAULT_CLUSTER_NAME` | `in-cluster` | Nome do cluster onde o CommitKube roda |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | `admin@commitkube.local` / `admin123` | Root do primeiro boot. **Defina em qualquer deploy real** |
| `ANTHROPIC_API_KEY` | — | Habilita o review por IA |
| `ANTHROPIC_REVIEW_MODEL` | `claude-haiku-4-5-20251001` | Modelo do review |
| `SMTP_HOST` `SMTP_PORT` `SMTP_USER` `SMTP_PASS` `SMTP_FROM` | — | Fallback de SMTP quando não há configuração salva em Settings |
| `NEXT_PUBLIC_API_URL` | `/api` | URL da API vista pelo navegador (no build do frontend) |

### Intervalos dos pollers

| Variável | Padrão |
|---|---|
| `TRIVY_DB_INTERVAL` | `6h` |
| `RESCAN_INTERVAL` | `1h` |
| `GITOPS_INTERVAL` | `3m` |
| `WORKLOAD_MONITORING_INTERVAL` | `5m` |
| `POD_MONITORING_INTERVAL` | `2m` |
| `TOPOLOGY_INTERVAL` | `10m` |
| `APP_ERROR_INTERVAL` | `2m` |
| `DELIVERY_INTERVAL` | `5m` |
| `POSTURE_INTERVAL` | `6h` |
| `CLOUDFLARE_INTERVAL` | `5m` (mínimo 1m) |
| `CLOUDFLARE_EXPOSURE_INTERVAL` | `6h` (mínimo 10m) |

Os alertas de node rodam a cada 5 min, sem variável.

### Retenção (dias)

| Variável | Padrão |
|---|---|
| `WORKLOAD_RETENTION_DAYS` | `30` |
| `POD_RETENTION_DAYS` | `3` |
| `TOPOLOGY_RETENTION_DAYS` | `7` |
| `APP_ERROR_RETENTION_DAYS` | `3` |
| `DORA_RETENTION_DAYS` | `180` |
| `POSTURE_RETENTION_DAYS` | `365` |
| `CLOUDFLARE_ALERT_RETENTION_DAYS` | `90` |

### Scans

| Variável | Padrão | Descrição |
|---|---|---|
| `SCAN_WORKERS` | `2` | Scans em paralelo |
| `SCAN_QUEUE_DEPTH` | `500` | Tamanho da fila |
| `RESCAN_BATCH` | `20` | Repositórios por passada de rescan |
| `RESCAN_IMAGE_AGE` | `24h` | Idade a partir da qual a imagem é escaneada de novo |
| `RESCAN_FULL_AGE` | `168h` | Idade a partir da qual o código é escaneado de novo |
| `TRIVY_CACHE_DIR` | `<pasta do DB_PATH>/trivy-cache` | Cache compartilhado da base do Trivy |

### Ajuste fino

| Variável | Padrão | Descrição |
|---|---|---|
| `DORA_FAILURE_WINDOW` | `1h` | Janela depois de um deploy em que um problema conta como falha da mudança |
| `APP_ERROR_RATE_PCT` / `APP_ERROR_CRITICAL_PCT` | `5` / `20` | % de 5xx para abrir um problema de aplicação / para ele ser crítico |
| `APP_ERROR_MIN_REQUESTS` | `20` | Requisições mínimas na janela para calcular a taxa |
| `APP_ERROR_WINDOWS` | `3` | Janelas seguidas acima do limite para abrir o problema |
| `APP_ERROR_LOGS_PER_MIN` | `6` | Linhas de erro por minuto no log para abrir o problema |
| `APP_DEPENDENCY_MIN_FAILURES` | `5` | Falhas de dependência para atribuir a causa a ela |
| `APP_LOG_LIMIT_BYTES` / `APP_LOG_SCAN_MAX_PODS` | `8MiB` / `120` | Limites da leitura de logs por passada |
| `INGRESS_CONTROLLER_LABELS` | — | `k=v,k=v` para achar o ingress controller quando os labels não são os padrão |
| `CLOUDFLARE_EXPOSURE_INTERNETDB` | — | `false` desliga a consulta de portas no Shodan InternetDB |
| `CLOUDFLARE_EXPOSURE_PROBE` | — | `false` desliga o teste de conexão direto que confirma quando uma porta listada pelo InternetDB já foi fechada |

## Persistência

Os dados ficam no volume (`/app/data`):

```bash
docker cp commitkube:/app/data/kubecommit.db ./backup.db
```

O banco guarda hashes de senha, seeds de MFA e credenciais cifradas — trate o
backup como um segredo. Ele só é recuperável com o mesmo `ENCRYPTION_KEY`.

Por ser SQLite, rode **uma réplica só**: os pollers não têm eleição de líder,
e duas réplicas fariam o trabalho em dobro sobre arquivos diferentes.

## Desenvolvimento

```bash
# backend
cd backend
JWT_SECRET=dev ENCRYPTION_KEY=$(openssl rand -hex 32) go run .

# frontend
cd frontend
npm install && npm run dev
```

Testes e checagens:

```bash
cd backend
JWT_SECRET=test ENCRYPTION_KEY=$(openssl rand -hex 32) go test ./...

cd frontend
npx tsc --noEmit -p .
npm run lint
```

Os testes do backend precisam das duas variáveis, senão o pacote aborta na
inicialização.
