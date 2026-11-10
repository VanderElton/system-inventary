# Inventário de Ecossistema de Produtos (PSIRT)

Plataforma simples para modelar o ecossistema de desenvolvimento de cada produto
(componentes, ferramentas/sistemas e equipes responsáveis), importar o SBOM de cada
componente e cruzar com vulnerabilidades, para responder rápido à pergunta do PSIRT:
**"essa vulnerabilidade nos afeta? Em qual produto? Quem eu aciono?"**

- **Stack:** Python 3.11+ · FastAPI · SQLite (um único arquivo) · interface em JavaScript puro (sem build).
- **Dependências de runtime:** só `fastapi`, `uvicorn` e `python-multipart`.

> Arquitetura, funcionamento e requisitos detalhados: [RFC-0001](docs/RFC-0001-inventario-ecossistema-psirt.md).

## Modelo de dados

```
Equipe ──dona de──▶ Produto ◀──N:N──▶ Componente ──1:N──▶ SBOM ──1:N──▶ Pacote ──▶ Achado ◀── Vulnerabilidade
   │                  │  │                │  │                                       ▲
   │                  │  └──▶ Plataforma ◀┘  └── (papel: código-fonte, build, deploy...) │
   │                  │       (runtime, framework, SO, RTOS, imagem base;              │
   │                  │        fim de suporte + estratégia de atualização)             │
   └──dona de──▶ Ferramenta/Sistema ──▶ Plataforma                                     │
                       └──────────── identificador purl/CPE ──────────────────────────┘
```

| Entidade | O que guarda |
|---|---|
| `teams` | Equipe, e-mail, canal de chat, gestor |
| `products` | Produto/linha, versão, criticidade, ciclo de vida, equipe dona, **mecanismo de atualização** (SaaS, container, OTA, loja de apps, instalado pelo cliente…) |
| `components` | Serviço, frontend, app, firmware, biblioteca, imagem… (pode ser compartilhado entre produtos) |
| `systems` | Ferramentas do ecossistema: SCM, CI/CD, registries, cloud, bancos, scanners… com purl/CPE opcional |
| `platforms` | Plataforma de desenvolvimento/execução (Java 17, Spring Boot 2.7, Node.js 18, FreeRTOS, Ubuntu 22.04…): tipo, **fim de suporte (EOL)** e **estratégia de atualização** |
| `product_components`, `product_systems`, `component_systems`, `*_platforms` | Relacionamentos, com o **papel** (build, deploy, execução, runtime, framework…) |
| `sboms`, `packages` | SBOM atual de cada componente e seus pacotes (nome, versão, purl, ecossistema, licença) |
| `vulns`, `findings` | Vulnerabilidades e achados por pacote/ferramenta, com **triagem estilo VEX** (em análise, afetado, não afetado, corrigido) |

## Funcionalidades

- Cadastro de produtos, componentes, ferramentas/sistemas e equipes, com **mapa visual do ecossistema** por produto.
- **Plataformas e estratégia de atualização:** cada produto, componente ou ferramenta é ligado às plataformas sobre as quais
  é construído, e cada um registra como as correções chegam ao cliente (deploy contínuo, nova imagem, OTA, loja de apps,
  pacote instalado pelo cliente…). O painel destaca plataformas fora de suporte ou vencendo e quantos produtos dependem delas;
  a busca de impacto também encontra plataformas (`Spring Boot@2.7`, `Node.js`).
- **Importação de SBOM** CycloneDX JSON e SPDX JSON por componente (upload na tela ou via API no pipeline).
  Vulnerabilidades/VEX embutidas no CycloneDX também são importadas.
- **Cruzamento com o [OSV.dev](https://osv.dev)** (gratuito, sem chave): verifica todos os pacotes dos SBOMs e as ferramentas com purl.
- **Importação de relatórios Trivy e Grype** (JSON), para quem já roda scanner no CI.
- **Busca de impacto** (`Onde somos afetados?`): por CVE/GHSA, pacote (`log4j-core@2.14.1`, `pkg:npm/lodash`) ou ferramenta (`Jenkins`).
  Se a CVE ainda não estiver registrada, a busca consulta o OSV.dev na hora, cruza os pacotes afetados com os SBOMs,
  classifica cada versão (afetada / verificar / não afetada) e permite registrar os achados para triagem.
- Resumo de produtos afetados e **equipes a acionar**, com atalho de e-mail.
- Triagem dos achados com status e notas, que **sobrevive à reimportação do SBOM** (se o pacote+versão continuar presente).
- Carga em massa do inventário via JSON e exportação completa (backup).

## Rodando

### Local

```bash
pip install -r requirements.txt
python seed.py --scan        # opcional: dados de exemplo (+ consulta ao OSV.dev)
uvicorn app.main:app --reload
# abra http://localhost:8000  ·  documentação da API em http://localhost:8000/docs
```

O banco fica em `data/inventario.db` (altere com a variável `INVENTARIO_DB`).

### Docker / nuvem

```bash
docker build -t inventario-psirt .
docker run -p 8000:8000 -v inventario-data:/data inventario-psirt
```

Funciona em qualquer serviço que rode um container com **disco persistente** montado em `/data`
(Render, Fly.io, Railway, Azure App Service, AWS ECS/App Runner, Kubernetes…). A porta respeita a variável `PORT`.

> ⚠️ O MVP **não tem autenticação**. Em nuvem, publique atrás de um proxy com SSO/VPN
> (ex.: Cloudflare Access, OAuth2 Proxy, IAP) até que a autenticação seja adicionada.

## Integração com CI/CD

Envie o SBOM ao final do build; o componente, o produto e a equipe são criados se não existirem:

```bash
syft . -o cyclonedx-json > bom.json   # ou trivy, cdxgen, plugins CycloneDX do Maven/Gradle/npm
curl -F file=@bom.json \
  "https://inventario.suaempresa/api/sbom?component=api-pagamentos&version=1.4.0&product=Portal%20do%20Cliente&team=Squad%20Pagamentos"
```

Outras rotas úteis: `POST /api/scan` (reconsulta o OSV), `GET /api/impact?q=CVE-...`,
`POST /api/vulns/{id}/register`, `POST /api/components/{id}/report` (Trivy/Grype), `POST /api/import`, `GET /api/export`.

## Carga do inventário

Veja o formato em [`exemplos/inventario-exemplo.json`](exemplos/inventario-exemplo.json): equipes, ferramentas,
componentes e produtos referenciados por nome. Reimportar atualiza sem duplicar.
SBOMs de exemplo em [`exemplos/sboms/`](exemplos/sboms/).

## Testes

```bash
pip install -r requirements-dev.txt
pytest
```

Os testes não acessam a internet (o OSV.dev é simulado).

## Próximos passos sugeridos

- Autenticação (SSO/OIDC) e trilha de auditoria da triagem.
- Atualização periódica automática (`POST /api/scan` agendado) e alerta para novas vulnerabilidades críticas.
- Fontes adicionais: NVD/CPE para ferramentas comerciais, CISA KEV e EPSS para priorização.
- Exportação de VEX (CycloneDX/OpenVEX) por produto a partir da triagem.
- Comparação de versões específica por ecossistema (hoje a classificação de faixas é numérica e marca "verificar" quando não há dados).
