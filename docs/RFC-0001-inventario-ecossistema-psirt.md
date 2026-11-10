# RFC-0001: Inventário de Ecossistema de Produtos para PSIRT

| Campo | Valor |
|---|---|
| **Status** | Rascunho para revisão |
| **Autor** | Vander (com apoio do Claude) |
| **Criada em** | 2026-11-10 |
| **Repositório** | `VanderElton/system-inventary` |
| **Versão do sistema descrita** | MVP 0.1 (PR #1) |

---

## 1. Resumo

Esta RFC descreve um sistema simples para mapear o ecossistema de desenvolvimento de cada produto da empresa. O mapa liga produtos, componentes, ferramentas e sistemas, plataformas de desenvolvimento e equipes responsáveis. Também guarda o SBOM de cada componente e cruza esses dados com bases públicas de vulnerabilidades.

O objetivo principal é responder rápido às perguntas do PSIRT (Product Security Incident Response Team) quando uma vulnerabilidade é divulgada:

1. **Essa vulnerabilidade nos afeta?**
2. **Em quais produtos e componentes, e em qual versão?**
3. **Quem precisa ser acionado?**
4. **Como a correção chega ao cliente, e a plataforma ainda tem suporte?**

## 2. Motivação

Hoje a informação para responder a esse tipo de incidente fica espalhada:

- **Repositórios e pipelines:** as dependências reais de cada componente.
- **Planilhas, wikis ou memória das equipes:** quem é dono de cada componente e de cada produto.
- **Ferramentas de CI/CD, registries e cloud:** quais ferramentas participam do build e da entrega.
- **Documentação dos fornecedores:** quando cada plataforma (Java, Node.js, Spring Boot, FreeRTOS…) perde suporte.

Quando sai uma CVE crítica, como Log4Shell (CVE-2021-44228), a equipe de PSIRT perde horas ou dias montando esse quadro à mão. O sistema proposto centraliza o modelo do ecossistema e o liga aos SBOMs, para que a resposta inicial saia em minutos.

## 3. Objetivos e não objetivos

### 3.1 Objetivos

- **O1:** Modelar o ecossistema de cada produto: componentes, ferramentas e sistemas, plataformas e equipes, além das relações entre eles.
- **O2:** Importar SBOMs nos formatos padrão de mercado (CycloneDX e SPDX) por componente, manualmente ou pelo pipeline de CI/CD.
- **O3:** Cruzar os pacotes dos SBOMs com bases de vulnerabilidades e com relatórios de scanners já usados (Trivy, Grype).
- **O4:** Oferecer uma busca de impacto única por CVE/GHSA, pacote, ferramenta ou plataforma.
- **O5:** Registrar a triagem do PSIRT para cada achado (afetado, não afetado, corrigido), no estilo VEX.
- **O6:** Evidenciar plataformas fora de suporte e a estratégia de atualização de cada produto.
- **O7:** Ser simples de operar: poucas dependências, banco em arquivo único e implantação em qualquer ambiente que rode um container.

### 3.2 Não objetivos (nesta versão)

- **Gerar SBOMs:** isso continua sendo papel das ferramentas de build (Syft, Trivy, cdxgen, plugins CycloneDX).
- **Substituir um scanner:** o sistema consome achados de scanners, mas não analisa binários nem código.
- **Gerenciar tickets:** a integração com Jira e similares fica para o futuro (ver seção 10).
- **Controle de acesso:** autenticação e perfis de acesso não existem no MVP (ver seção 8 e RNF-08).

## 4. Glossário

| Termo | Significado |
|---|---|
| **PSIRT** | Equipe que recebe, avalia e coordena a resposta a vulnerabilidades nos produtos da empresa. |
| **SBOM** | *Software Bill of Materials*: a lista de pacotes e bibliotecas que compõem um componente. |
| **CycloneDX / SPDX** | Formatos padrão de SBOM. O sistema aceita ambos em JSON. |
| **purl** | *Package URL*: identificador padrão de um pacote, como `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`. |
| **CPE** | *Common Platform Enumeration*: identificador usado pelo NVD para produtos comerciais. |
| **OSV.dev** | Base pública e gratuita de vulnerabilidades de código aberto, consultada por API. |
| **GHSA / CVE** | Identificadores de vulnerabilidade (GitHub Security Advisory e Common Vulnerabilities and Exposures). |
| **VEX** | *Vulnerability Exploitability eXchange*: declaração de se um produto é ou não afetado por uma vulnerabilidade. |
| **EOL** | *End of Life*: data em que uma plataforma deixa de receber correções. |
| **Achado** | Uma vulnerabilidade associada a um pacote de um componente ou a uma ferramenta específica. |

## 5. Arquitetura

### 5.1 Visão geral

```
            ┌────────────────────────────────────────────────────────────┐
 Navegador  │  Interface web (SPA em JavaScript puro, sem build)         │
  (PSIRT,   │  Painel · Busca de impacto · Vulnerabilidades · Cadastros  │
  equipes)  └──────────────────────────────┬─────────────────────────────┘
                                           │ HTTP/JSON
 Pipeline   ┌──────────────────────────────▼─────────────────────────────┐
 CI/CD ────▶│  API REST (FastAPI)                       app/main.py      │
 (curl)     │  ├─ Cadastros e vínculos                                   │
            │  ├─ Ingestão de SBOM ──────────────▶ app/sbom.py           │
            │  ├─ Cruzamento de vulnerabilidades ▶ app/vulns.py ─────────┼──▶ OSV.dev
            │  ├─ Busca de impacto e triagem                             │   (HTTPS)
            │  └─ Importação/exportação do inventário                    │
            └──────────────────────────────┬─────────────────────────────┘
                                           │ SQL
            ┌──────────────────────────────▼─────────────────────────────┐
            │  SQLite (arquivo único)                   app/db.py        │
            │  data/inventario.db  ou  $INVENTARIO_DB                    │
            └────────────────────────────────────────────────────────────┘
```

### 5.2 Componentes do software

| Módulo | Responsabilidade |
|---|---|
| `app/main.py` | API REST: cadastros genéricos, vínculos, visões agregadas (ecossistema, painel), busca de impacto, ingestão de SBOM e de relatórios, triagem, importação/exportação, entrega da interface. |
| `app/db.py` | Esquema SQLite, conexão, transações e migrações automáticas de colunas novas. |
| `app/sbom.py` | Leitura de CycloneDX JSON (inclusive componentes aninhados e vulnerabilidades/VEX embutidas) e SPDX JSON (excluindo o pacote raiz descrito pelo documento). Extrai nome, versão, purl, ecossistema e licença. |
| `app/vulns.py` | Cliente do OSV.dev (consulta em lote e por identificador), normalização de severidade, leitura de relatórios Trivy e Grype, casamento de pacotes com os afetados pelo OSV e classificação de versão. |
| `app/static/` | Interface web: `index.html`, `app.js` (roteamento por hash, telas, mapa do ecossistema em SVG) e `style.css` (tema claro e escuro). |
| `seed.py` | Carga dos dados de exemplo (`exemplos/`), com cruzamento opcional no OSV. |
| `tests/` | Testes automatizados com pytest. O OSV é simulado, então os testes não dependem de internet. |

### 5.3 Stack e decisões

| Decisão | Escolha | Motivo |
|---|---|---|
| Linguagem / framework | Python 3.11+ com FastAPI | Simples, documentação automática da API (`/docs`) e ecossistema forte de segurança. |
| Banco | SQLite em arquivo único | Sem servidor para operar; backup é copiar um arquivo; suficiente para o volume de um inventário corporativo. Migrável para PostgreSQL (ver seção 10). |
| SQL | SQL direto, sem ORM | Consultas de impacto com várias junções ficam explícitas e fáceis de auditar. |
| Interface | JavaScript puro, sem etapa de build | Nada para compilar e nenhuma dependência de front-end para manter. |
| Base de vulnerabilidades | OSV.dev | Gratuita, sem chave, consultável por purl e com cobertura ampla de ecossistemas de código aberto. |
| Dependências de execução | `fastapi`, `uvicorn`, `python-multipart` | Superfície de ataque e de manutenção mínima. |
| Implantação | Dockerfile, com volume em `/data` e porta via `PORT` | Roda em qualquer serviço de container (Render, Fly.io, Azure, AWS, Kubernetes). |

## 6. Modelo de dados

### 6.1 Diagrama de entidades

```
                      ┌──────────────┐
          ┌──────────▶│    Equipe    │◀───────────────┬─────────────────┐
          │ dona      └──────────────┘ dona           │ dona            │ dona
   ┌──────┴──────┐  N:N  ┌──────────────┐  1:N  ┌────┴────┐  1:N  ┌─────┴───┐
   │   Produto   │◀─────▶│  Componente  │──────▶│  SBOM   │──────▶│ Pacote  │
   └──┬───────┬──┘       └──┬────────┬──┘       └─────────┘       └────┬────┘
      │ N:N   │ N:N     N:N │        │ N:N                             │ 1:N
      │       │             │        │                            ┌────▼────┐   N:1  ┌─────────────────┐
      │       ▼             ▼        │                            │ Achado  │───────▶│ Vulnerabilidade │
      │   ┌────────────────────┐     │                            └────▲────┘        └─────────────────┘
      │   │    Plataforma      │◀──┐ │                                 │ 1:N
      │   └────────────────────┘   │ │                                 │
      │ N:N                    N:N │ ▼ N:N                             │
      └──────────────────────▶┌────┴───────────────┐───────────────────┘
                              │ Ferramenta/Sistema │  (achado direto em
                              └────────────────────┘   ferramenta com purl)
```

### 6.2 Entidades

| Tabela | Campos principais | Observações |
|---|---|---|
| `teams` | nome (único), e-mail, canal de chat, gestor, notas | Contatos que o PSIRT aciona. |
| `products` | nome, versão, descrição, equipe dona, criticidade, ciclo de vida, mecanismo de atualização | Único por nome + versão. |
| `components` | nome, versão, tipo, linguagem, repositório, equipe dona, mecanismo de atualização, notas | Pode pertencer a vários produtos. |
| `systems` | nome, categoria, fornecedor, versão, identificador (purl/CPE), URL, equipe dona, mecanismo de atualização | SCM, CI/CD, registries, cloud, bancos, scanners, comunicação. |
| `platforms` | nome, versão, tipo, fornecedor, **data de EOL**, **estratégia de atualização**, identificador, equipe dona | Runtime, framework, SO, RTOS/SDK, imagem base, toolchain, mobile. |
| `product_components` | produto, componente | Relação N:N. |
| `product_systems`, `component_systems` | + papel (ex.: "build e deploy") | Ferramentas usadas diretamente pelo produto ou por um componente. |
| `product_platforms`, `component_platforms`, `system_platforms` | + papel (ex.: "runtime") | Plataformas sobre as quais cada item é construído. |
| `sboms` | componente, formato, versão da especificação, arquivo, data, total de pacotes | O SBOM mais recente substitui o anterior. |
| `packages` | SBOM, componente, nome, versão, purl, ecossistema, licença | Indexado por nome, purl e componente. |
| `vulns` | id (CVE/GHSA/OSV), aliases, resumo, severidade, CVSS, publicação, URL, fonte | Uma linha por vulnerabilidade. |
| `findings` | vulnerabilidade, pacote **ou** ferramenta, versão corrigida, **status**, notas, fonte | Único por vulnerabilidade + pacote e por vulnerabilidade + ferramenta. |

### 6.3 Enumerações

- **Criticidade do produto:** baixa, média, alta, crítica.
- **Ciclo de vida:** em desenvolvimento, ativo, só manutenção, fim de vida.
- **Tipo de componente:** serviço/API, biblioteca, frontend web, app mobile, firmware, imagem de container, CLI/agente, outro.
- **Categoria de ferramenta:** SCM, CI/CD, build, registro de artefatos, cloud/infra, banco de dados, monitoramento, segurança, comunicação, outro.
- **Tipo de plataforma:** linguagem/runtime, framework, sistema operacional, imagem base, RTOS/SDK embarcado, plataforma mobile, banco de dados, build/toolchain, outro.
- **Mecanismo de atualização:** deploy contínuo (SaaS), nova imagem de container, pacote instalado pelo cliente, OTA (firmware), loja de apps, nova versão de biblioteca publicada, atualização manual em campo, sem atualização possível.
- **Severidade:** crítica, alta, média, baixa, desconhecida (normalizada a partir das fontes).
- **Status da triagem:** em análise, afetado, não afetado, corrigido. Os dois primeiros contam como "em aberto".

## 7. Descrição de funcionamento

### 7.1 Cadastro do ecossistema

O ecossistema pode ser montado de três formas:

1. **Pela interface:** cada tela de lista tem "+ Novo", e as telas de detalhe têm "+ vincular" para ligar componentes, ferramentas e plataformas.
2. **Por carga em massa (`POST /api/import`):** um JSON com equipes, plataformas, ferramentas, componentes e produtos referenciados por nome (formato em `exemplos/inventario-exemplo.json`). Reimportar o mesmo arquivo atualiza os registros sem duplicar.
3. **Pelo pipeline (`POST /api/sbom`):** ao enviar um SBOM com nome de componente, produto e equipe, os registros que não existem são criados automaticamente.

A tela de cada produto mostra o **mapa do ecossistema** em cinco colunas, ligadas por linhas: produto, componentes, plataformas, ferramentas e equipes. As ferramentas e plataformas herdadas dos componentes aparecem com a indicação "via <componente>".

### 7.2 Ingestão de SBOM

```
SBOM (JSON) ──▶ detecta formato ──▶ extrai pacotes ──▶ substitui SBOM anterior ──▶ reaplica triagem
                (bomFormat /        (nome, versão,      do componente               dos pacotes que
                 spdxVersion)        purl, licença)                                  continuam iguais
```

1. O formato é detectado pelo conteúdo: `bomFormat: "CycloneDX"` ou presença de `spdxVersion`. Qualquer outro conteúdo é recusado com erro 400.
2. **CycloneDX:** os componentes são lidos de forma recursiva, inclusive os aninhados. As vulnerabilidades embutidas e a análise VEX (`analysis.state`) viram achados com o status correspondente.
3. **SPDX:** os pacotes são lidos de `packages`, e o purl vem de `externalRefs`. O pacote raiz (o próprio componente, indicado por `DESCRIBES`) é descartado.
4. O ecossistema de cada pacote é derivado do tipo do purl (npm, PyPI, Maven, Go, crates.io, NuGet etc.).
5. O SBOM anterior do componente e seus pacotes são substituídos.
6. **Preservação da triagem:** os achados anteriores são reaplicados aos pacotes do novo SBOM que tenham o mesmo nome, versão e purl, mantendo status, notas e versão corrigida. Se um pacote mudou de versão, o achado antigo deixa de valer.

### 7.3 Cruzamento com vulnerabilidades

Há três fontes de achados:

| Fonte | Como funciona |
|---|---|
| **OSV.dev** (`POST /api/scan`) | Envia todos os pacotes (ou só os de um componente) em lotes de até 1000 consultas para `querybatch`, por purl ou por nome + ecossistema + versão. Ferramentas com purl no campo identificador também são consultadas. Para cada vulnerabilidade retornada, busca os detalhes, normaliza a severidade e registra a versão corrigida. |
| **Scanners** (`POST /api/components/{id}/report`) | Lê relatórios JSON do Trivy (`Results`) ou do Grype (`matches`) e associa cada achado ao pacote do SBOM pelo purl ou por nome + versão. Pacotes que não estão no SBOM são criados. |
| **SBOM CycloneDX com vulnerabilidades** | Achados e análise VEX embutidos no próprio SBOM. |

Um achado novo entra com status "em análise". Um achado que já existe mantém a triagem feita.

### 7.4 Busca de impacto ("Onde somos afetados?")

Uma única caixa de busca, presente em todas as telas, aceita:

| Entrada | Exemplo | O que retorna |
|---|---|---|
| Vulnerabilidade | `CVE-2021-44228`, `GHSA-jfh8-c2jp-5v3q` | Achados registrados (busca também nos aliases) |
| Pacote | `log4j-core`, `lodash@4.17.20`, `pkg:npm/lodash` | Pacotes nos SBOMs, componentes e produtos que os contêm, e vulnerabilidades em aberto |
| Ferramenta | `Jenkins` | Produtos e componentes que usam a ferramenta |
| Plataforma | `Spring Boot@2.7`, `Node.js` | Produtos, componentes e ferramentas que dependem dela, com EOL e estratégia de atualização |

O topo do resultado mostra um **resumo**: os produtos potencialmente afetados, as equipes a acionar e um atalho para mandar e-mail a todas.

**Consulta ao vivo de CVE.** Quando o identificador parece uma vulnerabilidade e não há achado local, o sistema consulta o OSV.dev na hora:

1. Busca o registro pelo identificador. Muitos registros de CVE no OSV trazem só faixas de commits Git, sem pacotes. Nesse caso o sistema segue os aliases (por exemplo, CVE-2021-44228 → GHSA-jfh8-c2jp-5v3q) até achar os pacotes afetados.
2. Seleciona no inventário os pacotes com o mesmo nome, filtrando por ecossistema. Quando o purl do inventário tem namespace (grupo Maven, escopo npm, módulo Go), exige as coordenadas completas, para não confundir artefatos homônimos.
3. Classifica a versão de cada pacote encontrado:
   - **Versão afetada:** a versão está na lista explícita do OSV ou dentro de uma faixa `introduced`/`fixed`/`last_affected`.
   - **Verificar versão:** não há dados suficientes, por exemplo sem versão ou sem faixas comparáveis.
   - **Versão não afetada:** a versão está fora de todas as faixas.
4. Mostra o resultado sem gravar nada. Um botão "Registrar N achado(s) para triagem" grava como "em análise" os pacotes afetados ou a verificar (`POST /api/vulns/{id}/register`).

### 7.5 Triagem (estilo VEX)

A tela **Vulnerabilidades**, assim como as telas de produto, componente e ferramenta, lista os achados com filtros por status e por severidade. Cada achado mostra:

- a vulnerabilidade, os aliases e o link para a fonte;
- onde ocorre: pacote e versão, componente e produtos;
- a versão corrigida, quando conhecida;
- a equipe responsável;
- o status e uma nota de justificativa, ambos editáveis na própria tabela.

Para um produto, a visão de achados inclui os dos seus componentes e os das ferramentas ligadas a ele, diretamente ou via componentes.

### 7.6 Plataformas e estratégia de atualização

Cada plataforma tem data de EOL e uma estratégia de atualização em texto livre, como "migrar para Spring Boot 3.x (exige Java 17)". O sistema classifica o suporte de cada plataforma:

| Selo | Regra |
|---|---|
| Fora de suporte | EOL anterior a hoje |
| Vence em N dias | EOL em até 180 dias |
| Vence em menos de 1 ano | EOL em até 365 dias |
| Suportada | EOL depois de 1 ano |
| EOL não informado | sem data cadastrada |

O painel mostra quantas plataformas estão fora de suporte ou vencendo em 6 meses. Também lista as que vencem em até 1 ano, com quantos produtos, componentes e ferramentas dependem de cada uma. Combinada com o **mecanismo de atualização** do produto e dos componentes (SaaS, container, OTA, loja de apps…), essa visão indica quanto custa levar uma correção até o cliente.

### 7.7 Painel

O painel reúne:

- os totais de produtos, componentes, ferramentas, equipes, plataformas e pacotes;
- as vulnerabilidades em aberto por severidade;
- as lacunas do inventário: componentes sem SBOM, itens sem equipe dona e plataformas fora de suporte ou vencendo;
- as plataformas que pedem atualização;
- as 10 vulnerabilidades em aberto mais relevantes, ordenadas por severidade e número de produtos afetados.

### 7.8 Integração com CI/CD

No fim do build, o pipeline gera o SBOM e o envia:

```bash
syft . -o cyclonedx-json > bom.json
curl -F file=@bom.json \
  "https://inventario.empresa/api/sbom?component=api-pagamentos&version=1.4.0&product=Portal%20do%20Cliente&team=Squad%20Pagamentos"
```

Opcionalmente, o pipeline também envia o relatório do scanner para `/api/components/{id}/report`, ou dispara `POST /api/scan?component_id={id}`.

### 7.9 API

A documentação interativa fica em `/docs` (OpenAPI). Rotas principais:

| Método e rota | Função |
|---|---|
| `GET/POST /api/e/{entidade}` | Lista ou cria equipes, produtos, componentes, ferramentas e plataformas |
| `GET/PUT/DELETE /api/e/{entidade}/{id}` | Lê, altera ou exclui um item |
| `POST/DELETE /api/e/{entidade}/{id}/links/{alvo}[/{alvo_id}]` | Cria ou remove vínculos (com papel) |
| `GET /api/ecosystem/product/{id}` | Ecossistema completo de um produto |
| `GET /api/ecosystem/component/{id}` | Detalhe de componente, com SBOM, pacotes, ferramentas e plataformas |
| `GET /api/system-detail/{id}`, `GET /api/platform-detail/{id}` | Quem usa cada ferramenta ou plataforma |
| `GET /api/stats` | Dados do painel |
| `GET /api/impact?q=` | Busca de impacto |
| `POST /api/vulns/{id}/register` | Registra os achados de uma consulta ao vivo no OSV |
| `POST /api/components/{id}/sbom` | Importa o SBOM de um componente |
| `POST /api/sbom?component=&version=&product=&team=` | Importação pelo CI/CD, criando registros se preciso |
| `POST /api/scan[?component_id=]` | Cruza os pacotes com o OSV.dev |
| `POST /api/components/{id}/report` | Importa um relatório Trivy ou Grype |
| `GET /api/findings?status=&severity=&product_id=&component_id=&system_id=` | Lista achados |
| `PATCH /api/findings/{id}` | Altera status e notas da triagem |
| `POST /api/import`, `GET /api/export` | Carga em massa e backup completo em JSON |

## 8. Requisitos

**Legenda de status:** ✅ implementado no MVP · 🟡 parcial · ⬜ planejado

### 8.1 Requisitos funcionais

| ID | Requisito | Status |
|---|---|---|
| **Cadastro e modelagem** | | |
| RF-01 | Cadastrar, editar e excluir equipes com e-mail, canal de chat e gestor. | ✅ |
| RF-02 | Cadastrar produtos com versão/linha, criticidade, ciclo de vida, equipe dona e mecanismo de atualização. | ✅ |
| RF-03 | Cadastrar componentes com tipo, versão, linguagem, repositório, equipe dona e mecanismo de atualização. Um componente pode pertencer a vários produtos. | ✅ |
| RF-04 | Cadastrar ferramentas e sistemas com categoria, fornecedor, versão, identificador purl/CPE e equipe dona. | ✅ |
| RF-05 | Cadastrar plataformas com tipo, versão, fornecedor, data de EOL, estratégia de atualização e equipe dona. | ✅ |
| RF-06 | Vincular ferramentas e plataformas a produtos, componentes e ferramentas, com papel descritivo. | ✅ |
| RF-07 | Exibir o mapa visual do ecossistema de cada produto, incluindo itens herdados dos componentes. | ✅ |
| RF-08 | Importar o inventário em massa por JSON referenciado por nomes, de forma idempotente. | ✅ |
| RF-09 | Exportar o inventário completo, com SBOMs, vulnerabilidades e triagem, em JSON. | ✅ |
| **SBOM** | | |
| RF-10 | Importar SBOM CycloneDX JSON (componentes aninhados, vulnerabilidades e VEX embutidos). | ✅ |
| RF-11 | Importar SBOM SPDX JSON (purl via `externalRefs`, sem o pacote raiz). | ✅ |
| RF-12 | Receber SBOM pelo CI/CD, criando componente, produto e equipe que não existam. | ✅ |
| RF-13 | Preservar a triagem ao reimportar o SBOM, para pacotes com o mesmo nome, versão e purl. | ✅ |
| RF-14 | Manter o histórico de versões de SBOM por componente e permitir comparar duas versões. | ⬜ |
| RF-15 | Aceitar SBOM em XML (CycloneDX) e tag-value (SPDX). | ⬜ |
| **Vulnerabilidades** | | |
| RF-16 | Cruzar todos os pacotes, ou os de um componente, com o OSV.dev. | ✅ |
| RF-17 | Cruzar ferramentas que tenham purl com o OSV.dev. | ✅ |
| RF-18 | Importar relatórios Trivy JSON e Grype JSON. | ✅ |
| RF-19 | Normalizar a severidade das diferentes fontes para uma escala única. | ✅ |
| RF-20 | Cruzar ferramentas e plataformas comerciais via CPE no NVD. | ⬜ |
| RF-21 | Cruzar plataformas que tenham purl com o OSV.dev. | ⬜ |
| RF-22 | Priorizar com CISA KEV e EPSS (exploração conhecida e probabilidade de exploração). | ⬜ |
| RF-23 | Reconsultar as fontes periodicamente e avisar quando surgir uma vulnerabilidade crítica nova. | ⬜ |
| **Busca de impacto** | | |
| RF-24 | Buscar por CVE/GHSA (inclusive aliases), pacote (nome, `nome@versão` ou purl), ferramenta e plataforma. | ✅ |
| RF-25 | Resumir os produtos afetados e as equipes a acionar, com atalho de e-mail. | ✅ |
| RF-26 | Consultar uma CVE ainda não registrada direto no OSV.dev, seguindo aliases, e classificar a versão de cada pacote do inventário. | ✅ |
| RF-27 | Exigir as coordenadas completas (grupo, escopo ou namespace) ao casar pacotes com o OSV. | ✅ |
| RF-28 | Registrar para triagem os achados de uma consulta ao vivo. | ✅ |
| **Triagem** | | |
| RF-29 | Alterar o status (em análise, afetado, não afetado, corrigido) e a nota de cada achado. | ✅ |
| RF-30 | Filtrar achados por status, severidade, produto, componente e ferramenta. | ✅ |
| RF-31 | Incluir na visão do produto os achados das ferramentas ligadas a ele, direta ou indiretamente. | ✅ |
| RF-32 | Exportar a triagem como documento VEX (CycloneDX VEX ou OpenVEX) por produto. | ⬜ |
| RF-33 | Registrar o histórico de alterações da triagem (quem, quando, de qual para qual status). | ⬜ |
| RF-34 | Abrir tickets (ex.: Jira) para as equipes a partir de um achado ou de uma busca de impacto. | ⬜ |
| **Plataformas e atualização** | | |
| RF-35 | Classificar automaticamente o suporte de cada plataforma pela data de EOL. | ✅ |
| RF-36 | Exibir no painel as plataformas vencidas ou vencendo, com o número de dependentes. | ✅ |
| RF-37 | Mostrar no produto as plataformas diretas e herdadas, com estratégia de atualização e mecanismo de entrega. | ✅ |
| RF-38 | Preencher datas de EOL automaticamente a partir de uma fonte pública (ex.: endoflife.date). | ⬜ |

### 8.2 Requisitos não funcionais

| ID | Categoria | Requisito | Status |
|---|---|---|---|
| RNF-01 | Simplicidade | Rodar com só três dependências de execução (`fastapi`, `uvicorn`, `python-multipart`) e banco em arquivo único. | ✅ |
| RNF-02 | Portabilidade | Rodar em qualquer ambiente com Python 3.11+ ou container, com o caminho do banco configurável (`INVENTARIO_DB`) e a porta via `PORT`. | ✅ |
| RNF-03 | Persistência | Guardar todos os dados em um único arquivo SQLite, com integridade referencial (`foreign_keys = ON`) e operações em transação. | ✅ |
| RNF-04 | Evolução do esquema | Aplicar migrações de colunas novas automaticamente na inicialização, sem perder dados. | ✅ |
| RNF-05 | Interoperabilidade | Usar formatos abertos (CycloneDX, SPDX, purl, OSV) e uma API REST documentada em OpenAPI (`/docs`). | ✅ |
| RNF-06 | Testabilidade | Ter testes automatizados que rodam sem internet (OSV simulado). Hoje são 17 testes. | ✅ |
| RNF-07 | Usabilidade | Interface em pt-BR, com tema claro e escuro, e a busca de impacto acessível em todas as telas. | ✅ |
| RNF-08 | Segurança: acesso | Exigir autenticação via SSO/OIDC, com perfis (leitura, edição, PSIRT, administrador). Até lá, publicar só atrás de proxy com SSO ou VPN. | ⬜ |
| RNF-09 | Segurança: entrada | Escapar todo conteúdo exibido na interface (proteção contra XSS), usar SQL parametrizado e validar entidades e status contra listas fixas. | ✅ |
| RNF-10 | Segurança: integração | Exigir token por pipeline nas rotas de ingestão (`/api/sbom`, `/report`). | ⬜ |
| RNF-11 | Segurança: auditoria | Registrar quem alterou cada item e cada triagem. | ⬜ |
| RNF-12 | Resiliência | Mostrar mensagem clara e alternativa (importar relatório Trivy/Grype) quando o OSV.dev estiver inacessível. | ✅ |
| RNF-13 | Desempenho | Responder à busca de impacto em menos de 2 s para um inventário de até 100 mil pacotes. É uma meta e ainda não foi medida. | ⬜ |
| RNF-14 | Escalabilidade | Permitir trocar o SQLite por PostgreSQL quando houver várias instâncias ou escrita concorrente intensa. | ⬜ |
| RNF-15 | Backup | Permitir backup completo por cópia do arquivo do banco ou por `GET /api/export`. | ✅ |
| RNF-16 | Privacidade | Não enviar dados do inventário a terceiros além dos identificadores de pacote consultados no OSV.dev. | ✅ |

## 9. Segurança e riscos

| Risco | Impacto | Mitigação atual | Mitigação proposta |
|---|---|---|---|
| Acesso não autorizado (o MVP não tem login) | Exposição do mapa de dependências e das vulnerabilidades em aberto, informação sensível | Publicar só atrás de VPN ou proxy com SSO (Cloudflare Access, OAuth2 Proxy, IAP) | RNF-08 e RNF-10 |
| Falso negativo na classificação de versão | Produto afetado marcado como "não afetado" | A comparação é numérica e conservadora, e casos sem dados ficam como "verificar" | Comparação de versão específica por ecossistema (Maven, semver, PEP 440, Debian) |
| Falso positivo por pacote homônimo | Ruído na triagem | Casamento por coordenadas completas quando o purl tem namespace | Manter |
| SBOM incompleto ou desatualizado | Vulnerabilidade não detectada | O painel mostra componentes sem SBOM | Alertar sobre SBOM antigo e exigir SBOM no pipeline |
| Indisponibilidade do OSV.dev | Sem cruzamento novo | Mensagem de erro e importação de relatórios de scanner | Cache local e espelho do banco OSV |
| Escrita concorrente no SQLite | Bloqueios em uso intenso | Volume baixo esperado | RNF-14 (PostgreSQL) |

## 10. Limitações conhecidas e próximos passos

**Limitações atuais:**

- Não há autenticação nem trilha de auditoria.
- A comparação de faixas de versão é genérica, e não específica por ecossistema.
- Ferramentas e plataformas comerciais sem purl não são cruzadas com vulnerabilidades (falta NVD/CPE).
- Só o SBOM mais recente de cada componente é mantido.
- O cruzamento com o OSV é disparado manualmente ou pelo pipeline, sem agendamento.

**Roadmap sugerido, por prioridade:**

1. Autenticação por SSO/OIDC, tokens para o CI/CD e auditoria da triagem (RNF-08, RNF-10, RNF-11, RF-33).
2. Cruzamento agendado com alertas de vulnerabilidades críticas novas (RF-23), priorizado por KEV e EPSS (RF-22).
3. Exportação de VEX por produto (RF-32) e integração com tickets (RF-34).
4. NVD/CPE para ferramentas e plataformas comerciais (RF-20, RF-21) e datas de EOL automáticas (RF-38).
5. Histórico e comparação de SBOMs (RF-14) e migração para PostgreSQL quando o volume pedir (RNF-14).

## 11. Questões em aberto

1. **Login:** qual provedor de identidade a empresa usa (Azure AD/Entra, Okta, Google)? Isso define a implementação do RNF-08.
2. **Hospedagem:** em qual ambiente o sistema será publicado (cloud corporativa, Kubernetes interno)? Há exigência de residência de dados?
3. **Fontes oficiais:** existe uma CMDB ou um catálogo de serviços (Backstage, ServiceNow) que deva ser a fonte oficial de produtos e equipes, com sincronização em vez de cadastro manual?
4. **Fluxo do PSIRT:** a triagem precisa de aprovação, por exemplo um "não afetado" validado pelo PSIRT antes de valer?
5. **Clientes:** a exportação VEX será entregue a clientes? Nesse caso, qual formato eles esperam?

## 12. Referências

- CycloneDX: https://cyclonedx.org/specification/overview/
- SPDX: https://spdx.dev/
- Package URL (purl): https://github.com/package-url/purl-spec
- OSV.dev e a API: https://google.github.io/osv.dev/
- CISA, sobre VEX: https://www.cisa.gov/sbom
- endoflife.date: https://endoflife.date/
- Repositório: `README.md` (instalação, Docker, integração com CI/CD) e `exemplos/` (inventário e SBOMs de exemplo).
