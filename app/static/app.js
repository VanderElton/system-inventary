// Inventário de Ecossistema (PSIRT) - SPA em JavaScript puro, sem build.
const $ = (s, el = document) => el.querySelector(s);
const main = $("#main");
const h = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const LABELS = {
  criticality: { baixa: "Baixa", media: "Média", alta: "Alta", critica: "Crítica" },
  lifecycle: { desenvolvimento: "Em desenvolvimento", ativo: "Ativo", manutencao: "Só manutenção", eol: "Fim de vida (EOL)" },
  type: { servico: "Serviço / API", biblioteca: "Biblioteca", frontend: "Frontend web", app_mobile: "App mobile", firmware: "Firmware", container: "Imagem de container", cli: "CLI / agente", outro: "Outro" },
  category: { scm: "Repositório de código (SCM)", ci_cd: "CI/CD", build: "Build / empacotamento", registro_artefatos: "Registro de artefatos", cloud_infra: "Cloud / infraestrutura", banco_dados: "Banco de dados", monitoramento: "Monitoramento / logs", seguranca: "Segurança (SAST/DAST/SCA)", comunicacao: "Comunicação / tickets", outro: "Outro" },
  status: { em_analise: "Em análise", afetado: "Afetado", nao_afetado: "Não afetado", corrigido: "Corrigido" },
  severity: { critica: "Crítica", alta: "Alta", media: "Média", baixa: "Baixa", desconhecida: "Desconhecida" },
};
const lbl = (k, v) => (LABELS[k] && LABELS[k][v]) || v || "";

const FORMS = {
  teams: { title: "Equipe", fields: [["name", "Nome *"], ["email", "E-mail"], ["chat", "Canal (Slack/Teams)"], ["manager", "Responsável / gestor"], ["notes", "Observações", "textarea"]] },
  products: { title: "Produto", fields: [["name", "Nome *"], ["version", "Versão / linha"], ["description", "Descrição", "textarea"], ["owner_team_id", "Equipe responsável", "team"], ["criticality", "Criticidade", "criticality"], ["lifecycle", "Ciclo de vida", "lifecycle"]] },
  components: { title: "Componente", fields: [["name", "Nome *"], ["version", "Versão"], ["type", "Tipo", "type"], ["language", "Linguagem / stack"], ["repo_url", "Repositório (URL)"], ["owner_team_id", "Equipe responsável", "team"], ["notes", "Observações", "textarea"]] },
  systems: { title: "Ferramenta / sistema", fields: [["name", "Nome *"], ["category", "Categoria", "category"], ["vendor", "Fornecedor"], ["version", "Versão"], ["identifier", "Identificador (purl ou CPE) para cruzar com vulnerabilidades"], ["url", "URL"], ["owner_team_id", "Equipe responsável", "team"], ["notes", "Observações", "textarea"]] },
};

// ------------------------------------------------------------------ utilitários
async function api(path, opts = {}) {
  const o = { ...opts };
  if (o.json !== undefined) { o.body = JSON.stringify(o.json); o.headers = { "Content-Type": "application/json" }; delete o.json; }
  const r = await fetch(path, o);
  const data = r.headers.get("content-type")?.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.detail) || r.statusText);
  return data;
}
function toast(msg, ms = 3500) { const t = $("#toast"); t.textContent = msg; t.style.display = "block"; clearTimeout(t._t); t._t = setTimeout(() => (t.style.display = "none"), ms); }
const sev = (s) => `<span class="sev sev-${h(s || "desconhecida")}">${h(lbl("severity", s || "desconhecida"))}</span>`;
const team = (name) => (name ? `<span class="chip">👥 ${h(name)}</span>` : `<span class="muted small">sem dono</span>`);
const chips = (csv) => (csv ? csv.split(", ").map((x) => `<span class="chip">${h(x)}</span>`).join("") : "");
const sevSummary = (m = {}) => ["critica", "alta", "media", "baixa", "desconhecida"].filter((k) => m[k]).map((k) => `${sev(k)} ${m[k]}`).join(" ") || '<span class="muted small">—</span>';
const fmtDate = (s) => (s ? s.replace("T", " ").slice(0, 16) : "");
let TEAMS = [];
async function loadTeams() { TEAMS = await api("/api/e/teams"); }

function table(cols, rows, empty = "Nada cadastrado ainda.") {
  if (!rows.length) return `<div class="panel muted">${empty}</div>`;
  return `<div class="tw"><table><thead><tr>${cols.map((c) => `<th>${c[0]}</th>`).join("")}</tr></thead><tbody>${rows
    .map((r) => `<tr>${cols.map((c) => `<td>${c[1](r)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

function fieldHtml([key, label, kind], val) {
  val = val ?? "";
  if (kind === "textarea") return `<label>${label}<textarea name="${key}">${h(val)}</textarea></label>`;
  if (kind === "team") return `<label>${label}<select name="${key}"><option value="">—</option>${TEAMS.map((t) => `<option value="${t.id}" ${t.id == val ? "selected" : ""}>${h(t.name)}</option>`).join("")}</select></label>`;
  if (LABELS[kind]) return `<label>${label}<select name="${key}">${Object.entries(LABELS[kind]).map(([k, v]) => `<option value="${k}" ${k === val ? "selected" : ""}>${v}</option>`).join("")}</select></label>`;
  return `<label>${label}<input name="${key}" value="${h(val)}"></label>`;
}

function dialog(title, inner, onOk, okLabel = "Salvar") {
  const d = $("#dlg"), f = $("#dlgform");
  f.innerHTML = `<h1>${h(title)}</h1>${inner}<div class="act"><button value="cancel" formnovalidate>Cancelar</button><button class="primary" value="ok">${okLabel}</button></div>`;
  f.onsubmit = async (e) => {
    if (e.submitter?.value !== "ok") return;
    e.preventDefault();
    try { await onOk(Object.fromEntries(new FormData(f))); d.close(); route(); } catch (err) { toast("Erro: " + err.message); }
  };
  d.showModal();
}

async function editEntity(entity, id) {
  await loadTeams();
  const cur = id ? await api(`/api/e/${entity}/${id}`) : {};
  const F = FORMS[entity];
  dialog((id ? "Editar " : "Novo(a) ") + F.title.toLowerCase(), F.fields.map((f) => fieldHtml(f, cur[f[0]])).join(""), async (data) => {
    if (id) await api(`/api/e/${entity}/${id}`, { method: "PUT", json: data });
    else { const r = await api(`/api/e/${entity}`, { method: "POST", json: data }); if (entity !== "teams") location.hash = `#/${entity}/${r.id}`; }
    toast("Salvo.");
  });
}
async function delEntity(entity, id, name) {
  if (!confirm(`Excluir "${name}"? Os vínculos serão removidos.`)) return;
  await api(`/api/e/${entity}/${id}`, { method: "DELETE" });
  toast("Excluído."); location.hash = `#/${entity}`;
}
async function linkDialog(entity, id, target) {
  const opts = await api(`/api/e/${target}`);
  const hasRole = target === "systems";
  dialog(target === "systems" ? "Vincular ferramenta / sistema" : "Vincular componente",
    `<label>${target === "systems" ? "Ferramenta / sistema" : "Componente"}<select name="id">${opts.map((o) => `<option value="${o.id}">${h(o.name)}${o.version ? " " + h(o.version) : ""}${o.category ? " · " + h(lbl("category", o.category)) : ""}</option>`).join("")}</select></label>
     ${hasRole ? '<label>Papel / uso (ex.: "pipeline de build", "hospedagem", "repositório")<input name="role"></label>' : ""}
     <p class="small muted">Não está na lista? Cadastre em <a href="#/${target}">${target === "systems" ? "Ferramentas e sistemas" : "Componentes"}</a>.</p>`,
    async (d) => { await api(`/api/e/${entity}/${id}/links/${target}`, { method: "POST", json: { id: +d.id, role: d.role } }); toast("Vinculado."); }, "Vincular");
}
async function unlink(entity, id, target, tid) {
  await api(`/api/e/${entity}/${id}/links/${target}/${tid}`, { method: "DELETE" }); toast("Vínculo removido."); route();
}

// ------------------------------------------------------------------ páginas
async function pageDashboard() {
  const s = await api("/api/stats");
  const o = s.open_by_severity || {};
  main.innerHTML = `<h1>Painel</h1><p class="sub">Visão geral do ecossistema e da exposição a vulnerabilidades.</p>
  <div class="cards">
    <a class="card" href="#/products"><b>${s.products}</b><span>Produtos</span></a>
    <a class="card" href="#/components"><b>${s.components}</b><span>Componentes</span></a>
    <a class="card" href="#/systems"><b>${s.systems}</b><span>Ferramentas e sistemas</span></a>
    <a class="card" href="#/teams"><b>${s.teams}</b><span>Equipes</span></a>
    <div class="card"><b>${s.packages}</b><span>Pacotes (via SBOM)</span></div>
    <a class="card" href="#/vulns"><b>${Object.values(o).reduce((a, b) => a + b, 0)}</b><span>Vulnerabilidades em aberto</span><div>${sevSummary(o)}</div></a>
  </div>
  <h2>Lacunas do inventário</h2>
  <div class="cards">
    <a class="card" href="#/components"><b>${s.components_without_sbom}</b><span>Componentes sem SBOM</span></a>
    <a class="card" href="#/products"><b>${s.without_owner}</b><span>Produtos/componentes sem equipe dona</span></a>
  </div>
  <h2>Vulnerabilidades em aberto mais relevantes</h2>
  ${table([["Vulnerabilidade", (r) => `<a href="#/impacto?q=${encodeURIComponent(r.id)}">${h(r.id)}</a><div class="small muted">${h(r.aliases)}</div>`], ["Severidade", (r) => sev(r.severity)],
    ["Resumo", (r) => h((r.summary || "").slice(0, 140))], ["Produtos", (r) => r.products], ["Componentes", (r) => r.components]], s.top_vulns,
    "Nenhuma vulnerabilidade em aberto. Importe SBOMs nos componentes e rode o cruzamento em <a href='#/vulns'>Vulnerabilidades</a>.")}`;
}

async function pageList(entity) {
  const rows = await api(`/api/e/${entity}`);
  const cfg = {
    products: ["Produtos", "O que a empresa entrega. Cada produto é composto por componentes e usa ferramentas/sistemas.", [
      ["Produto", (r) => `<a href="#/products/${r.id}"><b>${h(r.name)}</b></a> ${h(r.version || "")}<div class="small muted">${h((r.description || "").slice(0, 90))}</div>`],
      ["Equipe", (r) => team(r.team)], ["Criticidade", (r) => lbl("criticality", r.criticality)], ["Ciclo", (r) => lbl("lifecycle", r.lifecycle)],
      ["Componentes", (r) => r.components], ["Ferramentas", (r) => r.systems], ["Vulns abertas", (r) => r.open_vulns || "—"]]],
    components: ["Componentes", "Serviços, bibliotecas, apps, firmwares e imagens. Cada um pode ter um SBOM e pertencer a vários produtos.", [
      ["Componente", (r) => `<a href="#/components/${r.id}"><b>${h(r.name)}</b></a> ${h(r.version || "")}<div class="small muted">${h(lbl("type", r.type))}${r.language ? " · " + h(r.language) : ""}</div>`],
      ["Equipe", (r) => team(r.team)], ["Produtos", (r) => chips(r.products) || '<span class="muted small">nenhum</span>'],
      ["SBOM", (r) => (r.sbom_at ? `${r.packages} pacotes<div class="small muted">${fmtDate(r.sbom_at)}</div>` : '<span class="muted small">sem SBOM</span>')],
      ["Vulns abertas", (r) => r.open_vulns || "—"]]],
    systems: ["Ferramentas e sistemas", "SCM, CI/CD, registries, cloud, scanners… tudo que participa do desenvolvimento e entrega.", [
      ["Ferramenta", (r) => `<a href="#/systems/${r.id}"><b>${h(r.name)}</b></a> ${h(r.version || "")}<div class="small muted">${h(r.vendor || "")}</div>`],
      ["Categoria", (r) => lbl("category", r.category)], ["Equipe", (r) => team(r.team)], ["Usado por produtos", (r) => r.products], ["Usado por componentes", (r) => r.components],
      ["Vulns abertas", (r) => r.open_vulns || "—"]]],
    teams: ["Equipes", "Quem responde por cada produto, componente e ferramenta — os contatos para o PSIRT acionar.", [
      ["Equipe", (r) => `<b>${h(r.name)}</b><div class="small muted">${h(r.manager || "")}</div>`],
      ["Contato", (r) => `${r.email ? `<a href="mailto:${h(r.email)}">${h(r.email)}</a>` : ""}<div class="small muted">${h(r.chat || "")}</div>`],
      ["Produtos", (r) => r.products], ["Componentes", (r) => r.components], ["Ferramentas", (r) => r.systems],
      ["", (r) => `<button class="link" onclick="editEntity('teams',${r.id})">editar</button><button class="link danger" onclick="delEntity('teams',${r.id},'${h(r.name).replace(/'/g, "")}')">excluir</button>`]]],
  }[entity];
  main.innerHTML = `<div class="bar"><div class="grow"><h1>${cfg[0]}</h1><p class="sub">${cfg[1]}</p></div>
    <input id="flt" placeholder="Filtrar…"><button class="primary" onclick="editEntity('${entity}')">+ Novo</button></div>
    <div id="lst">${table(cfg[2], rows)}</div>`;
  $("#flt").oninput = (e) => {
    const q = e.target.value.toLowerCase();
    $("#lst").innerHTML = table(cfg[2], rows.filter((r) => JSON.stringify(r).toLowerCase().includes(q)));
  };
}

async function pageProduct(id) {
  const e = await api(`/api/ecosystem/product/${id}`);
  const p = e.product;
  const viaComp = new Map();
  e.components.forEach((c) => c.systems.forEach((s) => { if (!viaComp.has(s.id)) viaComp.set(s.id, { ...s, via: [] }); viaComp.get(s.id).via.push(c.name); }));
  const allSys = new Map(e.systems.map((s) => [s.id, { ...s, direct: true }]));
  viaComp.forEach((s, k) => { if (!allSys.has(k)) allSys.set(k, s); });

  main.innerHTML = `<div class="bar"><div class="grow"><h1>${h(p.name)} ${h(p.version || "")}</h1>
      <p class="sub">${h(p.description || "")}</p></div>
    <button onclick="editEntity('products',${p.id})">Editar</button><button class="danger" onclick="delEntity('products',${p.id},'${h(p.name).replace(/'/g, "")}')">Excluir</button></div>
  <div class="panel"><dl class="kv"><dt>Equipe responsável</dt><dd>${team(p.team)}</dd><dt>Criticidade</dt><dd>${lbl("criticality", p.criticality)}</dd>
    <dt>Ciclo de vida</dt><dd>${lbl("lifecycle", p.lifecycle)}</dd></dl></div>
  <h2>Mapa do ecossistema</h2>
  <div class="eco" id="eco"><svg id="ecosvg"></svg>
    <div class="col"><h3>Produto</h3><div class="node prod" data-n="p">${h(p.name)}<small>${h(p.version || "")}</small></div></div>
    <div class="col"><h3>Componentes (${e.components.length})</h3>${e.components.map((c) => `<a class="node" data-n="c${c.id}" href="#/components/${c.id}">${h(c.name)} ${h(c.version || "")}<small>${h(lbl("type", c.type))} · ${c.packages ? c.packages + " pacotes" : "sem SBOM"}</small><small>${sevSummary(c.vulns)}</small></a>`).join("") || '<span class="muted small">nenhum</span>'}</div>
    <div class="col"><h3>Ferramentas e sistemas (${allSys.size})</h3>${[...allSys.values()].map((s) => `<a class="node sys" data-n="s${s.id}" href="#/systems/${s.id}">${h(s.name)}<small>${h(lbl("category", s.category))}${s.role ? " · " + h(s.role) : ""}</small></a>`).join("") || '<span class="muted small">nenhuma</span>'}</div>
    <div class="col"><h3>Equipes (${e.teams.length})</h3>${e.teams.map((t) => `<div class="node team" data-n="t${t.id}">${h(t.name)}<small>${h(t.email || "")} ${h(t.chat || "")}</small></div>`).join("") || '<span class="muted small">nenhuma</span>'}</div>
  </div>
  <div class="grid2">
   <div><h2>Componentes <button class="link" onclick="linkDialog('products',${p.id},'components')">+ vincular</button></h2>
   ${table([["Componente", (c) => `<a href="#/components/${c.id}">${h(c.name)}</a> ${h(c.version || "")}`], ["Equipe", (c) => team(c.team)], ["Vulns abertas", (c) => sevSummary(c.vulns)],
      ["", (c) => `<button class="link danger" onclick="unlink('products',${p.id},'components',${c.id})">remover</button>`]], e.components, "Nenhum componente vinculado.")}</div>
   <div><h2>Ferramentas e sistemas <button class="link" onclick="linkDialog('products',${p.id},'systems')">+ vincular</button></h2>
   ${table([["Ferramenta", (s) => `<a href="#/systems/${s.id}">${h(s.name)}</a><div class="small muted">${h(lbl("category", s.category))}</div>`], ["Uso", (s) => h(s.role || "") + (s.via ? `<div class="small muted">via ${h(s.via.join(", "))}</div>` : "")],
      ["", (s) => (s.direct ? `<button class="link danger" onclick="unlink('products',${p.id},'systems',${s.id})">remover</button>` : "")]], [...allSys.values()], "Nenhuma ferramenta vinculada.")}</div>
  </div>
  <h2>Vulnerabilidades deste produto</h2><div id="pv"></div>`;
  drawLinks(e);
  renderFindings($("#pv"), { product_id: id, status: "abertos" });
}

function drawLinks(e) {
  const eco = $("#eco"), svg = $("#ecosvg");
  const draw = () => {
    const base = eco.getBoundingClientRect();
    const pos = (n) => { const el = eco.querySelector(`[data-n="${n}"]`); if (!el) return null; const r = el.getBoundingClientRect(); return { l: r.left - base.left + eco.scrollLeft, r: r.right - base.left + eco.scrollLeft, y: r.top - base.top + r.height / 2 }; };
    const edges = [];
    e.components.forEach((c) => { edges.push(["p", "c" + c.id]); c.systems.forEach((s) => edges.push(["c" + c.id, "s" + s.id])); if (c.owner_team_id) edges.push(["c" + c.id, "t" + c.owner_team_id, 1]); });
    e.systems.forEach((s) => { edges.push(["p", "s" + s.id]); if (s.owner_team_id) edges.push(["s" + s.id, "t" + s.owner_team_id, 1]); });
    svg.setAttribute("width", eco.scrollWidth); svg.setAttribute("height", eco.scrollHeight);
    svg.innerHTML = edges.map(([a, b, dashed]) => {
      const A = pos(a), B = pos(b); if (!A || !B) return "";
      const x1 = A.r, x2 = B.l, mx = (x1 + x2) / 2;
      return `<path d="M${x1},${A.y} C${mx},${A.y} ${mx},${B.y} ${x2},${B.y}" fill="none" stroke="currentColor" stroke-opacity="${dashed ? 0.25 : 0.35}" ${dashed ? 'stroke-dasharray="4 4"' : ""}/>`;
    }).join("");
  };
  draw(); window.onresize = draw;
}

async function pageComponent(id) {
  const d = await api(`/api/ecosystem/component/${id}`);
  const c = d.component;
  const sb = d.sboms[0];
  main.innerHTML = `<div class="bar"><div class="grow"><h1>${h(c.name)} ${h(c.version || "")}</h1><p class="sub">${h(lbl("type", c.type))}${c.language ? " · " + h(c.language) : ""}</p></div>
    <button onclick="editEntity('components',${c.id})">Editar</button><button class="danger" onclick="delEntity('components',${c.id},'${h(c.name).replace(/'/g, "")}')">Excluir</button></div>
  <div class="grid2">
    <div class="panel"><dl class="kv"><dt>Equipe</dt><dd>${team(c.team)}</dd>
      <dt>Repositório</dt><dd>${c.repo_url ? `<a href="${h(c.repo_url)}" target="_blank" rel="noopener">${h(c.repo_url)}</a>` : "—"}</dd>
      <dt>Produtos</dt><dd>${d.products.map((p) => `<a class="chip" href="#/products/${p.id}">${h(p.name)} ${h(p.version || "")}</a>`).join("") || "—"}</dd>
      <dt>Ferramentas</dt><dd>${d.systems.map((s) => `<span class="chip"><a href="#/systems/${s.id}">${h(s.name)}</a>${s.role ? " · " + h(s.role) : ""} <button class="link danger" title="remover" onclick="unlink('components',${c.id},'systems',${s.id})">×</button></span>`).join("")}
        <button class="link" onclick="linkDialog('components',${c.id},'systems')">+ vincular</button></dd>
      <dt>Observações</dt><dd>${h(c.notes || "—")}</dd></dl></div>
    <div class="panel"><b>SBOM</b>
      <p class="small muted">${sb ? `Atual: ${h(sb.format)} ${h(sb.spec_version || "")} · ${sb.package_count} pacotes · ${h(sb.filename || "")} · ${fmtDate(sb.imported_at)}` : "Nenhum SBOM importado."}</p>
      <div class="bar"><label class="btn primary">Importar SBOM (CycloneDX/SPDX JSON)<input type="file" accept=".json" hidden id="fsbom"></label>
      <label class="btn">Importar relatório Trivy/Grype<input type="file" accept=".json" hidden id="frep"></label>
      <button id="bscan" ${d.packages.length ? "" : "disabled"}>Cruzar com OSV.dev</button></div>
      <p class="small muted">Um novo SBOM substitui o anterior; a triagem já feita (status/notas) é preservada para pacotes iguais.</p></div>
  </div>
  <h2>Vulnerabilidades</h2><div id="cv"></div>
  <h2>Pacotes (${d.packages.length})</h2><input id="pf" placeholder="Filtrar pacotes…" style="margin-bottom:8px"><div id="pk"></div>`;
  const pkCols = [["Pacote", (k) => `<b>${h(k.name)}</b>`], ["Versão", (k) => h(k.version)], ["purl", (k) => `<span class="mono">${h(k.purl || "")}</span>`], ["Licença", (k) => h(k.license || "")], ["Vulns abertas", (k) => k.open_vulns || "—"]];
  const showPk = (q = "") => ($("#pk").innerHTML = table(pkCols, d.packages.filter((k) => !q || (k.name + " " + (k.purl || "")).toLowerCase().includes(q)).slice(0, 500), "Sem pacotes — importe um SBOM."));
  showPk(); $("#pf").oninput = (ev) => showPk(ev.target.value.toLowerCase());
  const upload = (inp, url) => (inp.onchange = async () => {
    const fd = new FormData(); fd.append("file", inp.files[0]);
    try { const r = await api(url, { method: "POST", body: fd }); toast("Importado: " + JSON.stringify(r)); route(); } catch (err) { toast("Erro: " + err.message, 6000); }
  });
  upload($("#fsbom"), `/api/components/${id}/sbom`);
  upload($("#frep"), `/api/components/${id}/report`);
  $("#bscan").onclick = async () => {
    toast("Consultando OSV.dev…", 20000);
    try { const r = await api(`/api/scan?component_id=${id}`, { method: "POST" }); toast(`${r.checked} pacotes verificados, ${r.vulns} vulnerabilidades encontradas.`); route(); } catch (err) { toast("Erro: " + err.message, 8000); }
  };
  renderFindings($("#cv"), { component_id: id });
}

async function pageSystem(id) {
  const d = await api(`/api/system-detail/${id}`);
  const s = d.system;
  main.innerHTML = `<div class="bar"><div class="grow"><h1>${h(s.name)} ${h(s.version || "")}</h1><p class="sub">${h(lbl("category", s.category))}${s.vendor ? " · " + h(s.vendor) : ""}</p></div>
    <button onclick="editEntity('systems',${s.id})">Editar</button><button class="danger" onclick="delEntity('systems',${s.id},'${h(s.name).replace(/'/g, "")}')">Excluir</button></div>
  <div class="panel"><dl class="kv"><dt>Equipe</dt><dd>${team(s.team)}</dd><dt>Identificador</dt><dd class="mono">${h(s.identifier || "—")}</dd>
    <dt>URL</dt><dd>${s.url ? `<a href="${h(s.url)}" target="_blank" rel="noopener">${h(s.url)}</a>` : "—"}</dd><dt>Observações</dt><dd>${h(s.notes || "—")}</dd></dl></div>
  <div class="grid2"><div><h2>Produtos que usam</h2>${table([["Produto", (p) => `<a href="#/products/${p.id}">${h(p.name)}</a> ${h(p.version || "")}`], ["Uso", (p) => h(p.role || "")]], d.products, "Nenhum produto vinculado diretamente.")}</div>
  <div><h2>Componentes que usam</h2>${table([["Componente", (c) => `<a href="#/components/${c.id}">${h(c.name)}</a>`], ["Uso", (c) => h(c.role || "")], ["Produtos", (c) => chips(c.products)]], d.components, "Nenhum componente vinculado.")}</div></div>
  <h2>Vulnerabilidades</h2><div id="sv"></div>`;
  renderFindings($("#sv"), { system_id: id });
}

async function renderFindings(el, params) {
  const rows = await api("/api/findings?" + new URLSearchParams(params));
  el.innerHTML = table([
    ["Vulnerabilidade", (f) => `<a href="#/impacto?q=${encodeURIComponent(f.vuln_id)}">${h(f.vuln_id)}</a>${f.url ? ` <a href="${h(f.url)}" target="_blank" rel="noopener" class="small">↗</a>` : ""}<div class="small muted">${h(f.aliases || "")}</div>`],
    ["Sev.", (f) => sev(f.severity)],
    ["Onde", (f) => (f.package ? `<b>${h(f.package)}</b> ${h(f.version || "")}<div class="small">em <a href="#/components/${f.component_id}">${h(f.component)}</a></div>` : `🛠 ${h(f.system)}`) + `<div>${chips(f.products)}</div>`],
    ["Corrigido em", (f) => h(f.fixed_version || "")],
    ["Equipe", (f) => team(f.team)],
    ["Triagem", (f) => `<select data-f="${f.id}">${Object.entries(LABELS.status).map(([k, v]) => `<option value="${k}" ${k === f.status ? "selected" : ""}>${v}</option>`).join("")}</select>
       <input data-n="${f.id}" placeholder="nota / justificativa" value="${h(f.notes || "")}" style="width:100%;margin-top:4px">`],
  ], rows, "Nenhuma vulnerabilidade encontrada.");
  el.querySelectorAll("select[data-f]").forEach((s) => (s.onchange = async () => { await api(`/api/findings/${s.dataset.f}`, { method: "PATCH", json: { status: s.value } }); toast("Triagem atualizada."); }));
  el.querySelectorAll("input[data-n]").forEach((i) => (i.onchange = async () => { await api(`/api/findings/${i.dataset.n}`, { method: "PATCH", json: { notes: i.value } }); toast("Nota salva."); }));
}

async function pageVulns(qs) {
  const st = qs.get("status") ?? "abertos", sv = qs.get("severity") || "";
  main.innerHTML = `<div class="bar"><div class="grow"><h1>Vulnerabilidades</h1><p class="sub">Achados do cruzamento SBOM × bases de vulnerabilidade, com triagem PSIRT (estilo VEX).</p></div>
    <button class="primary" id="scanall">Cruzar todos os SBOMs com OSV.dev</button></div>
    <div class="bar"><select id="fst"><option value="abertos">Em aberto (em análise + afetado)</option><option value="">Todos</option>${Object.entries(LABELS.status).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select>
    <select id="fsv"><option value="">Todas as severidades</option>${Object.entries(LABELS.severity).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select></div><div id="fl"></div>`;
  $("#fst").value = st; $("#fsv").value = sv;
  const go = () => (location.hash = "#/vulns?" + new URLSearchParams({ status: $("#fst").value, severity: $("#fsv").value }));
  $("#fst").onchange = go; $("#fsv").onchange = go;
  $("#scanall").onclick = async () => {
    toast("Consultando OSV.dev…", 60000);
    try { const r = await api("/api/scan", { method: "POST" }); toast(`${r.checked} itens verificados, ${r.vulns} vulnerabilidades, ${r.findings} ocorrências.`); route(); } catch (err) { toast("Erro: " + err.message, 8000); }
  };
  const p = {}; if (st) p.status = st; if (sv) p.severity = sv;
  renderFindings($("#fl"), p);
}

async function pageImpact(qs) {
  const q = qs.get("q") || "";
  main.innerHTML = `<h1>Busca de impacto</h1><p class="sub">Responda rápido “onde somos afetados?”: busque por <b>CVE/GHSA</b>, por <b>pacote</b> (ex.: <span class="mono">log4j-core</span>, <span class="mono">lodash@4.17.20</span>, <span class="mono">pkg:npm/lodash</span>) ou por <b>ferramenta</b> (ex.: Jenkins).</p>
  <form class="bar" id="if"><input name="q" value="${h(q)}" class="grow" placeholder="CVE-2021-44228, log4j-core, jenkins…" autofocus><button class="primary">Buscar</button></form><div id="ir"></div>`;
  $("#if").onsubmit = (e) => { e.preventDefault(); location.hash = "#/impacto?q=" + encodeURIComponent(new FormData(e.target).get("q")); };
  if (!q) return;
  const r = await api("/api/impact?q=" + encodeURIComponent(q));
  const prods = new Set(), teams = new Map();
  const osvHits = r.osv && r.osv.matches ? r.osv.matches.filter((m) => m.version_status !== "nao_afetada") : [];
  [...r.vulns, ...r.packages, ...r.systems, ...osvHits].forEach((x) => { (x.products || "").split(", ").filter(Boolean).forEach((p) => prods.add(p)); if (x.team) teams.set(x.team, x.team_email); });
  $("#ir").innerHTML = `<div class="panel"><b>Resumo:</b> ${prods.size} produto(s) potencialmente afetado(s) ${chips([...prods].join(", "))}
    <div style="margin-top:6px"><b>Equipes a acionar:</b> ${[...teams].map(([t, m]) => `<span class="chip">👥 ${h(t)}${m ? ` · <a href="mailto:${h(m)}">${h(m)}</a>` : ""}</span>`).join("") || "—"}</div>
    ${teams.size ? `<div style="margin-top:6px"><a class="btn" href="mailto:${[...teams.values()].filter(Boolean).join(",")}?subject=${encodeURIComponent("[PSIRT] Avaliação de impacto: " + q)}">✉ E-mail para as equipes</a></div>` : ""}</div>
  ${r.osv ? osvSection(r.osv) : ""}
  <h2>Por vulnerabilidade (${r.vulns.length})</h2>
  ${table([["Vuln", (x) => `<b>${h(x.vuln)}</b> ${sev(x.severity)}<div class="small muted">${h(x.aliases || "")}</div>`], ["Pacote/ferramenta", (x) => `${h(x.package)} ${h(x.version || "")}`],
    ["Componente", (x) => (x.component_id ? `<a href="#/components/${x.component_id}">${h(x.component)}</a>` : x.system_id ? `<a href="#/systems/${x.system_id}">🛠 ${h(x.package)}</a>` : "")], ["Produtos", (x) => chips(x.products)],
    ["Equipe", (x) => team(x.team)], ["Status", (x) => lbl("status", x.status)], ["Correção", (x) => h(x.fixed_version || "")]], r.vulns, "Nenhum achado registrado para esse identificador.")}
  <h2>Por pacote nos SBOMs (${r.packages.length})</h2>
  ${table([["Pacote", (x) => `<b>${h(x.package)}</b> ${h(x.version || "")}<div class="mono">${h(x.purl || "")}</div>`], ["Componente", (x) => `<a href="#/components/${x.component_id}">${h(x.component)}</a>`],
    ["Produtos", (x) => chips(x.products)], ["Equipe", (x) => team(x.team)], ["Vulns abertas", (x) => h(x.open_vulns || "—")]], r.packages, "Nenhum pacote com esse nome nos SBOMs importados.")}
  <h2>Por ferramenta / sistema (${r.systems.length})</h2>
  ${table([["Ferramenta", (x) => `<a href="#/systems/${x.system_id}">${h(x.system)}</a> ${h(x.version || "")}<div class="small muted">${h(lbl("category", x.category))}</div>`],
    ["Produtos", (x) => chips(x.products)], ["Componentes", (x) => chips(x.components)], ["Equipe", (x) => team(x.team)]], r.systems, "Nenhuma ferramenta com esse nome.")}`;
}

const VSTATUS = { afetada: ["sev-critica", "Versão afetada"], verificar: ["sev-desconhecida", "Verificar versão"], nao_afetada: ["sev-baixa", "Versão não afetada"] };
function osvSection(o) {
  if (o.error) return `<div class="panel muted">OSV.dev: ${h(o.error)}</div>`;
  const v = o.vuln, open = o.matches.filter((m) => m.version_status !== "nao_afetada").length;
  setTimeout(() => {
    const b = $("#osvreg");
    if (b) b.onclick = async () => {
      try { const r = await api(`/api/vulns/${encodeURIComponent(v.id)}/register`, { method: "POST" }); toast(`${r.registered} achado(s) registrados para triagem.`); route(); }
      catch (err) { toast("Erro: " + err.message, 6000); }
    };
  });
  return `<h2>Consulta no OSV.dev</h2><div class="panel"><b><a href="${h(v.url)}" target="_blank" rel="noopener">${h(v.id)}</a></b> ${sev(v.severity)}
    <span class="small muted">${h((v.aliases || []).join(" "))}</span><div>${h(v.summary || "")}</div>
    <div class="small muted" style="margin-top:4px">Pacotes afetados segundo o OSV: ${h(o.affected_packages.join(", ") || "—")}</div>
    ${open ? `<div style="margin-top:8px"><button class="primary" id="osvreg">Registrar ${open} achado(s) para triagem</button></div>` : ""}</div>
  ${table([["Pacote", (x) => `<b>${h(x.name)}</b> ${h(x.version || "")}<div class="mono">${h(x.purl || "")}</div>`],
    ["Situação", (x) => `<span class="sev ${VSTATUS[x.version_status][0]}">${VSTATUS[x.version_status][1]}</span>`],
    ["Componente", (x) => `<a href="#/components/${x.component_id}">${h(x.component)}</a>`], ["Produtos", (x) => chips(x.products)], ["Equipe", (x) => team(x.team)]],
    o.matches, "Nenhum pacote afetado encontrado nos SBOMs importados.")}`;
}

function pageData() {
  main.innerHTML = `<h1>Importar / Exportar</h1><p class="sub">Carga em massa do inventário e integração com CI/CD.</p>
  <div class="grid2"><div class="panel"><b>Importar inventário (JSON)</b>
    <p class="small muted">Equipes, ferramentas, componentes e produtos referenciados por nome. Reimportar atualiza (não duplica). Veja o formato em <span class="mono">exemplos/inventario-exemplo.json</span>.</p>
    <label class="btn primary">Escolher arquivo JSON<input type="file" accept=".json" hidden id="finv"></label></div>
  <div class="panel"><b>Exportar</b><p class="small muted">Backup completo (inventário, SBOMs, vulnerabilidades e triagem) em JSON.</p><a class="btn" href="/api/export">Baixar exportação</a></div></div>
  <h2>Enviar SBOM a partir do pipeline (CI/CD)</h2>
  <pre>curl -F file=@bom.json \\
  "${location.origin}/api/sbom?component=api-pagamentos&version=1.4.0&product=Portal%20do%20Cliente&team=Squad%20Pagamentos"</pre>
  <p class="small muted">Cria o componente (e o vínculo com o produto/equipe) se não existir e substitui o SBOM anterior. Gere o SBOM com Syft, Trivy, cdxgen ou plugins CycloneDX do Maven/Gradle/npm. Documentação da API em <a href="/docs">/docs</a>.</p>`;
  $("#finv").onchange = async (e) => {
    try { const data = JSON.parse(await e.target.files[0].text()); const r = await api("/api/import", { method: "POST", json: data }); toast(`Importados ${r.imported} itens.`); }
    catch (err) { toast("Erro: " + err.message, 6000); }
  };
}

// ------------------------------------------------------------------ roteador
async function route() {
  const [path, query] = (location.hash.slice(1) || "/").split("?");
  const qs = new URLSearchParams(query || "");
  const parts = path.split("/").filter(Boolean);
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.getAttribute("href") === "#/" + (parts[0] || "")));
  window.onresize = null;
  try {
    if (!parts.length) await pageDashboard();
    else if (parts[0] === "impacto") await pageImpact(qs);
    else if (parts[0] === "vulns") await pageVulns(qs);
    else if (parts[0] === "dados") pageData();
    else if (parts[0] === "products" && parts[1]) await pageProduct(parts[1]);
    else if (parts[0] === "components" && parts[1]) await pageComponent(parts[1]);
    else if (parts[0] === "systems" && parts[1]) await pageSystem(parts[1]);
    else if (FORMS[parts[0]]) await pageList(parts[0]);
    else main.innerHTML = "<h1>Página não encontrada</h1>";
  } catch (err) { main.innerHTML = `<h1>Erro</h1><p>${h(err.message)}</p>`; }
}
$("#quick").onsubmit = (e) => { e.preventDefault(); location.hash = "#/impacto?q=" + encodeURIComponent(new FormData(e.target).get("q")); };
window.addEventListener("hashchange", route);
route();
