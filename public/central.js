'use strict';

// ============================================================
// Painel da Central — sem innerHTML para dados de denúncias.
// Todo texto vindo do servidor entra no DOM via textContent, então
// "<img onerror=...>" numa descrição aparece como texto, nunca executa.
// (A CSP do servidor, script-src 'self', é a segunda camada.)
// ============================================================

const API = '';
const CHAVE_TOKEN = 'central_api_key';

let token = lerToken();
let filtroAtual = '';
let ocorrencias = new Map();
let fonteSSE = null;
let timerReconexao = null;

const $ = (id) => document.getElementById(id);

// ---------- sessão do operador (sem token padrão embutido) ----------
function lerToken() {
  try { return sessionStorage.getItem(CHAVE_TOKEN) || null; } catch { return null; }
}
function guardarToken(t) {
  try { sessionStorage.setItem(CHAVE_TOKEN, t); } catch { /* modo privado: fica só em memória */ }
}
function esquecerToken() {
  token = null;
  try { sessionStorage.removeItem(CHAVE_TOKEN); } catch { /* ignora */ }
}

function pararSSE() {
  clearTimeout(timerReconexao);
  if (fonteSSE) { fonteSSE.close(); fonteSSE = null; }
}

function pedirLogin(mensagem) {
  pararSSE();
  esquecerToken();
  ocorrencias = new Map();
  $('lista-ocorrencias').replaceChildren();
  const erro = $('login-erro');
  erro.textContent = mensagem || '';
  erro.hidden = !mensagem;
  $('login').hidden = false;
  $('input-token').focus();
}

async function validarToken(candidato) {
  try {
    const r = await fetch(`${API}/api/ocorrencias`, { headers: { 'x-central-token': candidato } });
    return r.ok;
  } catch {
    return false;
  }
}

$('form-login').addEventListener('submit', async (e) => {
  e.preventDefault();
  const campo = $('input-token');
  const candidato = campo.value.trim();
  if (!candidato) return;
  $('btn-login').disabled = true;
  const ok = await validarToken(candidato);
  $('btn-login').disabled = false;
  if (!ok) {
    $('login-erro').textContent = 'Token inválido ou servidor indisponível.';
    $('login-erro').hidden = false;
    campo.select();
    return;
  }
  campo.value = '';
  token = candidato;
  guardarToken(token);
  $('login').hidden = true;
  iniciar();
});

/** fetch autenticado: um 401 em qualquer chamada devolve o operador ao login. */
async function fetchCentral(url, opcoes = {}) {
  const r = await fetch(url, {
    ...opcoes,
    headers: { ...(opcoes.headers || {}), 'x-central-token': token },
  });
  if (r.status === 401) {
    pedirLogin('Sessão expirada ou token inválido. Entre novamente.');
    return null;
  }
  return r;
}

// ---------- helpers de DOM ----------
function el(tag, classe, texto) {
  const n = document.createElement(tag);
  if (classe) n.className = classe;
  if (texto !== undefined && texto !== null) n.textContent = String(texto);
  return n;
}

function urgenciaLabel(n) { return n <= 1 ? 'urgencia-1' : n <= 3 ? 'urgencia-3' : 'urgencia-5'; }
function statusLabel(s) {
  return { recebido: 'Recebida', triagem: 'Em triagem', despachado: 'Despachada', em_atendimento: 'Em atendimento', encerrado: 'Encerrada' }[s] || s;
}
function proximoStatus(atual) {
  const fluxo = { recebido: 'triagem', triagem: 'despachado', despachado: 'em_atendimento', em_atendimento: 'encerrado' };
  return fluxo[atual];
}
// SQLite grava datetime('now') em UTC, sem fuso; sem isto o navegador o leria como hora local.
function dataUTC(s) {
  return new Date(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s) ? `${s.replace(' ', 'T')}Z` : s);
}

// ---------- dados ----------
async function carregarOcorrencias() {
  const container = $('lista-ocorrencias');
  const url = `${API}/api/ocorrencias${filtroAtual ? `?status=${encodeURIComponent(filtroAtual)}` : ''}`;
  try {
    const r = await fetchCentral(url);
    if (r === null) return; // 401: o login já foi exibido
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const dados = await r.json();
    if (!Array.isArray(dados)) throw new Error('Resposta inválida');
    ocorrencias = new Map(dados.map((o) => [o.id, o]));
    renderizar();
  } catch (erro) {
    container.replaceChildren(el('div', 'vazio', 'Não foi possível carregar as ocorrências.'));
    console.error('Falha ao carregar ocorrências:', erro);
  }
}

async function atualizarStatus(id, statusNovo) {
  try {
    await fetchCentral(`${API}/api/ocorrencias/${encodeURIComponent(id)}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status_novo: statusNovo }),
    });
  } catch (erro) {
    console.error('Falha ao atualizar status:', erro);
  }
}

// O PDF exige o token em header; window.open() não consegue enviá-lo.
async function baixarRelatorio(id, protocolo) {
  try {
    const r = await fetchCentral(`${API}/api/ocorrencias/${encodeURIComponent(id)}/relatorio.pdf`);
    if (r === null) return;
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const blob = await r.blob();
    const href = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = href;
    a.download = `relatorio_${String(protocolo).replace(/[^\w-]/g, '')}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(href), 10000);
  } catch (erro) {
    console.error('Falha ao baixar relatório:', erro);
  }
}

// ---------- render ----------
function criarCard(o) {
  const card = el('div', `ocorrencia-card ${urgenciaLabel(Number(o.nivel_urgencia))}`);

  const topo = el('div', 'card-top');
  topo.append(el('span', 'protocolo', o.protocolo_publico), el('span', 'badge-status', statusLabel(o.status)));

  const origem = o.identificado ? '· 🙋 identificada' : '· 🕶️ anônima';
  const proximo = proximoStatus(o.status);

  const acoes = el('div', 'card-actions');
  if (proximo) {
    const avancar = el('button', `action-btn${proximo === 'encerrado' ? ' encerrar' : ''}`, `Avançar → ${statusLabel(proximo)}`);
    avancar.type = 'button';
    avancar.addEventListener('click', () => atualizarStatus(o.id, proximo));
    acoes.appendChild(avancar);
  }
  const pdf = el('button', 'action-btn', '📄 Relatório PDF');
  pdf.type = 'button';
  pdf.addEventListener('click', () => baixarRelatorio(o.id, o.protocolo_publico));
  acoes.appendChild(pdf);

  card.append(
    topo,
    el('div', 'tipo', o.tipo_incidente),
    el('div', 'setor', `📍 ${o.setor_geolocalizacao || 'setor não informado'} ${origem}`),
    el('div', 'descricao', o.descricao || ''),
    acoes,
    el('div', 'meta', `Recebida em ${dataUTC(o.criado_em).toLocaleString('pt-BR')}`)
  );
  return card;
}

function renderizar() {
  const container = $('lista-ocorrencias');
  const lista = Array.from(ocorrencias.values())
    .filter((o) => !filtroAtual || o.status === filtroAtual)
    .sort((a, b) => a.nivel_urgencia - b.nivel_urgencia || dataUTC(b.criado_em) - dataUTC(a.criado_em));

  if (lista.length === 0) {
    container.replaceChildren(el('div', 'vazio', 'Nenhuma ocorrência nesse filtro. 🎉'));
    return;
  }
  container.replaceChildren(...lista.map(criarCard));
}

document.querySelectorAll('.filtro-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filtro-btn').forEach((b) => b.classList.remove('ativo'));
    btn.classList.add('ativo');
    filtroAtual = btn.dataset.status;
    carregarOcorrencias();
  });
});

// ---------- tempo real (SSE) ----------
function marcarConexao(ligado) {
  const statusEl = $('status-conexao');
  statusEl.textContent = ligado ? '🟢 ao vivo' : '🔴 reconectando…';
  statusEl.className = `status-conexao ${ligado ? 'on' : 'off'}`;
}

function conectarSSE() {
  pararSSE();
  // EventSource não envia headers: o servidor aceita ?token= SOMENTE nesta rota.
  const es = new EventSource(`${API}/api/eventos-central?token=${encodeURIComponent(token)}`);
  fonteSSE = es;

  es.onopen = () => {
    marcarConexao(true);
    carregarOcorrencias(); // ressincroniza o que possa ter chegado durante a queda
  };

  es.onerror = async () => {
    marcarConexao(false);
    // CLOSED = o navegador desistiu (ex.: 401). Distingue token ruim de rede fora do ar.
    if (es.readyState === EventSource.CLOSED) {
      es.close();
      if (fonteSSE === es) fonteSSE = null;
      if (await validarToken(token)) {
        timerReconexao = setTimeout(conectarSSE, 3000);
      } else if (token) {
        pedirLogin('Sessão expirada ou token inválido. Entre novamente.');
      }
    }
  };

  const aoReceber = (e) => {
    try {
      const o = JSON.parse(e.data);
      ocorrencias.set(o.id, o);
      renderizar();
      if (e.type === 'nova_ocorrencia' && o.nivel_urgencia === 1 && 'vibrate' in navigator) {
        navigator.vibrate([200, 100, 200]);
      }
    } catch (erro) {
      console.error('Evento SSE inválido:', erro);
    }
  };
  es.addEventListener('nova_ocorrencia', aoReceber);
  es.addEventListener('status_atualizado', aoReceber);
}

function iniciar() {
  carregarOcorrencias();
  conectarSSE();
}

// Sem token na sessão => login. Nunca existe token "padrão".
if (token) iniciar();
else pedirLogin();
