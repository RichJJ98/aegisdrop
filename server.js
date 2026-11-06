'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { db, uuid, seedEventoPadrao, comTransacaoImediata } = require('./db');
const { encryptField, decryptField, dailyFingerprintHash, gerarProtocolo } = require('./crypto-utils');
const { GENESIS_HASH, calcularHashEncadeado, hashPayload, verificarCadeia } = require('./audit-chain');
const { registrarTentativa } = require('./ratelimit');
const { ErroEvidencia, sanitizarEvidenciaImagem, gravarEvidencia, removerEvidencia } = require('./evidence');

const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');

const PORT = process.env.PORT || 3000;
const EVENTO_ID = seedEventoPadrao();

// ator_id entra na cadeia de hash com '|' como separador: restringe o alfabeto.
const CENTRAL_OPERATOR_ID = process.env.CENTRAL_OPERATOR_ID || 'central-api';
if (!/^[A-Za-z0-9_.:@-]{1,64}$/.test(CENTRAL_OPERATOR_ID)) {
  console.error('CENTRAL_OPERATOR_ID inválido: use apenas letras, números e _ . : @ - (máx. 64).');
  process.exit(1);
}

const MAX_EVIDENCIAS = 5;
const STATUS_VALIDOS = new Set(['recebido', 'triagem', 'despachado', 'em_atendimento', 'encerrado']);

const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';";

// ------------------------------------------------------------
// Autenticação da Central
// ------------------------------------------------------------
const CENTRAL_API_KEY = process.env.CENTRAL_API_KEY || '';
if (!CENTRAL_API_KEY) {
  console.warn('[SEGURANCA] CENTRAL_API_KEY não definida: todas as rotas da Central responderão 401.');
} else if (CENTRAL_API_KEY.length < 32) {
  console.warn('[SEGURANCA] CENTRAL_API_KEY curta (<32 caracteres). Use um valor aleatório longo.');
}

// Compara digests SHA-256 (32 bytes fixos): timingSafeEqual exige tamanhos
// iguais, e assim o tamanho do token também não vaza pelo tempo de resposta.
function digestToken(valor) {
  return crypto.createHash('sha256').update(valor, 'utf8').digest();
}
const CHAVE_DIGEST = CENTRAL_API_KEY ? digestToken(CENTRAL_API_KEY) : null;

/**
 * Token aceito por: Authorization: Bearer <t>  |  X-Central-Token: <t>
 * e, SOMENTE se `permitirQuery` (SSE: EventSource do navegador não envia
 * headers), por ?token=<t>. Fora do SSE o token nunca é aceito na URL, para
 * não ir parar em logs de acesso, histórico ou Referer.
 */
function centralTokenValido(req, url, { permitirQuery = false } = {}) {
  if (!CHAVE_DIGEST) return false;

  const authorization = req.headers.authorization;
  let recebido;
  if (typeof authorization === 'string' && authorization.startsWith('Bearer ')) {
    recebido = authorization.slice('Bearer '.length);
  } else if (typeof req.headers['x-central-token'] === 'string') {
    recebido = req.headers['x-central-token'];
  } else if (permitirQuery) {
    recebido = url.searchParams.get('token');
  }
  if (typeof recebido !== 'string' || recebido.length === 0) return false;

  return crypto.timingSafeEqual(digestToken(recebido), CHAVE_DIGEST);
}

function exigirAcessoCentral(req, res, url, opcoes) {
  if (centralTokenValido(req, url, opcoes)) return true;
  enviarJSON(res, 401, { erro: 'Não autorizado.' });
  return false;
}

// ------------------------------------------------------------
// SSE: clientes conectados no painel da Central de Segurança
// ------------------------------------------------------------
const clientesSSE = new Set();

function broadcastSSE(evento, payload) {
  const linha = `event: ${evento}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of clientesSSE) {
    res.write(linha);
  }
}

// ------------------------------------------------------------
// Auditoria em cadeia de hash (fórmula e verificação em audit-chain.js)
// ------------------------------------------------------------
/**
 * Acrescenta UM elo à cadeia. Leitura do último hash + INSERT acontecem na
 * mesma transação BEGIN IMMEDIATE (síncrona), então dois eventos nunca
 * apontam para o mesmo hash_anterior. Se já houver transação externa aberta
 * (ex.: criação de ocorrência), participa dela.
 *
 * `payload_hash` = SHA-256 do payload sensível (veja hashPayload): o conteúdo
 * em si nunca é gravado na trilha, mas fica amarrado a ela.
 */
function registrarAuditoria({ entidade, entidade_id, acao, ator_id, payload_hash }) {
  return comTransacaoImediata(() => {
    const ultimo = db.prepare('SELECT id, hash_encadeado FROM logs_auditoria ORDER BY id DESC LIMIT 1').get();
    const seqLinha = db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'logs_auditoria'").get();

    // Usa o maior entre sqlite_sequence e o último id: se alguém apagar a cauda,
    // o próximo id deixa um buraco que o verificador acusa (a cadeia não "cicatriza").
    const id = Math.max(seqLinha ? Number(seqLinha.seq) : 0, ultimo ? ultimo.id : 0) + 1;
    const hash_anterior = ultimo ? ultimo.hash_encadeado : GENESIS_HASH;
    const ts_ms = Date.now();

    const registro = { id, entidade, entidade_id, acao, ator_id, payload_hash, hash_anterior, ts_ms };
    const hash_encadeado = calcularHashEncadeado(registro); // lança se algum campo for inválido

    db.prepare(
      `INSERT INTO logs_auditoria
         (id, entidade, entidade_id, acao, ator_id, payload_hash, hash_anterior, hash_encadeado, ts_ms)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(id, entidade, entidade_id, acao, ator_id, payload_hash, hash_anterior, hash_encadeado, ts_ms);

    return hash_encadeado;
  });
}

// ------------------------------------------------------------
// Helpers HTTP
// ------------------------------------------------------------
function enviarJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function lerCorpoJSON(req) {
  return new Promise((resolve, reject) => {
    let dados = '';
    let tamanho = 0;
    const LIMITE = 15 * 1024 * 1024; // 15MB (fotos em base64 são grandes)
    req.on('data', (chunk) => {
      tamanho += chunk.length;
      if (tamanho > LIMITE) {
        reject(new Error('PAYLOAD_TOO_LARGE'));
        req.destroy();
        return;
      }
      dados += chunk;
    });
    req.on('end', () => {
      try {
        resolve(dados ? JSON.parse(dados) : {});
      } catch (e) {
        reject(new Error('JSON_INVALIDO'));
      }
    });
    req.on('error', reject);
  });
}

function ipHashDaRequisicao(req) {
  const ip = req.socket.remoteAddress || 'desconhecido';
  return dailyFingerprintHash(ip);
}

function serveStatic(req, res, urlPath) {
  const publicDir = path.resolve(__dirname, 'public');
  const requestedPath = urlPath === '/' ? 'index.html' : urlPath;
  const filePath = path.resolve(publicDir, `.${requestedPath}`);
  const relativePath = path.relative(publicDir, filePath);
  if (relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Não encontrado');
      return;
    }
    const ext = path.extname(filePath);
    const tipos = {
      '.html': 'text/html; charset=utf-8',
      '.js': 'text/javascript; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
    };
    res.writeHead(200, { 'Content-Type': tipos[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ------------------------------------------------------------
// Regras de negócio
// ------------------------------------------------------------

function linhaOcorrenciaParaCentral(row) {
  return {
    id: row.id,
    protocolo_publico: row.protocolo_publico,
    tipo_incidente: row.tipo_incidente,
    descricao: decryptField(row.descricao_criptografada),
    setor_geolocalizacao: row.setor_geolocalizacao,
    lat: row.lat,
    lng: row.lng,
    nivel_urgencia: row.nivel_urgencia,
    status: row.status,
    equipe_designada_id: row.equipe_designada_id,
    criado_em: row.criado_em,
    encerrado_em: row.encerrado_em,
    identificado: row.denunciante_id != null,
  };
}

async function handleCriarOcorrencia(req, res) {
  const ipHash = ipHashDaRequisicao(req);
  let body;
  try {
    body = await lerCorpoJSON(req);
  } catch (e) {
    return enviarJSON(res, 400, { erro: 'Corpo inválido ou muito grande.' });
  }

  const fingerprintHash = ipHash;
  const { bloqueado, exigeCaptcha } = registrarTentativa(fingerprintHash);

  if (bloqueado) {
    return enviarJSON(res, 429, {
      erro: 'Muitas denúncias enviadas em pouco tempo. Se isto é uma emergência real, use o botão de pânico (190/180).',
    });
  }
  if (exigeCaptcha && !body.captcha_ok) {
    return enviarJSON(res, 428, {
      erro: 'CAPTCHA_NECESSARIO',
      mensagem: 'Confirme que você não é um robô para continuar.',
    });
  }

  const { tipo_incidente, descricao, setor_geolocalizacao, lat, lng, nivel_urgencia, anonimo, contato, evidencias } =
    body;

  if (typeof tipo_incidente !== 'string' || !tipo_incidente || typeof descricao !== 'string' || !descricao) {
    return enviarJSON(res, 400, { erro: 'tipo_incidente e descricao são obrigatórios (texto).' });
  }
  if (tipo_incidente.length > 64 || descricao.length > 10000) {
    return enviarJSON(res, 400, { erro: 'tipo_incidente (máx. 64) ou descricao (máx. 10000) excede o limite.' });
  }

  // ---- 1) Evidências: validar e sanitizar TUDO antes de tocar no banco ----
  // Uma única evidência inválida rejeita a denúncia inteira com 400 (nada é gravado).
  let sanitizadas = [];
  if (evidencias !== undefined && evidencias !== null) {
    if (!Array.isArray(evidencias) || evidencias.length > MAX_EVIDENCIAS) {
      return enviarJSON(res, 400, { erro: 'EVIDENCIA_INVALIDA', detalhe: 'EVIDENCIAS_DEVE_SER_LISTA_ATE_5' });
    }
    try {
      for (const ev of evidencias) sanitizadas.push(await sanitizarEvidenciaImagem(ev));
    } catch (e) {
      if (e instanceof ErroEvidencia) {
        return enviarJSON(res, 400, { erro: 'EVIDENCIA_INVALIDA', detalhe: e.codigo });
      }
      throw e;
    }
  }

  // ---- 2) Arquivos em disco (hash conferido) e 3) registros em UMA transação ----
  const ocorrenciaId = uuid();
  const protocolo = gerarProtocolo();
  const arquivos = [];
  const evidenciasSalvas = [];
  let row;

  try {
    for (const s of sanitizadas) arquivos.push(gravarEvidencia(s));

    row = comTransacaoImediata(() => {
      let denuncianteId = null;
      if (anonimo === false && typeof contato === 'string' && contato && contato.length <= 200) {
        denuncianteId = uuid();
        db.prepare(
          `INSERT INTO denunciantes (id, contato_criptografado, device_fingerprint_hash) VALUES (?, ?, ?)`
        ).run(denuncianteId, encryptField(contato), fingerprintHash);
      }

      db.prepare(
        `INSERT INTO ocorrencias
          (id, evento_id, denunciante_id, protocolo_publico, tipo_incidente, descricao_criptografada,
           setor_geolocalizacao, lat, lng, nivel_urgencia, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'recebido')`
      ).run(
        ocorrenciaId,
        EVENTO_ID,
        denuncianteId,
        protocolo,
        tipo_incidente,
        encryptField(descricao),
        typeof setor_geolocalizacao === 'string' ? setor_geolocalizacao.slice(0, 100) : null,
        typeof lat === 'number' ? lat : null,
        typeof lng === 'number' ? lng : null,
        Number.isInteger(nivel_urgencia) && nivel_urgencia >= 1 && nivel_urgencia <= 5 ? nivel_urgencia : 3
      );

      sanitizadas.forEach((s, i) => {
        const evidenciaId = uuid();
        db.prepare(
          `INSERT INTO evidencias
             (id, ocorrencia_id, tipo, caminho_storage, hash_sha256, hash_original_sha256, metadados_exif_removidos)
           VALUES (?, ?, 'foto', ?, ?, ?, 1)`
        ).run(evidenciaId, ocorrenciaId, arquivos[i], s.hashSha256, s.hashOriginalSha256);
        evidenciasSalvas.push({ id: evidenciaId, sha256: s.hashSha256 });
      });

      registrarAuditoria({
        entidade: 'ocorrencia',
        entidade_id: ocorrenciaId,
        acao: 'criou',
        ator_id: denuncianteId || `anonimo:${fingerprintHash.slice(0, 12)}`,
        payload_hash: hashPayload({
          tipo_incidente,
          descricao,
          setor: setor_geolocalizacao ?? null,
          anonimo: denuncianteId === null,
          evidencias: sanitizadas.map((s) => ({ sha256: s.hashSha256, sha256_original: s.hashOriginalSha256 })),
        }),
      });

      return db.prepare('SELECT * FROM ocorrencias WHERE id = ?').get(ocorrenciaId);
    });
  } catch (e) {
    for (const a of arquivos) removerEvidencia(a); // sem registro no banco => sem arquivo órfão
    throw e;
  }

  broadcastSSE('nova_ocorrencia', linhaOcorrenciaParaCentral(row));

  return enviarJSON(res, 201, {
    protocolo_publico: protocolo,
    ocorrencia_id: ocorrenciaId,
    evidencias_registradas: evidenciasSalvas.length,
    evidencias: evidenciasSalvas,
    aviso_captcha_futuro: exigeCaptcha,
  });
}

function handleListarOcorrencias(req, res, query) {
  const statusFiltro = query.get('status');
  let rows;
  if (statusFiltro) {
    rows = db
      .prepare('SELECT * FROM ocorrencias WHERE evento_id = ? AND status = ? ORDER BY nivel_urgencia ASC, criado_em DESC')
      .all(EVENTO_ID, statusFiltro);
  } else {
    rows = db
      .prepare('SELECT * FROM ocorrencias WHERE evento_id = ? ORDER BY nivel_urgencia ASC, criado_em DESC')
      .all(EVENTO_ID);
  }
  enviarJSON(res, 200, rows.map(linhaOcorrenciaParaCentral));
}

function handleDetalheOcorrencia(req, res, id, operadorId) {
  const row = db.prepare('SELECT * FROM ocorrencias WHERE id = ?').get(id);
  if (!row) return enviarJSON(res, 404, { erro: 'Não encontrada.' });

  registrarAuditoria({
    entidade: 'ocorrencia',
    entidade_id: id,
    acao: 'visualizou',
    ator_id: operadorId,
    payload_hash: hashPayload({ ocorrencia_id: id, operacao: 'detalhe' }),
  });

  const historico = db
    .prepare('SELECT * FROM historico_status WHERE ocorrencia_id = ? ORDER BY criado_em ASC')
    .all(id)
    .map((h) => ({ ...h, observacao: decryptField(h.observacao_criptografada), observacao_criptografada: undefined }));

  const evidencias = db
    .prepare(
      'SELECT id, tipo, hash_sha256, hash_original_sha256, metadados_exif_removidos, criado_em FROM evidencias WHERE ocorrencia_id = ?'
    )
    .all(id);

  enviarJSON(res, 200, { ...linhaOcorrenciaParaCentral(row), historico, evidencias });
}

async function handleAtualizarStatus(req, res, id) {
  let body;
  try {
    body = await lerCorpoJSON(req);
  } catch (e) {
    return enviarJSON(res, 400, { erro: 'Corpo inválido.' });
  }
  const { status_novo, observacao, equipe_designada_id } = body;
  if (typeof status_novo !== 'string' || !STATUS_VALIDOS.has(status_novo)) {
    return enviarJSON(res, 400, { erro: `status_novo inválido. Use: ${[...STATUS_VALIDOS].join(', ')}.` });
  }

  const row = db.prepare('SELECT * FROM ocorrencias WHERE id = ?').get(id);
  if (!row) return enviarJSON(res, 404, { erro: 'Não encontrada.' });

  const encerrarAgora = status_novo === 'encerrado';
  const equipe = typeof equipe_designada_id === 'string' ? equipe_designada_id.slice(0, 100) : null;
  const obs = typeof observacao === 'string' ? observacao.slice(0, 5000) : '';

  // Mudança de estado + histórico + elo de auditoria: tudo ou nada.
  const atualizado = comTransacaoImediata(() => {
    db.prepare(
      `UPDATE ocorrencias SET status = ?, equipe_designada_id = COALESCE(?, equipe_designada_id), encerrado_em = ? WHERE id = ?`
    ).run(status_novo, equipe, encerrarAgora ? new Date().toISOString() : row.encerrado_em, id);

    db.prepare(
      `INSERT INTO historico_status (id, ocorrencia_id, status_anterior, status_novo, operador_id, observacao_criptografada)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(uuid(), id, row.status, status_novo, CENTRAL_OPERATOR_ID, encryptField(obs));

    registrarAuditoria({
      entidade: 'ocorrencia',
      entidade_id: id,
      acao: `alterou_status:${row.status}->${status_novo}`,
      ator_id: CENTRAL_OPERATOR_ID,
      payload_hash: hashPayload({
        status_anterior: row.status,
        status_novo,
        observacao: obs,
        equipe_designada_id: equipe,
      }),
    });

    return db.prepare('SELECT * FROM ocorrencias WHERE id = ?').get(id);
  });

  broadcastSSE('status_atualizado', linhaOcorrenciaParaCentral(atualizado));
  enviarJSON(res, 200, linhaOcorrenciaParaCentral(atualizado));
}

function handleConsultaProtocolo(req, res, protocolo) {
  const row = db.prepare('SELECT * FROM ocorrencias WHERE protocolo_publico = ?').get(protocolo);
  if (!row) return enviarJSON(res, 404, { erro: 'Protocolo não encontrado.' });
  // Consulta pública NÃO expõe descrição nem evidências — só status/timeline.
  const historico = db
    .prepare('SELECT status_novo, criado_em FROM historico_status WHERE ocorrencia_id = ? ORDER BY criado_em ASC')
    .all(row.id);
  enviarJSON(res, 200, {
    protocolo_publico: row.protocolo_publico,
    status_atual: row.status,
    tipo_incidente: row.tipo_incidente,
    criado_em: row.criado_em,
    timeline: historico,
  });
}

function handleSetores(req, res) {
  const evento = db.prepare('SELECT * FROM eventos WHERE id = ?').get(EVENTO_ID);
  enviarJSON(res, 200, {
    evento: evento.nome,
    setores: JSON.parse(evento.mapa_setores || '[]'),
    contatos_emergencia: JSON.parse(evento.contatos_emergencia || '{}'),
  });
}

async function handleRelatorioPDF(req, res, id, operadorId) {
  const row = db.prepare('SELECT * FROM ocorrencias WHERE id = ?').get(id);
  if (!row) return enviarJSON(res, 404, { erro: 'Não encontrada.' });

  registrarAuditoria({
    entidade: 'ocorrencia',
    entidade_id: id,
    acao: 'exportou_pdf',
    ator_id: operadorId,
    payload_hash: hashPayload({ ocorrencia_id: id, operacao: 'relatorio_pdf' }),
  });

  const historico = db
    .prepare('SELECT * FROM historico_status WHERE ocorrencia_id = ? ORDER BY criado_em ASC')
    .all(id);
  const evidencias = db.prepare('SELECT * FROM evidencias WHERE ocorrencia_id = ?').all(id);

  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const page = pdfDoc.addPage([595.28, 841.89]); // A4
  let y = 800;
  const margem = 50;

  function linha(texto, { negrito = false, tamanho = 11, cor = rgb(0, 0, 0), espaco = 16 } = {}) {
    page.drawText(texto, { x: margem, y, size: tamanho, font: negrito ? fontBold : font, color: cor });
    y -= espaco;
  }

  linha('RELATÓRIO DE OCORRÊNCIA — SUBSÍDIO PARA REGISTRO OFICIAL', { negrito: true, tamanho: 14, espaco: 24 });
  linha(`Protocolo: ${row.protocolo_publico}`, { negrito: true });
  linha(`Tipo de incidente: ${row.tipo_incidente}`);
  linha(`Setor: ${row.setor_geolocalizacao || 'não informado'}`);
  linha(`Nível de urgência: ${row.nivel_urgencia}`);
  linha(`Status final: ${row.status}`);
  linha(`Aberto em: ${row.criado_em}`);
  linha(`Encerrado em: ${row.encerrado_em || '-'}`);
  linha(`Denúncia identificada: ${row.denunciante_id ? 'sim' : 'não (anônima)'}`);
  y -= 10;

  linha('DESCRIÇÃO DO INCIDENTE:', { negrito: true });
  const descricao = decryptField(row.descricao_criptografada) || '';
  const larguraMax = 90;
  for (let i = 0; i < descricao.length; i += larguraMax) {
    linha(descricao.slice(i, i + larguraMax), { tamanho: 10 });
  }
  y -= 10;

  linha('LINHA DO TEMPO:', { negrito: true });
  for (const h of historico) {
    linha(`${h.criado_em} — ${h.status_anterior || '(início)'} -> ${h.status_novo} (operador: ${h.operador_id})`, {
      tamanho: 10,
    });
  }
  y -= 10;

  linha('EVIDÊNCIAS (referência de custódia — arquivos sob guarda restrita):', { negrito: true });
  if (evidencias.length === 0) {
    linha('Nenhuma evidência anexada.', { tamanho: 10 });
  }
  for (const e of evidencias) {
    linha(`Tipo: ${e.tipo} | SHA-256 do arquivo armazenado: ${e.hash_sha256}`, { tamanho: 8 });
    if (e.hash_original_sha256) {
      linha(`   SHA-256 do upload original (antes da remoção de metadados): ${e.hash_original_sha256}`, { tamanho: 8 });
    }
  }

  y -= 20;
  linha(
    'Este documento é gerado automaticamente como subsídio informativo e NÃO substitui o Boletim de',
    { tamanho: 9, cor: rgb(0.4, 0.4, 0.4) }
  );
  linha(
    'Ocorrência oficial. Encaminhar às autoridades competentes (Polícia Civil / Disque 100 / Conselho Tutelar).',
    { tamanho: 9, cor: rgb(0.4, 0.4, 0.4) }
  );

  const pdfBytes = await pdfDoc.save();
  res.writeHead(200, {
    'Content-Type': 'application/pdf',
    'Content-Disposition': `attachment; filename="relatorio_${row.protocolo_publico}.pdf"`,
  });
  res.end(Buffer.from(pdfBytes));
}

// Mesma rotina matemática do CLI audit-verify.js (recalcula todos os hashes).
// 200 = íntegra; 409 = violação detectada (fácil de alarmar em monitoramento).
function handleAuditoriaVerificarIntegridade(req, res) {
  const r = verificarCadeia(db);
  if (r.ok) {
    return enviarJSON(res, 200, { integro: true, total_logs: r.total, ultimo_hash: r.ultimo_hash });
  }
  return enviarJSON(res, 409, { integro: false, total_logs: r.total, validados: r.validados, falha: r.falha });
}

// ------------------------------------------------------------
// Router
// ------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  // Base fixa: um cabeçalho Host malformado não pode derrubar o processo.
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch {
    res.writeHead(400);
    return res.end('Bad Request');
  }
  const { pathname, searchParams } = url;

  // Cabeçalhos de segurança em TODAS as respostas (estáticos, API e SSE).
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');

  // CORS básico (para o front rodar em porta separada durante dev, se preciso)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Central-Token');
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  try {
    if (pathname === '/api/eventos/setores' && req.method === 'GET') {
      return handleSetores(req, res);
    }

    if (pathname === '/api/ocorrencias' && req.method === 'POST') {
      return await handleCriarOcorrencia(req, res);
    }

    if (pathname === '/api/ocorrencias' && req.method === 'GET') {
      if (!exigirAcessoCentral(req, res, url)) return;
      return handleListarOcorrencias(req, res, searchParams);
    }

    if (pathname.startsWith('/api/ocorrencias/protocolo/') && req.method === 'GET') {
      const protocolo = decodeURIComponent(pathname.split('/').pop());
      return handleConsultaProtocolo(req, res, protocolo);
    }

    if (pathname.match(/^\/api\/ocorrencias\/[^/]+\/relatorio\.pdf$/) && req.method === 'GET') {
      if (!exigirAcessoCentral(req, res, url)) return;
      const id = pathname.split('/')[3];
      return await handleRelatorioPDF(req, res, id, CENTRAL_OPERATOR_ID);
    }

    if (pathname.match(/^\/api\/ocorrencias\/[^/]+\/status$/) && req.method === 'PATCH') {
      if (!exigirAcessoCentral(req, res, url)) return;
      const id = pathname.split('/')[3];
      return await handleAtualizarStatus(req, res, id);
    }

    if (pathname.match(/^\/api\/ocorrencias\/[^/]+$/) && req.method === 'GET') {
      if (!exigirAcessoCentral(req, res, url)) return;
      const id = pathname.split('/').pop();
      return handleDetalheOcorrencia(req, res, id, CENTRAL_OPERATOR_ID);
    }

    if (pathname === '/api/auditoria/status' && req.method === 'GET') {
      if (!exigirAcessoCentral(req, res, url)) return;
      return handleAuditoriaVerificarIntegridade(req, res);
    }

    if (pathname === '/api/eventos-central' && req.method === 'GET') {
      // SSE: EventSource não envia headers, então aqui (e só aqui) aceita ?token=
      if (!exigirAcessoCentral(req, res, url, { permitirQuery: true })) return;
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });
      res.write('retry: 3000\n\n');
      clientesSSE.add(res);
      req.on('close', () => clientesSSE.delete(res));
      return;
    }

    if (pathname.startsWith('/api/')) {
      return enviarJSON(res, 404, { erro: 'Rota de API não encontrada.' });
    }

    // Estáticos (frontend)
    return serveStatic(req, res, pathname);
  } catch (err) {
    console.error('Erro não tratado:', err);
    if (res.headersSent) return res.end();
    return enviarJSON(res, 500, { erro: 'Erro interno.' });
  }
});

server.listen(PORT, () => {
  console.log(`\n  Servidor rodando em http://localhost:${PORT}`);
  console.log(`  App da vítima:      http://localhost:${PORT}/denuncia.html`);
  console.log(`  Central de Segurança: http://localhost:${PORT}/central.html`);
  console.log(`  Evento ativo (seed): ${EVENTO_ID}\n`);
});
