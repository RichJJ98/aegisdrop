'use strict';

// node:sqlite é experimental no Node 22 (rodar com --experimental-sqlite).
// Em produção real, trocar por Postgres (ver README.md, seção "Produção").
const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const crypto = require('node:crypto');

const DB_PATH = path.join(__dirname, 'data', 'app.db');
const db = new DatabaseSync(DB_PATH);

db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA journal_mode = WAL;'); // melhora concorrência sob picos de escrita

function colunasDe(tabela) {
  // `tabela` é sempre uma constante deste arquivo (nunca entrada do usuário).
  return db.prepare(`PRAGMA table_info(${tabela})`).all().map((c) => c.name);
}

// ------------------------------------------------------------
// Migração: a trilha de auditoria antiga não guardava `ts_ms` nem
// `payload_hash`, então era impossível recalcular seus hashes. Em vez de
// apagar ou "consertar" evidência, a tabela antiga é preservada com outro
// nome e uma trilha nova começa do zero.
// ------------------------------------------------------------
{
  const cols = colunasDe('logs_auditoria');
  if (cols.length > 0 && !cols.includes('ts_ms')) {
    const destino = `logs_auditoria_legado_${Date.now()}`;
    db.exec(`ALTER TABLE logs_auditoria RENAME TO ${destino};`);
    console.warn(`[DB] Trilha de auditoria antiga preservada em "${destino}" (não verificável). Nova trilha iniciada.`);
  }
}

db.exec(`
CREATE TABLE IF NOT EXISTS eventos (
    id              TEXT PRIMARY KEY,
    nome            TEXT NOT NULL,
    data_inicio     TEXT NOT NULL,
    data_fim        TEXT NOT NULL,
    mapa_setores    TEXT, -- JSON: lista de setores/geofences
    contatos_emergencia TEXT, -- JSON
    status          TEXT DEFAULT 'ativo'
);

CREATE TABLE IF NOT EXISTS denunciantes (
    id                      TEXT PRIMARY KEY,
    contato_criptografado   BLOB,             -- NULL se anônimo puro
    device_fingerprint_hash TEXT,
    criado_em               TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ocorrencias (
    id                      TEXT PRIMARY KEY,
    evento_id               TEXT REFERENCES eventos(id),
    denunciante_id           TEXT REFERENCES denunciantes(id),
    protocolo_publico        TEXT UNIQUE NOT NULL,
    tipo_incidente           TEXT NOT NULL,
    descricao_criptografada  BLOB NOT NULL,
    setor_geolocalizacao     TEXT,
    lat                     REAL,
    lng                     REAL,
    nivel_urgencia           INTEGER DEFAULT 3,
    status                  TEXT DEFAULT 'recebido',
    equipe_designada_id      TEXT,
    criado_em                TEXT DEFAULT (datetime('now')),
    encerrado_em              TEXT
);

-- hash_sha256          = SHA-256 do arquivo SANITIZADO gravado em disco
--                        (é o que a cadeia de custódia consegue provar).
-- hash_original_sha256 = SHA-256 do upload bruto, antes de remover metadados.
-- caminho_storage      = nome do arquivo dentro de data/evidencias/ (relativo).
CREATE TABLE IF NOT EXISTS evidencias (
    id                          TEXT PRIMARY KEY,
    ocorrencia_id                TEXT NOT NULL REFERENCES ocorrencias(id),
    tipo                        TEXT, -- somente 'foto' (imagens JPEG/PNG/WebP sanitizadas)
    caminho_storage              TEXT NOT NULL,
    hash_sha256                  TEXT NOT NULL,
    hash_original_sha256         TEXT,
    metadados_exif_removidos     INTEGER DEFAULT 1,
    criado_em                    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS historico_status (
    id                          TEXT PRIMARY KEY,
    ocorrencia_id                TEXT NOT NULL REFERENCES ocorrencias(id),
    status_anterior               TEXT,
    status_novo                   TEXT,
    operador_id                   TEXT NOT NULL,
    observacao_criptografada      BLOB,
    criado_em                     TEXT DEFAULT (datetime('now'))
);

-- Trilha com cadeia de hash. Fórmula em audit-chain.js:
--   hash_encadeado = SHA-256(id|entidade|entidade_id|acao|ator_id|payload_hash|hash_anterior|ts_ms)
CREATE TABLE IF NOT EXISTS logs_auditoria (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    entidade        TEXT,
    entidade_id     TEXT,
    acao            TEXT,
    ator_id         TEXT,
    payload_hash    TEXT,
    hash_anterior   TEXT,
    hash_encadeado  TEXT,
    ts_ms           INTEGER,
    criado_em       TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ocorrencias_status ON ocorrencias(status);
CREATE INDEX IF NOT EXISTS idx_ocorrencias_evento ON ocorrencias(evento_id);
CREATE INDEX IF NOT EXISTS idx_evidencias_ocorrencia ON evidencias(ocorrencia_id);
`);

// Bancos criados antes desta versão não têm a coluna do hash do original.
if (!colunasDe('evidencias').includes('hash_original_sha256')) {
  db.exec('ALTER TABLE evidencias ADD COLUMN hash_original_sha256 TEXT;');
}

function uuid() {
  return crypto.randomUUID();
}

// ------------------------------------------------------------
// Transação síncrona exclusiva. BEGIN IMMEDIATE toma o lock de escrita
// logo no início, então "ler o último hash + inserir o próximo elo" é
// atômico: a cadeia não pode bifurcar. Reentrante (chamadas aninhadas
// participam da transação externa). `fn` DEVE ser síncrona: um `await`
// dentro dela devolveria o controle com a transação aberta.
// ------------------------------------------------------------
let profundidadeTx = 0;

function comTransacaoImediata(fn) {
  if (profundidadeTx > 0) return fn();
  db.exec('BEGIN IMMEDIATE');
  profundidadeTx += 1;
  try {
    const resultado = fn();
    if (resultado && typeof resultado.then === 'function') {
      throw new Error('comTransacaoImediata exige função síncrona (recebeu uma Promise).');
    }
    db.exec('COMMIT');
    return resultado;
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch { /* sem transação ativa */ }
    throw e;
  } finally {
    profundidadeTx -= 1;
  }
}

// Semente: garante que sempre exista pelo menos um evento ativo para o MVP.
function seedEventoPadrao() {
  const existente = db.prepare('SELECT id FROM eventos LIMIT 1').get();
  if (existente) return existente.id;
  const id = uuid();
  db.prepare(
    `INSERT INTO eventos (id, nome, data_inicio, data_fim, mapa_setores, contatos_emergencia, status)
     VALUES (?, ?, ?, ?, ?, ?, 'ativo')`
  ).run(
    id,
    'Convenção Demo 2026',
    new Date().toISOString(),
    new Date(Date.now() + 3 * 24 * 3600 * 1000).toISOString(),
    JSON.stringify(['Artist Alley', 'Praça de Alimentação', 'Portão Principal', 'Arena Principal', 'Área Cosplay']),
    JSON.stringify({ policia: '190', central_mulher: '180', brigada_interna: '(interno) ramal 100' })
  );
  return id;
}

module.exports = { db, uuid, seedEventoPadrao, comTransacaoImediata };
