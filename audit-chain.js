'use strict';

// ============================================================
// Cadeia de hash da trilha de auditoria — lógica PURA e compartilhada.
// ------------------------------------------------------------
// Usada por três consumidores, para que a fórmula nunca divirja:
//   - server.js        (gravação de cada elo)
//   - server.js        (GET /api/auditoria/status)
//   - audit-verify.js  (CLI forense, banco aberto em readOnly)
//
// Este módulo NÃO toca em chave mestra nem em disco: pode ser carregado
// por um auditor externo sem efeitos colaterais.
//
// Fórmula canônica (spec):
//   entrada = [id, entidade, entidade_id, acao, ator_id,
//              payload_hash, hash_anterior, ts_ms].join('|')
//   hash_encadeado = SHA-256(entrada, utf8)  -> hex minúsculo
// ============================================================

const crypto = require('node:crypto');

const GENESIS_HASH = '0'.repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
const CAMPOS_TEXTO = ['entidade', 'entidade_id', 'acao', 'ator_id'];

function sha256Hex(dados) {
  return crypto.createHash('sha256').update(dados).digest('hex');
}

/** JSON com chaves ordenadas: mesma entrada => mesmo hash, sempre. */
function jsonCanonico(valor) {
  if (valor === null || valor === undefined || typeof valor !== 'object') {
    return JSON.stringify(valor === undefined ? null : valor);
  }
  if (Array.isArray(valor)) return `[${valor.map(jsonCanonico).join(',')}]`;
  const chaves = Object.keys(valor).sort();
  return `{${chaves.map((k) => `${JSON.stringify(k)}:${jsonCanonico(valor[k])}`).join(',')}}`;
}

/** SHA-256 do payload sensível (o payload em si nunca entra na trilha). */
function hashPayload(payload) {
  return sha256Hex(jsonCanonico(payload));
}

/**
 * Monta a entrada canônica. Falha ALTO em vez de normalizar: como o
 * separador é '|', um campo contendo '|' (ou nulo/vazio) tornaria a
 * serialização ambígua. Na gravação isso aborta a operação; na verificação
 * isso conta como registro adulterado.
 */
function entradaCanonica(r) {
  if (!Number.isSafeInteger(r.id) || r.id < 1) throw new Error('AUDITORIA_CAMPO_INVALIDO:id');
  if (!Number.isSafeInteger(r.ts_ms) || r.ts_ms < 0) throw new Error('AUDITORIA_CAMPO_INVALIDO:ts_ms');
  for (const campo of CAMPOS_TEXTO) {
    const v = r[campo];
    if (typeof v !== 'string' || v.length === 0 || v.includes('|')) {
      throw new Error(`AUDITORIA_CAMPO_INVALIDO:${campo}`);
    }
  }
  for (const campo of ['payload_hash', 'hash_anterior']) {
    if (typeof r[campo] !== 'string' || !HEX64.test(r[campo])) {
      throw new Error(`AUDITORIA_CAMPO_INVALIDO:${campo}`);
    }
  }
  return [r.id, r.entidade, r.entidade_id, r.acao, r.ator_id, r.payload_hash, r.hash_anterior, r.ts_ms].join('|');
}

function calcularHashEncadeado(registro) {
  return crypto.createHash('sha256').update(entradaCanonica(registro), 'utf8').digest('hex');
}

/** Comparação em tempo constante de dois SHA-256 em hex. Formato inválido => false. */
function iguaisHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (!HEX64.test(a) || !HEX64.test(b)) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/**
 * Recalcula a cadeia inteira a partir do banco.
 * Aceita qualquer DatabaseSync (inclusive aberto com { readOnly: true }).
 *
 * Detecta: hash divergente (linha editada), elo quebrado (hash_anterior não
 * confere), id ausente/fora de ordem (linha apagada no meio) e truncamento
 * da cauda (sqlite_sequence maior que o número de linhas).
 *
 * LIMITE: quem tem escrita no arquivo do banco e conhece a fórmula pode
 * recomputar a cadeia inteira (e ajustar sqlite_sequence). Para detectar isso
 * é preciso ancorar `ultimo_hash` fora do banco (publicar/assinar/HMAC).
 *
 * @returns {{ok:true,total:number,ultimo_hash:string}
 *          |{ok:false,total:number,validados:number,falha:{id:number|null,codigo:string,detalhe:string}}}
 */
function verificarCadeia(db) {
  const rows = db
    .prepare(
      `SELECT id, entidade, entidade_id, acao, ator_id, payload_hash,
              hash_anterior, hash_encadeado, ts_ms
         FROM logs_auditoria ORDER BY id ASC`
    )
    .all();

  let anterior = GENESIS_HASH;
  let idEsperado = 1;

  for (const row of rows) {
    const falha = (codigo, detalhe) => ({
      ok: false,
      total: rows.length,
      validados: idEsperado - 1,
      falha: { id: row.id ?? null, codigo, detalhe },
    });

    if (row.id !== idEsperado) {
      return falha('ELO_AUSENTE', `esperado id ${idEsperado}, encontrado ${row.id}`);
    }
    if (!iguaisHex(row.hash_anterior, anterior)) {
      return falha('ELO_QUEBRADO', 'hash_anterior não corresponde ao hash do registro precedente');
    }
    let recalculado;
    try {
      recalculado = calcularHashEncadeado(row);
    } catch (e) {
      return falha('REGISTRO_INVALIDO', e.message);
    }
    if (!iguaisHex(recalculado, row.hash_encadeado)) {
      return falha('HASH_DIVERGENTE', 'hash_encadeado armazenado difere do hash recalculado');
    }
    anterior = row.hash_encadeado;
    idEsperado += 1;
  }

  let seq = null;
  try {
    const linha = db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'logs_auditoria'").get();
    seq = linha ? Number(linha.seq) : null;
  } catch {
    seq = null; // sqlite_sequence só existe depois do primeiro INSERT em tabela AUTOINCREMENT
  }
  if (seq !== null && seq !== rows.length) {
    return {
      ok: false,
      total: rows.length,
      validados: rows.length,
      falha: {
        id: null,
        codigo: 'TRUNCAMENTO_DETECTADO',
        detalhe: `sqlite_sequence=${seq}, mas há ${rows.length} registros (cauda removida?)`,
      },
    };
  }

  return { ok: true, total: rows.length, ultimo_hash: anterior };
}

module.exports = {
  GENESIS_HASH,
  sha256Hex,
  jsonCanonico,
  hashPayload,
  calcularHashEncadeado,
  iguaisHex,
  verificarCadeia,
};
