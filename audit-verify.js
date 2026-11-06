'use strict';

// ============================================================
// Verificador forense independente da trilha de auditoria.
// ------------------------------------------------------------
// Abre o banco SOMENTE LEITURA, recalcula o SHA-256 de cada registro e
// compara com o hash armazenado em tempo constante (crypto.timingSafeEqual).
//
//   node audit-verify.js              -> verifica data/app.db
//   node audit-verify.js <caminho.db> -> verifica uma cópia forense
//
// Códigos de saída:  0 = cadeia íntegra
//                    1 = adulteração/quebra de elo detectada, ou erro
// ============================================================

const path = require('node:path');
const process = require('node:process');
const { DatabaseSync } = require('node:sqlite');
const { verificarCadeia } = require('./audit-chain');

const DB_PATH = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.join(__dirname, 'data', 'app.db');

let db;
try {
  console.log(`[AUDIT] Abrindo banco (somente leitura): ${DB_PATH}`);
  db = new DatabaseSync(DB_PATH, { readOnly: true });

  const r = verificarCadeia(db);

  if (!r.ok) {
    console.error(`[FAIL] Cadeia de custódia VIOLADA.`);
    console.error(`       código : ${r.falha.codigo}`);
    console.error(`       registro: ${r.falha.id === null ? '-' : '#' + r.falha.id}`);
    console.error(`       detalhe: ${r.falha.detalhe}`);
    console.error(`       validados antes da falha: ${r.validados} de ${r.total}`);
    process.exit(1);
  }

  console.log(`[PASS] Cadeia íntegra: ${r.total} registro(s) recalculados e validados.`);
  if (r.total > 0) console.log(`       hash da ponta da cadeia: ${r.ultimo_hash}`);
  process.exit(0);
} catch (err) {
  // Tabela ausente, esquema antigo, banco ilegível etc.: nunca devolver PASS.
  console.error('[ERRO FATAL]:', err.message);
  process.exit(1);
} finally {
  try { db?.close(); } catch { /* já encerrando */ }
}
