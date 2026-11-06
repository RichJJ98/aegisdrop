'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// ============================================================
// CHAVE MESTRA (AES-256-GCM) — segregada do código e do git
// ------------------------------------------------------------
// Ordem de resolução:
//   1. AEGIS_MASTER_KEY       64 caracteres hex (32 bytes). Preferida:
//                             injete via secret manager / KMS.
//   2. AEGIS_MASTER_KEY_FILE  caminho de um arquivo com 32 bytes brutos,
//                             de preferência FORA do diretório do projeto.
//   3. data/master.key        somente em desenvolvimento (gerada na 1ª
//                             execução). Está no .gitignore.
// Com NODE_ENV=production a chave NUNCA é gerada automaticamente: se não
// foi fornecida, o processo encerra em vez de criar uma chave local.
// ============================================================

const KEY_PATH_PADRAO = path.join(__dirname, 'data', 'master.key');

function avisarPermissoes(caminho) {
  try {
    const modo = fs.statSync(caminho).mode & 0o777;
    if (process.platform !== 'win32' && (modo & 0o077) !== 0) {
      console.warn(`[SEGURANCA] ${caminho} está legível por outros usuários (modo ${modo.toString(8)}). Use chmod 600.`);
    }
  } catch { /* melhor esforço */ }
}

function carregarMasterKey() {
  const hex = process.env.AEGIS_MASTER_KEY;
  if (hex) {
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      throw new Error('AEGIS_MASTER_KEY inválida: esperado 64 caracteres hexadecimais (32 bytes).');
    }
    return Buffer.from(hex, 'hex');
  }

  const caminho = process.env.AEGIS_MASTER_KEY_FILE
    ? path.resolve(process.env.AEGIS_MASTER_KEY_FILE)
    : KEY_PATH_PADRAO;

  if (fs.existsSync(caminho)) {
    const chave = fs.readFileSync(caminho);
    if (chave.length !== 32) {
      throw new Error(`Chave mestra em ${caminho} deve ter exatamente 32 bytes (tem ${chave.length}).`);
    }
    avisarPermissoes(caminho);
    return chave;
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'Chave mestra ausente em produção. Defina AEGIS_MASTER_KEY (64 hex) ou AEGIS_MASTER_KEY_FILE; ' +
        'o servidor não gera chaves automaticamente em produção.'
    );
  }

  // Desenvolvimento: gera uma vez, com permissão restrita, e nunca sobrescreve ('wx').
  fs.mkdirSync(path.dirname(caminho), { recursive: true });
  const nova = crypto.randomBytes(32);
  fs.writeFileSync(caminho, nova, { mode: 0o600, flag: 'wx' });
  console.warn(`[SEGURANCA] Chave de DESENVOLVIMENTO gerada em ${caminho}. Não versione este arquivo.`);
  return nova;
}

const MASTER_KEY = carregarMasterKey();

/**
 * Criptografa um texto com AES-256-GCM.
 * Retorna um único Buffer: [iv(12) | authTag(16) | ciphertext]
 * pronto para ser gravado num campo BLOB.
 */
function encryptField(plaintext) {
  if (plaintext == null) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const ciphertext = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]);
}

/** Descriptografa o formato gerado por encryptField(). */
function decryptField(blob) {
  if (blob == null) return null;
  const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
  const iv = buf.subarray(0, 12);
  const authTag = buf.subarray(12, 28);
  const ciphertext = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

/** SHA-256 de um Buffer/string — usado para integridade de evidências. */
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Hash não reversível para rate limiting / detecção de abuso, SEM guardar
 * IP em texto puro. HMAC-SHA-256 com a chave mestra (antes, 8 caracteres da
 * chave entravam como "sal" de uma entrada de baixa entropia — um IP —, o que
 * permitiria forçar bruta esse trecho da chave). O dia entra na mensagem, então
 * não é possível correlacionar o mesmo dispositivo entre dias.
 */
function dailyFingerprintHash(rawFingerprint) {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  return crypto.createHmac('sha256', MASTER_KEY).update(`${today}::${rawFingerprint}`).digest('hex');
}

/** Gera um protocolo público curto tipo OC-2026-8841. */
function gerarProtocolo() {
  const ano = new Date().getFullYear();
  const num = crypto.randomInt(1000, 9999);
  return `OC-${ano}-${num}`;
}

// A cadeia de hash da auditoria vive em audit-chain.js (lógica pura e verificável).
module.exports = {
  encryptField,
  decryptField,
  sha256,
  dailyFingerprintHash,
  gerarProtocolo,
};
