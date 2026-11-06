'use strict';

// Rate limiter em memória, por fingerprint hash (não por IP puro —
// evita penalizar redes NAT compartilhadas do Wi-Fi do evento).
// Em produção com múltiplas instâncias: trocar por Redis (INCR + TTL).

const janelas = new Map(); // ip_hash -> [timestamps]

const LIMITE_JANELA_MS = 60 * 60 * 1000; // 1 hora
const LIMITE_MAX_TENTATIVAS = 5; // máx. 5 denúncias/hora por fingerprint
const LIMITE_CAPTCHA_A_PARTIR = 2; // exige captcha a partir da 2ª no período curto
const JANELA_CURTA_MS = 2 * 60 * 1000; // 2 minutos

function registrarTentativa(ipHash) {
  if (typeof ipHash !== 'string' || ipHash.length === 0) {
    throw new TypeError('ipHash deve ser uma string não vazia');
  }

  const agora = Date.now();
  const lista = (janelas.get(ipHash) || []).filter(
    (t) => agora - t < LIMITE_JANELA_MS
  );
  lista.push(agora);
  janelas.set(ipHash, lista);

  const tentativasNaJanelaCurta = lista.filter((t) => agora - t < JANELA_CURTA_MS).length;

  return {
    bloqueado: lista.length > LIMITE_MAX_TENTATIVAS,
    exigeCaptcha: tentativasNaJanelaCurta >= LIMITE_CAPTCHA_A_PARTIR,
    tentativasNaUltimaHora: lista.length,
  };
}

// Limpeza periódica para não vazar memória em eventos longos.
setInterval(() => {
  const agora = Date.now();
  for (const [key, lista] of janelas) {
    const restante = lista.filter((t) => agora - t < LIMITE_JANELA_MS);
    if (restante.length === 0) janelas.delete(key);
    else janelas.set(key, restante);
  }
}, 10 * 60 * 1000).unref();

module.exports = { registrarTentativa };
