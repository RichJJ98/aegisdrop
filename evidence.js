'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { sha256 } = require('./crypto-utils');

// Dependência real de produção — instale com "npm install" (ver package.json).
const sharp = require('sharp');

const EVIDENCIAS_DIR = path.resolve(__dirname, 'data', 'evidencias');
if (!fs.existsSync(EVIDENCIAS_DIR)) fs.mkdirSync(EVIDENCIAS_DIR, { recursive: true });

const MAX_IMAGE_BYTES = 10 * 1024 * 1024;
const MAX_IMAGE_PIXELS = 25_000_000;
const BASE64_ESTRITO = /^[A-Za-z0-9+/]+={0,2}$/;

const EXTENSAO = { jpeg: '.jpg', png: '.png', webp: '.webp' };
const PNG_ASSINATURA = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/** Erro de entrada inválida: o servidor o converte em HTTP 400. */
class ErroEvidencia extends Error {
  constructor(codigo) {
    super(codigo);
    this.name = 'ErroEvidencia';
    this.codigo = codigo;
    this.statusCode = 400;
  }
}

/** Magic bytes estritos: JPEG, PNG ou WebP (RIFF + 'WEBP'). Qualquer outra coisa => null. */
function detectarFormato(buf) {
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'jpeg';
  if (buf.length >= 8 && buf.subarray(0, 8).equals(PNG_ASSINATURA)) return 'png';
  if (
    buf.length >= 12 &&
    buf.subarray(0, 4).toString('latin1') === 'RIFF' &&
    buf.subarray(8, 12).toString('latin1') === 'WEBP'
  ) {
    return 'webp';
  }
  return null;
}

/**
 * Valida e sanitiza UMA imagem, inteiramente em memória (nada vai a disco aqui).
 *
 *  1. aceita somente { tipo: 'foto', base64 } — não existe caminho genérico;
 *  2. decodifica base64 de forma estrita e limita o tamanho;
 *  3. confere magic bytes (JPEG/PNG/WebP) e confirma com o decoder do sharp;
 *  4. rotate() sem argumentos aplica a orientação EXIF nos PIXELS e, como
 *     nenhum withMetadata/keep* é chamado, o sharp regrava a imagem sem
 *     EXIF/XMP/IPTC (GPS, modelo do aparelho, datas);
 *  5. relê o resultado para garantir que não restou metadado;
 *  6. calcula o SHA-256 do buffer FINAL (o que irá ao disco) e do original.
 *
 * @throws {ErroEvidencia} qualquer violação (=> HTTP 400)
 */
async function sanitizarEvidenciaImagem(evidencia) {
  if (!evidencia || typeof evidencia !== 'object' || evidencia.tipo !== 'foto') {
    throw new ErroEvidencia('TIPO_EVIDENCIA_NAO_PERMITIDO');
  }
  const b64 = evidencia.base64;
  if (typeof b64 !== 'string' || b64.length === 0) throw new ErroEvidencia('BASE64_AUSENTE');
  if (b64.length > Math.ceil((MAX_IMAGE_BYTES * 4) / 3) + 4) throw new ErroEvidencia('IMAGEM_MUITO_GRANDE');
  if (b64.length % 4 !== 0 || !BASE64_ESTRITO.test(b64)) throw new ErroEvidencia('BASE64_INVALIDO');

  const original = Buffer.from(b64, 'base64');
  if (original.length === 0) throw new ErroEvidencia('IMAGEM_VAZIA');
  if (original.length > MAX_IMAGE_BYTES) throw new ErroEvidencia('IMAGEM_MUITO_GRANDE');

  const formato = detectarFormato(original);
  if (!formato) throw new ErroEvidencia('FORMATO_IMAGEM_INVALIDO');

  let limpo;
  try {
    const imagem = sharp(original, { limitInputPixels: MAX_IMAGE_PIXELS });

    const meta = await imagem.metadata();
    if (meta.format !== formato) throw new ErroEvidencia('FORMATO_INCONSISTENTE');

    const pipeline = imagem.rotate(); // sem argumentos: orientação real nos pixels
    if (formato === 'jpeg') limpo = await pipeline.jpeg({ quality: 90 }).toBuffer();
    else if (formato === 'png') limpo = await pipeline.png().toBuffer();
    else limpo = await pipeline.webp({ quality: 90 }).toBuffer();

    const residual = await sharp(limpo).metadata();
    if (residual.exif || residual.xmp || residual.iptc || residual.tifftagPhotoshop) {
      throw new ErroEvidencia('METADADOS_RESIDUAIS');
    }
  } catch (e) {
    if (e instanceof ErroEvidencia) throw e;
    throw new ErroEvidencia('IMAGEM_CORROMPIDA_OU_NAO_PROCESSAVEL');
  }

  return {
    buffer: limpo,
    formato,
    extensao: EXTENSAO[formato],
    hashSha256: sha256(limpo), // arquivo final sanitizado (= o que fica em disco)
    hashOriginalSha256: sha256(original), // upload bruto, só como referência
  };
}

/**
 * Grava o buffer SANITIZADO em disco e confirma que o arquivo gravado tem
 * exatamente o hash calculado (correspondência forense banco <-> disco).
 * Nome = UUID gerado aqui; nada vindo do cliente compõe o caminho.
 * Retorna o nome do arquivo (relativo a data/evidencias/), que é o que vai ao banco.
 */
function gravarEvidencia(sanitizada) {
  const arquivo = `${crypto.randomUUID()}${sanitizada.extensao}`;
  const caminho = path.resolve(EVIDENCIAS_DIR, arquivo);
  const relativo = path.relative(EVIDENCIAS_DIR, caminho);
  if (relativo.startsWith(`..${path.sep}`) || path.isAbsolute(relativo) || relativo !== arquivo) {
    throw new Error('CAMINHO_EVIDENCIA_INVALIDO');
  }

  fs.writeFileSync(caminho, sanitizada.buffer, { mode: 0o600, flag: 'wx' });

  if (sha256(fs.readFileSync(caminho)) !== sanitizada.hashSha256) {
    fs.unlinkSync(caminho);
    throw new Error('EVIDENCIA_HASH_DIVERGENTE_NO_DISCO');
  }
  return arquivo;
}

/** Remove um arquivo de evidência (rollback quando a transação do banco falha). */
function removerEvidencia(arquivo) {
  try {
    fs.unlinkSync(path.join(EVIDENCIAS_DIR, path.basename(arquivo)));
  } catch { /* já não existe */ }
}

module.exports = { ErroEvidencia, sanitizarEvidenciaImagem, gravarEvidencia, removerEvidencia };
