const API = '';
let tipoSelecionado = null;
let urgenciaSelecionada = 3;
let modoAnonimo = true;
let fotoBase64 = null;

// Fingerprint simples (não invasivo): só para anti-abuso, não identifica a pessoa.
function gerarFingerprintCliente() {
  const dados = [navigator.userAgent, screen.width, screen.height, new Date().getTimezoneOffset()].join('|');
  let hash = 0;
  for (let i = 0; i < dados.length; i++) { hash = ((hash << 5) - hash) + dados.charCodeAt(i); hash |= 0; }
  return 'fp_' + Math.abs(hash);
}
const fingerprint = gerarFingerprintCliente();

// Carrega setores do evento
fetch(API + '/api/eventos/setores').then(r => r.json()).then(dados => {
  document.getElementById('nome-evento').textContent = dados.evento;
  const select = document.getElementById('select-setor');
  dados.setores.forEach(s => {
    const opt = document.createElement('option');
    opt.value = s; opt.textContent = s;
    select.appendChild(opt);
  });
}).catch(() => {
  document.getElementById('nome-evento').textContent = 'Evento (offline)';
});

document.querySelectorAll('#chips-tipo .chip').forEach(chip => {
  chip.onclick = () => {
    document.querySelectorAll('#chips-tipo .chip').forEach(c => c.classList.remove('selecionado'));
    chip.classList.add('selecionado');
    tipoSelecionado = chip.dataset.valor;
  };
});

document.querySelectorAll('#chips-urgencia .urgencia-btn').forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll('#chips-urgencia .urgencia-btn').forEach(b => b.classList.remove('selecionado'));
    btn.classList.add('selecionado');
    urgenciaSelecionada = Number(btn.dataset.valor);
  };
});
document.querySelector('#chips-urgencia [data-valor="3"]').classList.add('selecionado');

document.querySelectorAll('#toggle-anonimo .chip').forEach(chip => {
  chip.onclick = () => {
    document.querySelectorAll('#toggle-anonimo .chip').forEach(c => c.classList.remove('selecionado'));
    chip.classList.add('selecionado');
    modoAnonimo = chip.dataset.valor === 'anonimo';
    document.getElementById('campo-contato').style.display = modoAnonimo ? 'none' : 'block';
  };
});

document.getElementById('input-foto').addEventListener('change', (e) => {
  const arquivo = e.target.files[0];
  if (!arquivo) return;
  const erroFoto = document.getElementById('campo-erro');
  // Espelha as regras do servidor (JPEG/PNG/WebP até 10 MB) para avisar antes do envio.
  if (!['image/jpeg', 'image/png', 'image/webp'].includes(arquivo.type) || arquivo.size > 10 * 1024 * 1024) {
    e.target.value = '';
    fotoBase64 = null;
    document.getElementById('preview-anexos').replaceChildren();
    erroFoto.textContent = 'A foto precisa ser JPEG, PNG ou WebP, de até 10 MB.';
    erroFoto.style.display = 'block';
    return;
  }
  erroFoto.style.display = 'none';
  const reader = new FileReader();
  reader.onload = () => {
    fotoBase64 = reader.result.split(',')[1];
    const preview = document.getElementById('preview-anexos');
    preview.replaceChildren();
    const img = document.createElement('img');
    img.src = reader.result;
    preview.appendChild(img);
  };
  reader.readAsDataURL(arquivo);
});

// ------------------------------------------------------------
// Fila offline-first: se a rede falhar, guarda no localStorage
// e tenta reenviar sozinho quando a conexão voltar.
// ------------------------------------------------------------
const CHAVE_FILA = 'fila_denuncias_pendentes';

function pegarFila() {
  try { return JSON.parse(localStorage.getItem(CHAVE_FILA) || '[]'); } catch { return []; }
}
function salvarFila(fila) {
  localStorage.setItem(CHAVE_FILA, JSON.stringify(fila));
}
function enfileirarDenuncia(payload) {
  const fila = pegarFila();
  fila.push(payload);
  salvarFila(fila);
}

async function tentarReenviarFila() {
  const fila = pegarFila();
  if (fila.length === 0) return;
  const restante = [];
  for (const payload of fila) {
    try {
      const r = await fetch(API + '/api/ocorrencias', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      });
      if (r.status === 400 && Array.isArray(payload.evidencias) && payload.evidencias.length > 0) {
        // Foto recusada pelo servidor: não deixa a denúncia presa para sempre; reenvia só o texto.
        restante.push({ ...payload, evidencias: [] });
      } else if (!r.ok) {
        restante.push(payload);
      }
    } catch { restante.push(payload); }
  }
  salvarFila(restante);
  document.getElementById('offline-aviso').classList.toggle('visivel', restante.length > 0);
}

window.addEventListener('online', tentarReenviarFila);
setInterval(tentarReenviarFila, 15000);
tentarReenviarFila();
if (pegarFila().length > 0) document.getElementById('offline-aviso').classList.add('visivel');

document.getElementById('form-denuncia').addEventListener('submit', async (e) => {
  e.preventDefault();
  const erroEl = document.getElementById('campo-erro');
  erroEl.style.display = 'none';

  const descricao = document.getElementById('descricao').value.trim();
  if (!tipoSelecionado || !descricao) {
    erroEl.textContent = 'Selecione o tipo de incidente e descreva o que aconteceu.';
    erroEl.style.display = 'block';
    return;
  }

  const btn = document.getElementById('btn-enviar');
  btn.disabled = true; btn.textContent = 'Enviando…';

  const payload = {
    tipo_incidente: tipoSelecionado,
    descricao,
    setor_geolocalizacao: document.getElementById('select-setor').value || null,
    nivel_urgencia: urgenciaSelecionada,
    anonimo: modoAnonimo,
    contato: modoAnonimo ? null : document.getElementById('contato').value,
    fingerprint_cliente: fingerprint,
    evidencias: fotoBase64 ? [{ tipo: 'foto', base64: fotoBase64 }] : [],
  };

  try {
    const r = await fetch(API + '/api/ocorrencias', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    });
    if (!r.ok) {
      // Antes, qualquer resposta não-429 era tratada como sucesso (protocolo "undefined").
      const j = await r.json().catch(() => ({}));
      erroEl.textContent =
        j.erro === 'EVIDENCIA_INVALIDA'
          ? 'Não foi possível aceitar a foto (use JPEG, PNG ou WebP de até 10 MB). Troque ou remova a foto e envie de novo.'
          : j.mensagem || j.erro || 'Não foi possível enviar agora. Tente novamente.';
      erroEl.style.display = 'block';
      btn.disabled = false; btn.textContent = 'Enviar denúncia';
      return;
    }
    const dados = await r.json();
    document.getElementById('form-denuncia').style.display = 'none';
    document.getElementById('protocolo-gerado').textContent = dados.protocolo_publico;
    document.getElementById('resultado').classList.add('visivel');
  } catch (err) {
    // Sem rede: guarda na fila offline e avisa o usuário que foi "recebido localmente"
    enfileirarDenuncia(payload);
    document.getElementById('offline-aviso').classList.add('visivel');
    document.getElementById('form-denuncia').style.display = 'none';
    document.getElementById('protocolo-gerado').textContent = '(será gerado ao sincronizar)';
    document.getElementById('resultado').classList.add('visivel');
  }
});

document.getElementById("btn-nova").addEventListener("click", () => location.reload());
