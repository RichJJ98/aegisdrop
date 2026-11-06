# AegisDrop — Incident Reporting & Forensic Audit Platform

[![Node.js](https://img.shields.io/badge/Node.js-22.5%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Database](https://img.shields.io/badge/SQLite-node%3Asqlite_(native)-003B57?logo=sqlite&logoColor=white)](https://nodejs.org/api/sqlite.html)
[![Security](https://img.shields.io/badge/Cryptography-AES--256--GCM%20%7C%20SHA--256-blue)](https://nodejs.org/api/crypto.html)
[![Realtime](https://img.shields.io/badge/Realtime-SSE_(Native)-orange)](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Sistema de triagem de incidentes críticos em tempo real e recolha segura de relatos para eventos de grande escala e ambientes corporativos. Construído com arquitetura *Zero-Framework Core*, sanitização estrita de evidências multimédia e cadeia de custódia forense imutável via *hash chaining*.

---

## 🎯 Problema & Abordagem de Engenharia

Plataformas convencionais de denúncia enfrentam frequentemente três vetores de falha crítica:
1. **Superfície de ataque inflacionada por dependências:** Backends assentes em frameworks densos expõem cadeias de suprimento (*supply chain*) desnecessárias.
2. **Fuga colateral de metadados:** Ficheiros de imagem submetidos por vítimas retêm coordenadas geográficas precisas (GPS) e identificadores de dispositivo (EXIF).
3. **Vulnerabilidade a adulteração administrativa:** Bases relacionais padrão permitem que registos de auditoria sejam manipulados diretamente sem deixar prova matemática.

O **AegisDrop** resolve estes problemas recorrendo ao ecossistema moderno do **Node.js 22+**, tirando partido de módulos nativos de alto desempenho (`node:http`, `node:sqlite`, `node:crypto`) e uma pipeline rigorosa de higienização de dados.

---

## 🛡️ Pilares de Segurança & Arquitetura

### 1. Núcleo Minimalista Nativo (Zero-Framework Core)
- **Servidor HTTP:** Roteamento e streaming implementados diretamente sobre `node:http`.
- **Persistência Relacional:** Utilização da funcionalidade nativa `node:sqlite` (`DatabaseSync`), eliminando dependências externas compiladas por terceiros.
- **Transmissão em Tempo Real:** Mecanismo de despacho operado via **Server-Sent Events (SSE)** nativo com autenticação em tempo constante (`crypto.timingSafeEqual`).

### 2. Sanitização Forense de Imagens (`evidence.js`)
- **Validação por Magic Bytes:** Verificação direta da assinatura binária no cabeçalho do ficheiro (restringido a JPEG, PNG e WEBP), impedindo extensões falsas.
- **Descarte de Metadados (Stripping):** Processamento gráfico em memória via `sharp` com recompressão forçada para eliminar metadados EXIF/IPTC.
- **Mitigação de Path Traversal:** Identificadores gerados com `crypto.randomUUID()` e restritos estritamente ao diretório `data/evidencias`.

### 3. Cifra de Repouso & Cadeia de Custódia Imutável
- **Cifra Autenticada:** Conteúdos sensíveis são cifrados com **AES-256-GCM**, garantindo confidencialidade e autenticidade através de vetores de inicialização únicos por registo.
- **Hash Chaining Sequencial:** Cada evento no sistema gera um elo na tabela `logs_auditoria`:
  $$\text{Hash}_{\text{bloco}} = \text{SHA256}(\text{ID} \parallel \text{Entidade} \parallel \text{Ação} \parallel \text{Ator} \parallel \text{Hash}_{\text{anterior}} \parallel \text{Timestamp})$$
  Qualquer mutação manual no histórico corrompe a verificação matemática dos blocos subsequentes.

---

## 🔍 Verificação Forense da Cadeia de Custódia

O sistema inclui o utilitário independente `audit-verify.js` para auditoria externa em modo estritamente de leitura:

```bash
# Executa o cálculo e a prova matemática de integridade
node --experimental-sqlite audit-verify.js