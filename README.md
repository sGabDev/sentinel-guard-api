# 🛡️ API de Detecção de Ataques em Tempo Real

Uma poderosa aplicação em Node.js que detecta requisições HTTP maliciosas em tempo real utilizando padrões inteligentes de detecção via middleware e Socket.IO para alertas de segurança em tempo real.

## 📋 Visão Geral

Este projeto demonstra mecanismos de detecção de segurança nível enterprise utilizados em APIs reais. Ele identifica e bloqueia ataques comuns da web enquanto fornece notificações em tempo real via WebSocket.

**Finalidade Educacional**: Este projeto foi criado para ensinar conceitos de cibersegurança e deve ser utilizado apenas para fins educacionais/demonstração.

---

## 🎯 Principais Funcionalidades

✅ Detecção de SQL Injection
✅ Detecção de XSS (Cross-Site Scripting)
✅ Proteção contra Força Bruta
✅ Rate Limiting (anti-flood/DoS)
✅ Alertas em Tempo Real (Socket.IO)
✅ Bloqueio por IP
✅ Arquitetura limpa e modular
✅ Dashboard interativo

---

## 🔐 Métodos de Detecção

### 1. SQL Injection (SQL_INJECTION)

**O que é**: Injeção de código SQL para manipular consultas ao banco de dados.

**Como detecta:**

```javascript
- ' OR 1=1
- UNION SELECT
- DROP TABLE
- ; DELETE FROM
- -- ou /* */
```

**Exemplos de ataque:**

```
?search=' OR 1=1 --
?user=admin' UNION SELECT * FROM users --
?id=1; DROP TABLE users;
```

Endpoint: `GET /search?q=PAYLOAD`

---

### 2. XSS (Cross-Site Scripting)

**O que é**: Execução de JavaScript malicioso no navegador do usuário.

**Detecta:**

```javascript
- <script>
- javascript:
- onerror=
- onload=
- <iframe>
```

**Exemplos:**

```html
<script>alert('XSS')</script>
<img src=x onerror="alert(1)">
```

Endpoint: `POST /comment`

---

### 3. Força Bruta (BRUTE_FORCE_DETECTED)

**O que é**: Tentativas repetidas de login para descobrir senhas.

**Configuração:**

```javascript
- 5 tentativas falhas → bloqueio
- Bloqueio de 15 minutos
```

Endpoint: `POST /login`

---

### 4. Flood / Rate Limiting (RATE_LIMIT_EXCEEDED)

**O que é**: Envio massivo de requisições para derrubar o servidor.

**Configuração:**

```javascript
- 60 requisições por minuto por IP
```

---

## 🛠️ Estrutura do Projeto

```
seg/
├── server.js
├── middleware/
│   └── securityDetector.js
├── routes/
│   └── demoRoutes.js
├── utils/
│   ├── threatDetector.js
│   └── ipTracker.js
├── public/
│   └── index.html
├── package.json
└── README.md
```

---

## 🚀 Instalação

```bash
npm install
npm start
```

Acesse:

```
http://localhost:3000
```

---

## 📡 Endpoints

### Health

```
GET /health
```

### Docs

```
GET /api/docs
```

### Login

```
POST /login
```

### Search

```
GET /search?q=test
```

### Comment

```
POST /comment
```

### Status

```
GET /status
```

---

## 🧪 Testes rápidos

### SQL Injection

```bash
curl "http://localhost:3000/search?q=test' OR 1=1"
```

### XSS

```bash
curl -X POST http://localhost:3000/comment \
-d '{"post_id":1,"comment":"<script>alert(1)</script>"}'
```

### Força Bruta

```bash
# executar várias vezes
curl -X POST http://localhost:3000/login \
-d '{"username":"admin","password":"wrong"}'
```

---

## 🔄 Monitoramento em Tempo Real

```javascript
socket.on('attack:detected', (data) => {
  console.log(data);
});
```

---

## 📊 Configuração

```javascript
this.config = {
  requestsPerMinute: 60,
  failedLoginThreshold: 5,
  blockDurationMinutes: 15
};
```

---

## 🛡️ Boas Práticas Demonstradas

* Validação de entrada
* Rate limiting
* Bloqueio por IP
* Detecção por padrões
* Monitoramento em tempo real
* Arquitetura modular

---

## 🚨 Observações

⚠️ Uso educacional
⚠️ Não usar em produção sem melhorias
⚠️ Não testar ataques sem permissão

---

## 📄 Licença

MIT

---

**Bora evoluir na cibersegurança 🚀🛡️**
