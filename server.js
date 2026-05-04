const express = require("express");
const http = require("http");
const { Server: SocketIOServer } = require("socket.io");
const cors = require("cors");

const createSecurityDetector = require("./middleware/securityDetector");
const demoRoutes = require("./routes/demoRoutes");

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"],
    },
});

const PORT = process.env.PORT || 3000;
const HOST = "localhost";

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(createSecurityDetector(io));

app.get("/health", (req, res) => {
    return res.status(200).json({
        status: "ok",
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
    });
});

app.get("/api/docs", (req, res) => {
    return res.status(200).json({
        name: "API de Detecção de Ataques em Tempo Real",
        version: "1.0.0",
        description:
            "Detecta e bloqueia requisições HTTP maliciosas em tempo real",
        endpoints: [
            {
                method: "GET",
                path: "/health",
                description: "Endpoint de verificação de saúde",
            },
            {
                method: "GET",
                path: "/api/docs",
                description: "Documentação da API",
            },
            {
                method: "POST",
                path: "/login",
                description:
                    "Endpoint de login para demonstração - testa detecção de força bruta. Use qualquer usuário com senha errada 5+ vezes para ativar o bloqueio.",
                example: {
                    body: { username: "admin", password: "senha_errada" },
                },
            },
            {
                method: "GET",
                path: "/search",
                description:
                    "Endpoint de busca para demonstração - testa detecção de SQL Injection. Tente adicionar ' OR 1=1 na query.",
                example: {
                    query: "?q=test' OR 1=1",
                },
            },
            {
                method: "POST",
                path: "/comment",
                description:
                    "Endpoint de comentário para demonstração - testa detecção de XSS. Tente incluir <script> no comentário.",
                example: {
                    body: {
                        post_id: 1,
                        comment: "Comentário seguro aqui",
                    },
                },
            },
            {
                method: "GET",
                path: "/status",
                description:
                    "Obtém o status atual de segurança e IPs bloqueados",
            },
        ],
        detection: {
            sqlInjection: {
                description: "Detecta padrões de SQL Injection",
                examples: [
                    "' OR 1=1",
                    "UNION SELECT",
                    "admin' --",
                    "DROP TABLE",
                ],
            },
            xss: {
                description: "Detecta padrões de XSS/Injeção de script",
                examples: [
                    "<script>alert(1)</script>",
                    "javascript:alert(1)",
                    "<img src=x onerror='alert(1)'>",
                ],
            },
            bruteForce: {
                description: "Detecta tentativas de força bruta",
                threshold: "5 tentativas falhas",
                blockDuration: "15 minutos",
            },
            flooding: {
                description: "Detecta excesso de requisições",
                threshold: "60+ requisições por minuto",
                blockDuration: "Até a taxa cair abaixo do limite",
            },
        },
    });
});

app.use("/", demoRoutes);

app.use((req, res) => {
    return res.status(404).json({
        error: "Não encontrado",
        message: "O endpoint solicitado não existe",
        path: req.path,
        availableEndpoints: [
            "/health",
            "/api/docs",
            "/status",
            "POST /login",
            "GET /search",
            "POST /comment",
        ],
    });
});

io.on("connection", (socket) => {
    const timestamp = new Date().toISOString();
    console.log(`[SOCKET.IO] Cliente conectado: ${socket.id} em ${timestamp}`);

    socket.emit("message", {
        type: "welcome",
        message: "Conectado ao Detector de Ataques em Tempo Real",
        timestamp,
    });

    socket.on("test", (data) => {
        console.log(`[SOCKET.IO] Mensagem de teste de ${socket.id}:`, data);
        socket.emit("test:response", {
            message: "Mensagem de teste recebida",
            received: data,
            timestamp: new Date().toISOString(),
        });
    });

    socket.on("disconnect", () => {
        console.log(
            `[SOCKET.IO] Cliente desconectado: ${socket.id} em ${new Date().toISOString()}`,
        );
    });

    socket.on("error", (error) => {
        console.error(`[SOCKET.IO] Erro de ${socket.id}:`, error);
    });
});

server.listen(PORT, HOST, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║     API Detector de Ataques em Tempo Real - Iniciada! 🛡️   ║
╚════════════════════════════════════════════════════════════╝

📡 Servidor rodando em: http://${HOST}:${PORT}
📊 Dashboard Web: http://${HOST}:${PORT}
📝 Documentação da API: http://${HOST}:${PORT}/api/docs
🏥 Verificação de saúde: http://${HOST}:${PORT}/health

🔒 Recursos de Segurança Ativos:
   ✓ Detecção de SQL Injection
   ✓ Detecção de XSS
   ✓ Proteção contra força bruta
   ✓ Limitação de taxa / Detecção de flood
   ✓ Alertas em tempo real com Socket.IO
   ✓ Bloqueio baseado em IP

🧪 Rotas de Demonstração:
   POST /login - Testar força bruta
   GET /search - Testar SQL Injection
   POST /comment - Testar XSS
   GET /status - Ver status de segurança

Pressione Ctrl+C para parar o servidor
  `);
});

process.on("SIGINT", () => {
    console.log(
        "\n\n[ENCERRAMENTO] Sinal SIGINT recebido. Encerrando graciosamente...",
    );
    server.close(() => {
        console.log("[ENCERRAMENTO] Servidor encerrado");
        process.exit(0);
    });
});

module.exports = { app, server, io };
