const express = require("express");
const ipTracker = require("../utils/ipTracker");

const router = express.Router();

const USUARIOS_DEMO = {
    admin: "password123",
    user: "secret456",
};

router.post("/login", (req, res) => {
    const { username, password } = req.body;
    const clientIP = req.clientIP;

    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: "Usuário e senha são obrigatórios",
        });
    }

    const validUser = USUARIOS_DEMO[username];

    if (validUser && validUser === password) {
        ipTracker.recordSuccessfulLogin(clientIP);

        console.log(
            `[LOGIN] Login bem-sucedido para usuário '${username}' de ${clientIP}`,
        );

        return res.status(200).json({
            success: true,
            message: `Bem-vindo ${username}!`,
            token: `token_${Math.random().toString(36).substr(2, 9)}`,
        });
    } else {
        const failureRecord = ipTracker.recordFailedLogin(clientIP);

        console.warn(
            `[LOGIN FALHOU] Tentativa ${failureRecord.failedAttempts} para usuário '${username}' de ${clientIP}`,
        );

        if (failureRecord.blocked) {
            return res.status(403).json({
                success: false,
                message:
                    "Muitas tentativas de login falhadas. Seu IP foi bloqueado por 15 minutos.",
            });
        }

        return res.status(401).json({
            success: false,
            message: "Credenciais inválidas",
            remainingAttempts: 5 - failureRecord.failedAttempts,
        });
    }
});

router.get("/search", (req, res) => {
    const { q } = req.query;
    const clientIP = req.clientIP;

    if (!q) {
        return res.status(400).json({
            error: "Parâmetro de busca ausente",
            message: "Forneça uma busca com ?q=sua_busca",
        });
    }

    console.log(`[BUSCA] Query de ${clientIP}: "${q}"`);

    const mockResults = [
        { id: 1, title: "Boas práticas de segurança em Node.js" },
        { id: 2, title: "Prevenção de SQL Injection" },
        { id: 3, title: "Segurança em aplicações web" },
    ];

    const results = mockResults.filter(
        (item) =>
            item.title.toLowerCase().includes(q.toLowerCase()) ||
            item.id.toString().includes(q),
    );

    return res.status(200).json({
        success: true,
        query: q,
        resultsCount: results.length,
        results,
    });
});

router.post("/comment", (req, res) => {
    const { comment, post_id } = req.body;
    const clientIP = req.clientIP;

    if (!comment) {
        return res.status(400).json({
            error: "Comentário ausente",
            message: "O texto do comentário é obrigatório",
        });
    }

    if (!post_id) {
        return res.status(400).json({
            error: "post_id ausente",
            message: "post_id é obrigatório",
        });
    }

    console.log(
        `[COMENTÁRIO] Novo comentário no post ${post_id} de ${clientIP}`,
    );

    const storedComment = {
        id: Math.floor(Math.random() * 10000),
        post_id,
        comment,
        author_ip: clientIP,
        created_at: new Date().toISOString(),
    };

    return res.status(201).json({
        success: true,
        message: "Comentário enviado com sucesso",
        comment: storedComment,
    });
});

router.get("/status", (req, res) => {
    const blockedIPs = ipTracker.getBlockedIPs();

    return res.status(200).json({
        status: "operacional",
        timestamp: new Date().toISOString(),
        security: {
            blockedIPsCount: blockedIPs.length,
            blockedIPs: blockedIPs,
        },
        info: {
            availableEndpoints: [
                "POST /login (username, password)",
                "GET /search?q=query",
                "POST /comment (comment, post_id)",
                "GET /status",
            ],
        },
    });
});

module.exports = router;
