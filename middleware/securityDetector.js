const threatDetector = require("../utils/threatDetector");
const ipTracker = require("../utils/ipTracker");

function createSecurityDetector(io) {
    return (req, res, next) => {
        const clientIP = ipTracker.getClientIP(req);
        const timestamp = new Date().toISOString();

        console.log(`[${timestamp}] ${req.method} ${req.path} de ${clientIP}`);

        if (ipTracker.isIPBlocked(clientIP)) {
            const response = {
                timestamp,
                ip: clientIP,
                endpoint: req.path,
                method: req.method,
                attackType: "IP_BLOCKED",
                reason: "IP temporariamente bloqueado devido a atividade maliciosa anterior",
            };

            console.warn(
                `[BLOQUEADO] IP ${clientIP} está temporariamente bloqueado (${timestamp})`,
            );

            if (io) {
                io.emit("attack:detected", response);
            }

            return res.status(403).json({
                error: "Proibido",
                message:
                    "Seu IP foi temporariamente bloqueado devido a atividade suspeita",
            });
        }

        const requestCheck = ipTracker.trackRequest(clientIP);

        if (!requestCheck.allowed) {
            const response = {
                timestamp,
                ip: clientIP,
                endpoint: req.path,
                method: req.method,
                attackType: requestCheck.reason,
                requestCount: requestCheck.requestCount,
            };

            console.warn(
                `[ATAQUE] ${response.attackType} de ${clientIP} (${timestamp})`,
            );

            if (io) {
                io.emit("attack:detected", response);
            }

            return res.status(429).json({
                error: "Muitas Requisições",
                message:
                    "Excesso de requisições detectado. Tente novamente mais tarde.",
            });
        }

        const paramAnalysis = threatDetector.analisarParametros(req.query);

        if (paramAnalysis.isAttack) {
            const response = {
                timestamp,
                ip: clientIP,
                endpoint: req.path,
                method: req.method,
                attackType: paramAnalysis.type,
                details: paramAnalysis.details,
                maliciousInput: JSON.stringify(req.query),
            };

            console.error(
                `[ATAQUE] ${response.attackType} nos parâmetros de ${clientIP} (${timestamp})`,
            );

            if (io) {
                io.emit("attack:detected", response);
            }

            return res.status(403).json({
                error: "Proibido",
                message: `Entrada maliciosa detectada: ${paramAnalysis.details}`,
            });
        }

        if (
            ["POST", "PUT", "PATCH"].includes(req.method) &&
            req.body &&
            typeof req.body === "object"
        ) {
            const bodyAnalysis = threatDetector.analisarBody(req.body);

            if (bodyAnalysis.isAttack) {
                const response = {
                    timestamp,
                    ip: clientIP,
                    endpoint: req.path,
                    method: req.method,
                    attackType: bodyAnalysis.type,
                    details: bodyAnalysis.details,
                    maliciousInput: JSON.stringify(req.body),
                };

                console.error(
                    `[ATAQUE] ${response.attackType} no corpo de ${clientIP} (${timestamp})`,
                );

                if (io) {
                    io.emit("attack:detected", response);
                }

                return res.status(403).json({
                    error: "Proibido",
                    message: `Entrada maliciosa detectada: ${bodyAnalysis.details}`,
                });
            }
        }

        console.log(
            `[OK] Requisição limpa de ${clientIP} para ${req.path} (${timestamp})`,
        );

        req.clientIP = clientIP;

        next();
    };
}

module.exports = createSecurityDetector;
