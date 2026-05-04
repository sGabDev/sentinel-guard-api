class DetectorDeAmeacas {
    constructor() {
        this.sqlPatterns = [
            /('(\s|%20)*(OR|AND)(\s|%20)*'|'(\s|%20)*=(\s|%20)*')/gi,
            /(UNION(\s|%20)+SELECT)/gi,
            /(DROP(\s|%20)+TABLE)/gi,
            /(INSERT(\s|%20)+INTO)/gi,
            /(DELETE(\s|%20)+FROM)/gi,
            /(UPDATE(\s|%20)+SET)/gi,
            /(EXEC(\s|%20)*\()/gi,
            /(EXECUTE(\s|%20)*\()/gi,
            /(-{2}|\/\*|\*\/|;)/gi,
            /(;(\s|%20)*(DROP|DELETE|UPDATE))/gi,
        ];

        this.xssPatterns = [
            /(<script[^>]*>.*?<\/script>)/gi,
            /(javascript:)/gi,
            /(<iframe[^>]*>)/gi,
            /(onerror(\s|%20)*=)/gi,
            /(onload(\s|%20)*=)/gi,
            /(onclick(\s|%20)*=)/gi,
            /(onmouseover(\s|%20)*=)/gi,
            /(<img[^>]*on)/gi,
            /(<svg[^>]*on)/gi,
        ];
    }

    detectarSQLInjection(input) {
        if (!input || typeof input !== "string") return false;

        for (let pattern of this.sqlPatterns) {
            if (pattern.test(input)) {
                return true;
            }
        }
        return false;
    }

    detectarXSS(input) {
        if (!input || typeof input !== "string") return false;

        for (let pattern of this.xssPatterns) {
            if (pattern.test(input)) {
                return true;
            }
        }
        return false;
    }

    analisarParametros(params) {
        if (!params || typeof params !== "object") {
            return { isAttack: false };
        }

        const values = Object.values(params).join(" ");

        if (this.detectarSQLInjection(values)) {
            return {
                isAttack: true,
                type: "SQL_INJECTION",
                details: "Padrão de SQL Injection detectado nos parâmetros",
            };
        }

        if (this.detectarXSS(values)) {
            return {
                isAttack: true,
                type: "XSS",
                details: "Padrão de XSS detectado nos parâmetros",
            };
        }

        return { isAttack: false };
    }

    analisarBody(body) {
        if (!body || typeof body !== "object") {
            return { isAttack: false };
        }

        const bodyString = JSON.stringify(body);

        if (this.detectarSQLInjection(bodyString)) {
            return {
                isAttack: true,
                type: "SQL_INJECTION",
                details: "Padrão de SQL Injection detectado no corpo",
            };
        }

        if (this.detectarXSS(bodyString)) {
            return {
                isAttack: true,
                type: "XSS",
                details: "Padrão de XSS detectado no corpo",
            };
        }

        return { isAttack: false };
    }
}

module.exports = new DetectorDeAmeacas();
