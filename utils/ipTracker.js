class RastreadorIP {
    constructor() {
        this.ipActivity = new Map();
        this.blockedIPs = new Map();

        this.config = {
            requestsPerMinute: 60,
            failedLoginThreshold: 5,
            blockDurationMinutes: 15,
            floodThreshold: 100,
        };
    }

    getClientIP(req) {
        return (
            req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
            req.connection.remoteAddress ||
            req.socket.remoteAddress ||
            "unknown"
        );
    }

    isIPBlocked(ip) {
        if (!this.blockedIPs.has(ip)) {
            return false;
        }

        const blockTime = this.blockedIPs.get(ip);
        const now = Date.now();
        const blockDuration = this.config.blockDurationMinutes * 60 * 1000;

        if (now - blockTime > blockDuration) {
            this.blockedIPs.delete(ip);
            return false;
        }

        return true;
    }

    trackRequest(ip) {
        if (this.isIPBlocked(ip)) {
            return {
                allowed: false,
                reason: "IP_BLOCKED",
                requestCount: 0,
            };
        }

        const now = Date.now();
        const minuteInMs = 60 * 1000;

        if (!this.ipActivity.has(ip)) {
            this.ipActivity.set(ip, {
                count: 0,
                lastReset: now,
                failedLogins: 0,
                lastFailedLogin: null,
            });
        }

        const activity = this.ipActivity.get(ip);

        if (now - activity.lastReset > minuteInMs) {
            activity.count = 0;
            activity.lastReset = now;
        }

        activity.count++;

        if (activity.count > this.config.requestsPerMinute) {
            return {
                allowed: false,
                reason: "RATE_LIMIT_EXCEEDED",
                requestCount: activity.count,
            };
        }

        return {
            allowed: true,
            reason: null,
            requestCount: activity.count,
        };
    }

    recordFailedLogin(ip) {
        const now = Date.now();

        if (!this.ipActivity.has(ip)) {
            this.ipActivity.set(ip, {
                count: 0,
                lastReset: now,
                failedLogins: 0,
                lastFailedLogin: now,
            });
        }

        const activity = this.ipActivity.get(ip);
        activity.failedLogins++;
        activity.lastFailedLogin = now;

        if (activity.failedLogins >= this.config.failedLoginThreshold) {
            this.blockIP(ip);
            return {
                blocked: true,
                failedAttempts: activity.failedLogins,
                reason: "BRUTE_FORCE_DETECTED",
            };
        }

        return {
            blocked: false,
            failedAttempts: activity.failedLogins,
        };
    }

    recordSuccessfulLogin(ip) {
        if (this.ipActivity.has(ip)) {
            this.ipActivity.get(ip).failedLogins = 0;
        }
    }

    blockIP(ip) {
        this.blockedIPs.set(ip, Date.now());
    }

    unblockIP(ip) {
        this.blockedIPs.delete(ip);
    }

    getIPStats(ip) {
        if (!this.ipActivity.has(ip)) {
            return null;
        }

        const activity = this.ipActivity.get(ip);
        return {
            ip,
            requestCount: activity.count,
            failedLogins: activity.failedLogins,
            isBlocked: this.isIPBlocked(ip),
            lastActivity: activity.lastReset,
        };
    }

    getBlockedIPs() {
        return Array.from(this.blockedIPs.keys());
    }

    clearAll() {
        this.ipActivity.clear();
        this.blockedIPs.clear();
    }
}

module.exports = new RastreadorIP();
