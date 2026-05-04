-- Migration 002: certificados de agentes (PKI interna)

CREATE TABLE agent_certs (
    -- Un agente tiene como máximo un certificado vigente
    agent_id   UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    cert_pem   TEXT NOT NULL,
    -- Número de serie del certificado en hex. Usado para construir la CRL.
    serial     VARCHAR(64) NOT NULL UNIQUE,
    issued_at  TIMESTAMP NOT NULL DEFAULT now(),
    -- NULL mientras el certificado esté vigente
    revoked_at TIMESTAMP
);

CREATE INDEX idx_agent_certs_serial ON agent_certs (serial);
CREATE INDEX idx_agent_certs_revoked ON agent_certs (revoked_at) WHERE revoked_at IS NOT NULL;
