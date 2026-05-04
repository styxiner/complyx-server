-- Migration 003: tokens de enrolamiento de un solo uso

CREATE TABLE enroll_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- SHA-256 del token en claro. Nunca almacenamos el token en claro.
    token_hash    VARCHAR(64) NOT NULL UNIQUE,
    -- Hostname del endpoint al que está destinado este token (informativo)
    hostname_hint VARCHAR(255),
    created_at    TIMESTAMP NOT NULL DEFAULT now(),
    expires_at    TIMESTAMP NOT NULL,
    -- NULL mientras no se haya usado. Se escribe en el momento del enrolamiento.
    used_at       TIMESTAMP
);

-- Índice para la búsqueda por hash (la operación más frecuente)
CREATE INDEX idx_enroll_tokens_hash ON enroll_tokens (token_hash);

-- Índice para limpiar tokens expirados periódicamente
CREATE INDEX idx_enroll_tokens_expires ON enroll_tokens (expires_at)
    WHERE used_at IS NULL;
