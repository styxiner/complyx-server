-- Esto viene del repo styxiner/complyx:sql/01_create_tables.sql


CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE DOMAIN email AS citext
CHECK ( value ~ '^[a-zA-Z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$' );

-- Usuarios y roles
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) NOT NULL UNIQUE,
    email email NOT NULL UNIQUE,
    salted_password_hash VARCHAR NOT NULL,
    created_date TIMESTAMP NOT NULL DEFAULT now(),
    last_modified TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rolename VARCHAR(50) NOT NULL UNIQUE,
    created_date TIMESTAMP NOT NULL DEFAULT now(),
    last_modified TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE users_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    added_date TIMESTAMP NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

-- Agentes y grupos
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip INET NOT NULL,
    hostname VARCHAR,
    os_name VARCHAR(50),
    os_version VARCHAR(10),
    install_date TIMESTAMP NOT NULL DEFAULT now(),
    latest_connection TIMESTAMP NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true
);

CREATE UNIQUE INDEX idx_agents_ip ON agents (ip);

CREATE TABLE agent_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_date TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE agent_group_membership (
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    group_id UUID REFERENCES agent_groups(id) ON DELETE CASCADE,
    added_date TIMESTAMP NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, group_id)
);

-- Normativas
CREATE TABLE regulations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(250) NOT NULL,
    pdf_path VARCHAR(250) NOT NULL,
    added_date TIMESTAMP NOT NULL DEFAULT now(),
    last_modification TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE regulation_sections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    regulation_id UUID NOT NULL REFERENCES regulations(id) ON DELETE CASCADE,
    title VARCHAR
);

COMMENT ON TABLE regulation_sections IS 'Secciones de la normativa (ej. medida 8.28 de ISO 27001)';

-- Políticas
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(250) NOT NULL UNIQUE,
    version VARCHAR(10) NOT NULL,
    description TEXT,
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    created_date TIMESTAMP NOT NULL DEFAULT now(),
    last_modified TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE policy_elements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    name VARCHAR(100)
);

CREATE TABLE policy_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_element_id UUID NOT NULL REFERENCES policy_elements(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    rationale VARCHAR,
    check_command VARCHAR NOT NULL,
    created_date TIMESTAMP NOT NULL DEFAULT now()
);

COMMENT ON TABLE policy_checks IS 'JSON con el tipo de check y sus parámetros para el policy-engine del agente';

CREATE TABLE check_regulation_sections (
    check_id UUID REFERENCES policy_checks(id) ON DELETE CASCADE,
    regulation_section_id UUID REFERENCES regulation_sections(id) ON DELETE CASCADE,
    PRIMARY KEY (check_id, regulation_section_id)
);

CREATE TABLE policy_remediations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_check_id UUID NOT NULL REFERENCES policy_checks(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    description VARCHAR,
    remediation_command VARCHAR NOT NULL,
    created_date TIMESTAMP NOT NULL DEFAULT now()
);

COMMENT ON TABLE policy_remediations IS 'JSON con el tipo de remediación y sus parámetros para el remediation-engine del agente';

-- Asignaciones de políticas
CREATE TABLE agent_policies (
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    assigned_date TIMESTAMP NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, policy_id)
);

CREATE TABLE group_policies (
    group_id UUID REFERENCES agent_groups(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    assigned_date TIMESTAMP NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, policy_id)
);

-- Amenazas y riesgos
CREATE TABLE threats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    category VARCHAR(50),
    severity_score NUMERIC(3,1) CHECK (severity_score >= 0 AND severity_score <= 10),
    created_date TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE risks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    threat_id UUID NOT NULL REFERENCES threats(id) ON DELETE RESTRICT,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    impact NUMERIC(3,1) CHECK (impact >= 0 AND impact <= 10),
    probability NUMERIC(3,1) CHECK (probability >= 0 AND probability <= 10),
    risk_level VARCHAR(20) CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'accepted', 'transferred', 'closed')),
    created_date TIMESTAMP NOT NULL DEFAULT now(),
    review_date TIMESTAMP,
    acceptance_date TIMESTAMP
);

CREATE TABLE risk_policies (
    risk_id UUID REFERENCES risks(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    PRIMARY KEY (risk_id, policy_id)
);

-- Resultados de checks (tabla nueva, no en el schema original)
CREATE TABLE check_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    check_id UUID NOT NULL REFERENCES policy_checks(id) ON DELETE CASCADE,
    passed BOOLEAN NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    actual_value TEXT,
    expected_value TEXT,
    executed_at TIMESTAMP NOT NULL,
    received_at TIMESTAMP NOT NULL DEFAULT now(),
    UNIQUE (agent_id, check_id, executed_at)
);

CREATE INDEX idx_check_results_agent_check ON check_results (agent_id, check_id, executed_at DESC);

-- Scores de cumplimiento calculados (tabla nueva)
CREATE TABLE compliance_scores (
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    policy_element_id UUID REFERENCES policy_elements(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    total_checks INTEGER NOT NULL DEFAULT 0,
    passed_checks INTEGER NOT NULL DEFAULT 0,
    score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    last_updated TIMESTAMP NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, policy_element_id)
);
