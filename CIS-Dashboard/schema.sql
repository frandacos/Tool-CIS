-- Clientes (organizaciones/empresas a las que se les audita infraestructura)
CREATE TABLE IF NOT EXISTS client (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Servidores de un cliente. 'hostname' es orientativo para matchear contra
-- la columna Hostname de los CSV de auditoria, pero la asociacion real de
-- una corrida a un servidor se hace eligiendo el servidor a mano al importar
-- (no auto-matching), para que la trazabilidad no dependa de que el nombre
-- coincida exacto (FQDN vs NetBIOS, mayusculas, etc.)
CREATE TABLE IF NOT EXISTS server (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL REFERENCES client(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    hostname TEXT,
    criticality TEXT NOT NULL DEFAULT 'Medium',
    description TEXT,
    benchmark TEXT NOT NULL DEFAULT 'WS2025',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_server_client ON server(client_id);

-- Catalogo canonico de controles por benchmark (importado desde cis2025_controls_master.csv,
-- cis_debian13_controls_master.csv, ...). PK (benchmark, control_id): los IDs se repiten entre benchmarks.
-- remediation_hint: resumen de que toca Set-CIS_WS2025_<control_id> al remediar
-- (clave de registro, politica local, user right, etc.), generado por
-- Script-CIS/.../inventory/gen_remediation_hints.py e importado desde
-- remediation_hints.csv. NULL si el control no tiene Set-CIS_WS2025_*
-- (ManualReviewRequired) o si todavia no se importo ese CSV.
-- manual_remediation: seccion "Remediation:" oficial del benchmark CIS
-- (UI Path via GPO), extraida de cis2025.md por gen_manual_remediation.py
-- e importada desde manual_remediation.csv -- el procedimiento manual, sin
-- pasar por el Set-CIS_WS2025_* de CISHarden.
CREATE TABLE IF NOT EXISTS control_catalog (
    benchmark TEXT NOT NULL DEFAULT 'WS2025',
    control_id TEXT NOT NULL,
    title TEXT NOT NULL,
    chapter TEXT NOT NULL,
    profile_scope TEXT,
    level TEXT,
    page TEXT,
    remediation_hint TEXT,
    manual_remediation TEXT,
    PRIMARY KEY (benchmark, control_id)
);

-- Una fila por cada archivo de auditoria importado (una corrida de Invoke-CISAudit).
-- server_id puede ser NULL: corridas importadas antes de que existiera el
-- modelo de clientes/servidores, o corridas que todavia no se asignaron a
-- un servidor -- se pueden asignar despues desde la pantalla de la corrida,
-- no se pierden.
CREATE TABLE IF NOT EXISTS audit_run (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER REFERENCES server(id) ON DELETE SET NULL,
    hostname TEXT NOT NULL,
    source_filename TEXT,
    label TEXT,
    benchmark TEXT NOT NULL DEFAULT 'WS2025',
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Resultado de cada control dentro de una corrida
CREATE TABLE IF NOT EXISTS control_result (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES audit_run(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    title TEXT,
    status TEXT NOT NULL,
    expected_value TEXT,
    actual_value TEXT,
    notes TEXT,
    result_timestamp TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_result_run ON control_result(run_id);
CREATE INDEX IF NOT EXISTS idx_control_result_control ON control_result(control_id);
CREATE INDEX IF NOT EXISTS idx_control_result_status ON control_result(status);

-- Decision humana sobre un control, por servidor (un mismo control puede
-- tener una decision distinta en cada servidor -- ej. 5.2 Print Spooler
-- puede ser 'RiskAccepted' en un servidor de impresion y 'Compliant' en
-- cualquier otro). Independiente de las corridas importadas: no se pisa al
-- reimportar un CSV nuevo del mismo servidor.
CREATE TABLE IF NOT EXISTS manual_review (
    server_id INTEGER NOT NULL REFERENCES server(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    decision TEXT NOT NULL DEFAULT 'Pending',
    reviewer TEXT,
    evidence_notes TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (server_id, control_id)
);
