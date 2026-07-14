# CIS Dashboard

Aplicación web local (Flask + SQLite) para visualizar los resultados de
auditoría que genera [`Tool-CIS/CISHarden`](../Tool-CIS) y gestionar la
revisión de los controles `ManualReviewRequired`, organizados por
**cliente → servidor** para trazabilidad multi-cliente. Es un proyecto
separado de `Tool-CIS`: este repo **no ejecuta PowerShell ni toca los
servidores**, solo lee los CSV que `Invoke-CISAudit` exporta.

## Qué hace hoy (v2)

- **Clientes y servidores**: creá clientes, y bajo cada uno los servidores
  que le auditás (nombre, hostname orientativo, criticidad
  Critical/High/Medium/Low, descripción).
- Importa el catálogo canónico (`inventory/cis2025_controls_master.csv`,
  global, no depende de cliente/servidor) y corridas de auditoría
  (`Invoke-CISAudit -OutputPath`), **asignadas a mano a un servidor** al
  importar — no hay auto-matching por nombre, para que la trazabilidad no
  dependa de que el hostname coincida exacto.
- Dashboard por servidor: conteo Pass/Fail/NotApplicable/ManualReviewRequired/Error,
  cobertura por capítulo (con título, no solo el número) y por nivel de
  riesgo (Level 1 / Level 2 / Next Generation Windows Security), lista de
  controles en `Fail`.
- Historial: cada corrida importada queda guardada por servidor (no se
  pisan), así se puede ver la evolución de un servidor a lo largo del
  tiempo.
- Cola de revisión manual **por servidor**: el mismo control puede tener una
  decisión distinta en cada servidor (ej. Print Spooler `RiskAccepted` en un
  servidor de impresión, `Compliant` en cualquier otro). Marcá
  `Pending`/`Compliant`/`NonCompliant`/`RiskAccepted` con revisor y notas de
  evidencia, filtrable por servidor/capítulo/decisión.
- **Backup automático de la base** en cada arranque (`backups/`, se quedan
  los últimos 20) — antes de cualquier migración de esquema.

## Qué NO hace todavía (a futuro)

- No lanza remediaciones (`Set-CIS_*`) contra los servidores — hoy es
  solo lectura/visualización + registro de decisiones humanas. Requeriría
  conectividad hacia los servidores (PSRemoting/WinRM) y manejo de
  credenciales, un cambio de arquitectura deliberado a pensar aparte.

## Instalación

```bash
cd CIS-Dashboard
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Ejecutar

```bash
python3 app.py
```

Abre `http://127.0.0.1:5057` en el navegador. La base SQLite (`cisdash.sqlite3`)
se crea sola en el primer arranque, y en cada arranque se hace un backup
automático en `backups/` antes de aplicar cualquier cambio de esquema.

## Flujo de uso

1. **Clientes**: creá el cliente, y dentro de él los servidores que le vas a
   auditar (nombre, criticidad, descripción).
2. **Importar → catálogo**: subí `Tool-CIS/inventory/cis2025_controls_master.csv`
   una vez (y de nuevo si cambia el inventario). Es global, no pide servidor.
3. **Importar → corrida**: desde el servidor Windows, generá el CSV con
   `Invoke-CISAudit -OutputPath audit.csv` y subilo acá **eligiendo el
   servidor** de la lista desplegable (agrupada por cliente).
4. **Dashboard**: elegí cliente/servidor arriba a la izquierda, mirá qué
   capítulos y niveles de riesgo están peor, y la lista de `Fail`.
5. **Revisión manual**: para cada control de la cola, entrá al detalle (ya
   trae el servidor de contexto) y dejá la decisión + quién lo revisó + la
   evidencia.

### Corridas importadas antes de tener clientes/servidores

Si ya tenías corridas cargadas de la v1 (antes de este modelo), quedan
"Sin cliente asignado" — desde `/runs` o desde el detalle de la corrida
podés asignarlas a un servidor retroactivamente sin perder los datos.

## Estructura

```
app.py            # rutas Flask (clientes, servidores, dashboard, runs, import, control detail, manual review)
db.py             # conexion SQLite + backup automatico + migracion aditiva del schema
schema.sql        # tablas: client, server, control_catalog, audit_run, control_result, manual_review
templates/        # Jinja2, sin dependencias externas (CSS propio, sin JS pesado)
  _macros.html    # macro de las barras de cobertura (reusada en capitulos y niveles)
static/style.css
requirements.txt  # solo Flask
backups/          # copias automaticas de cisdash.sqlite3, una por arranque (ultimas 20)
```

## Datos que persisten

- `client` / `server`: se crean a mano, no se borran automáticamente.
- `control_catalog`: se pisa en cada reimportación (upsert por `control_id`).
- `audit_run` / `control_result`: se acumulan, nunca se borran automáticamente.
  `audit_run.server_id` puede quedar `NULL` (corrida sin asignar) hasta que
  se asocie a un servidor.
- `manual_review`: una fila por `(server_id, control_id)`, se actualiza cada
  vez que se guarda una revisión — es el registro de auditoría humana, no se
  toca al reimportar corridas.
- `manual_review_legacy`: si venías de la v1 (decisiones globales sin
  servidor), tus datos viejos quedaron acá tal cual, para consulta
  histórica — no se pierden, pero tampoco se muestran en la UI nueva (no hay
  forma automática de saber a qué servidor correspondía cada una).
