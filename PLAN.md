# Plan por etapas — Herramienta CIS Windows Server 2025

Base real extraída de `cis2025.md` (convertido de UTF-16LE a UTF-8 y parseado
con [`inventory/parse_toc.py`](inventory/parse_toc.py)):
**454 controles** "Automated"/"Manual" (452 Automated + 2 Manual) en 7
capítulos aplicables (los capítulos 6, 7, 8, 10-16 del benchmark no traen
recomendaciones numeradas para Server 2025, así que no generan etapa).
Inventario completo en
[`inventory/cis2025_controls_master.csv`](inventory/cis2025_controls_master.csv).

> **Nota de validación (corrección post-revisión cruzada):** el primer parseo
> automático había contado solo 415 controles. Al validar ese inventario
> contra un conteo independiente se detectaron **2 bugs del parser**, no del
> benchmark: (1) caracteres de salto de página (`\f`) pegados al inicio de la
> línea siguiente a un corte de página, que rompían el regex de "inicio de
> línea" y hacían desaparecer silenciosamente el control (ej. 1.1.4, 2.2.28);
> (2) un límite de profundidad de numeración (máx. 5 niveles) que descartaba
> IDs de hasta 7 niveles del capítulo 18 (ej. `18.10.42.11.1.1.1`), perdiendo
> 24 controles ahí. Corregido y re-generado: el total pasó de 415 a **454**,
> que coincide exacto con el conteo independiente, incluyendo los 2 controles
> Manual (`1.2.3` y `2.3.11.5`). Queda como lección de metodología: **nunca
> confiar en un solo conteo automático sin una segunda fuente de
> verificación**, sobre todo en documentos con saltos de página embebidos.

| Cap. | Sección | Controles |
|---|---|---|
| 1 | Account Policies (Password/Lockout) | 11 (7 Password + 4 Lockout) |
| 2 | Local Policies (User Rights Assignment / Security Options) | 118 (48 + 70) |
| 5 | System Services | 2 |
| 9 | Windows Defender Firewall (Domain/Private/Public) | 23 |
| 17 | Advanced Audit Policy Configuration | 34 |
| 18 | Administrative Templates (Computer) | 255 |
| 19 | Administrative Templates (User) | 11 |
| **Total** | | **454** |

## Etapa 0 — Preparación e inventario (ya ejecutada)

- [x] Detectar encoding real del benchmark (UTF-16LE con BOM) y generar copia
  UTF-8 legible para parseo.
- [x] Extraer el Table of Contents completo y generar
  `inventory/cis2025_controls_master.csv` con las 415 filas (control_id,
  título, alcance DC/MS/All, columnas de estado vacías).
- [ ] Levantar/confirmar el servidor de laboratorio (Windows Server 2025,
  aislado, snapshot tomable) donde se va a auditar y remediar en cada etapa.
  **Necesito que me confirmes: nombre/IP del server de lab, si es DC o
  Member Server, y si tenés WinRM/PSRemoting habilitado desde donde vamos a
  ejecutar.**
- [ ] Crear el esqueleto del módulo `CISHarden` (carpetas `Public/`,
  `Private/`, `Tests/`, `Reports/`) y el orquestador base
  (`Invoke-CISAudit.ps1`) que solo sabe recorrer capítulos y no tiene ningún
  `Test-*` todavía.

Criterio de cierre: el CSV existe con 415 filas, el server de lab responde
`Test-WSMan`, el esqueleto del módulo importa sin errores (`Import-Module` en
verde).

## Etapa 1 — Account Policies (11 controles) ✅ implementada

1.1 Password Policy (7) + 1.2 Account Lockout Policy (4). Todo vía
`secedit /export` / `Get-ADDefaultDomainPasswordPolicy` (DC) o
`net accounts` (MS). Etapa chica, ideal para validar el patrón
Test-*/Set-*/Pester antes de escalar a capítulos grandes.

Validación: correr `Test-CIS_1_*` contra el lab, forzar 2-3 controles a
estado no conforme a mano, confirmar que el audit los detecta, remediar,
re-auditar y confirmar Pass. Marcar las 11 filas del CSV (incluye 1.1.4, que
el primer inventario había perdido por el bug de parseo descripto arriba).

## Etapa 2 — Local Policies (118 controles, la más grande junto al cap. 18)

Se divide en 2 sub-etapas por volumen:
- **2a. User Rights Assignment (48) — ✅ implementada.** Todas vía `secedit`
  (sección `[Privilege Rights]`), que es el mecanismo oficial que usa el
  propio benchmark. Motor genérico en
  `CISHarden/Private/UserRightsEngine.ps1` (`Test-CISUserRight`/
  `Set-CISUserRight`, resuelve cada principal a SID en tiempo real contra el
  servidor, nunca hardcodea SIDs) + 48 funciones concretas en
  `CISHarden/Private/Chapter2-UserRightsAssignment.ps1`. Tests en
  `CISHarden/Tests/Chapter2-UserRights.Tests.ps1`. Pendiente correr Pester y
  validar en server de lab (`status_impl=OK`, falta `status_tested`/
  `status_validated`).

  > **Bug encontrado auditando un DC real (2026-07-14):** todos los
  > controles con valor esperado `'No One'` (2.2.1, 2.2.4, 2.2.14, 2.2.16,
  > 2.2.35, 2.2.39, 2.2.47) daban `Fail` con `ActualValue` vacío -- es decir,
  > el right realmente no tenía a nadie asignado (estado correcto) pero el
  > audit lo marcaba mal. Causa: `@($rights[$RightConstant])` sobre una clave
  > ausente del hashtable produce `@($null)`, que en PowerShell tiene
  > `.Count = 1`, no `0`. Corregido en `UserRightsEngine.ps1` filtrando
  > `$null` antes de contar (`Test-CISUserRight` y `Set-CISUserRight`). Los
  > mocks originales de Pester no lo detectaban porque simulaban el caso
  > vacío como `@{ SeTcbPrivilege = @() }` (array explícito) en vez de la
  > clave ausente (lo que realmente hace `secedit` cuando nadie tiene el
  > right) -- se agregó un test de regresión específico para ese escenario.
  > Lección: los mocks tienen que reproducir la forma exacta en que la
  > herramienta real (`secedit`) devuelve el caso límite, no solo el
  > resultado lógico esperado.
- 2b. Security Options (70) — pendiente. Mezcla de `secedit`
  (`[System Access]` / `[Registry Values]`), registro directo (`HKLM:\...`)
  y algunas GPO puras. Incluye el segundo control Manual del benchmark:
  `2.3.11.5` (Force logoff when logon hours expire).

Validación por sub-etapa (2a/2b) antes de pasar a la siguiente, y validación
agregada del capítulo completo (118/118 en el CSV) antes de Etapa 3.

## Etapa 3 — Windows Defender Firewall (23 controles)

9.1 Domain (7) + 9.2 Private (7) + 9.3 Public (9). Todo vía
`Get-NetFirewallProfile` / `Set-NetFirewallProfile` o registro
`HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall`.

## Etapa 4 — Advanced Audit Policy Configuration (34 controles)

17.1 a 17.9 (Account Logon, Account Management, Detailed Tracking, DS Access,
Logon/Logoff, Object Access, Policy Change, Privilege Use, System). Todo vía
`auditpol /get` y `auditpol /set /subcategory:...`. Validación: comparar
`auditpol /get /category:*` completo contra lo esperado, no solo subcategorías
sueltas.

## Etapa 5 — Administrative Templates (Computer) — 255 controles

El capítulo más grande, y el más afectado por el bug de profundidad de
numeración (algunos IDs de 18.10 llegan a 7 niveles, ej.
`18.10.42.11.1.1.1`). Se divide en sub-etapas por subsección para no perder
foco ni saltear nada:

| Sub-etapa | Sección | Controles |
|---|---|---|
| 5a | 18.1 Control Panel | 4 |
| 5b | 18.4 MS Security Guide | 6 |
| 5c | 18.5 MSS (Legacy) | 11 |
| 5d | 18.6 Network | 31 |
| 5e | 18.7 Printers | 18 |
| 5f | 18.8 Start Menu and Taskbar | 1 |
| 5g | 18.9 System | 68 |
| 5h | 18.10 Windows Components | 114 |
| 5i | 18.11 Custom Settings | 2 |

Casi todo es registro puro (`HKLM:\SOFTWARE\Policies\...` o
`HKLM:\SOFTWARE\Microsoft\...`), así que el patrón Test-*/Set-* es muy
repetitivo — pero **cada uno de los 222 se implementa individualmente**, no se
colapsan en una función "aplicar plantilla GPO". Validación por sub-etapa
(tabla de arriba) y validación agregada de todo el capítulo 18 al final.

## Etapa 6 — Administrative Templates (User) — 11 controles

19.5, 19.6, 19.7. Mismo patrón que Etapa 5, volumen chico.

## Etapa 7 — System Services (2 controles)

Print Spooler (Spooler) DC/MS — `Get-Service` / `Set-Service` +
`sc.exe sdset` si el benchmark pide ACL de servicio.

## Etapa 8 — Consolidación y orquestador final

- Unificar las 415 funciones en `Invoke-CISAudit.ps1` (parámetros `-Chapter`,
  `-ControlId`, `-All`) y `Invoke-CISRemediate.ps1` (con confirmación
  explícita y backup automático).
- Reporte HTML/CSV final con resumen por capítulo (Pass/Fail/NA/Manual) y
  detalle por control.
- Ejecutar el audit completo (415/415) contra el server de lab una vez más de
  punta a punta y confirmar que la cobertura del CSV es 100% en las tres
  columnas de estado.

## Cómo se garantiza que no se salta ningún control

1. El CSV de 415 filas es el checklist único: cada etapa cierra cuando sus
   filas correspondientes tienen `status_impl`, `status_tested` y
   `status_validated` completos.
2. Al final de cada etapa corro un chequeo de cobertura: cuento cuántas
   funciones `Test-*` existen en el módulo vs cuántas filas tiene esa sección
   del CSV — si no coinciden, no se avanza.
3. Los capítulos grandes (2, 18) están explícitamente sub-divididos para que
   ningún lote sea tan grande como para "perder" controles en el camino.
4. Antes de cerrar cada capítulo, releo la sección correspondiente del cuerpo
   del documento (no solo el TOC) para cazar controles que el parseo
   automático del índice haya partido mal.
5. El inventario nunca se da por definitivo con un solo conteo: se validó
   contra un recuento independiente y así se detectaron los 2 bugs de
   parseo descriptos al inicio de este documento (form-feed en saltos de
   página y límite de profundidad de numeración), que hacían perder 39
   controles silenciosamente (415 → 454 reales). El script de parseo queda
   versionado en `inventory/parse_toc.py` para poder re-auditarlo.

## Cómo se valida cada control a medida que se avanza

Por cada control, al implementarlo:
1. Ejecutar `Test-CIS_<id>` en el server de lab en su estado por defecto
   (recién instalado o snapshot limpio) y anotar el resultado esperado según
   el benchmark (`Default Value`).
2. Forzar el estado "no conforme" (manualmente o con `Set-*` invertido) y
   confirmar que `Test-*` lo detecta como `Fail`.
3. Correr `Set-CIS_<id>` y re-auditar: debe pasar a `Pass`.
4. Restaurar desde el backup tomado en el paso 3 y confirmar que
   `Test-*` vuelve a marcar el estado original correctamente.
5. Solo entonces se marca la fila como validada en el CSV.

## Qué necesito de vos para arrancar Etapa 0 de verdad

- Confirmación de que puedo usar `SYSTEM_PROMPT.md` como contrato de trabajo
  para las próximas sesiones (o si lo vas a pegar en otra herramienta/LLM).
- Datos del server de laboratorio (rol DC/MS, acceso WinRM) para poder
  validar cada control a medida que lo construyo, en vez de solo generar
  código sin probarlo.
