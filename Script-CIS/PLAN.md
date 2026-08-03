# Plan por etapas — Herramienta CIS Windows Server 2025

> **Nota de arquitectura (post-generalización):** este documento describe la
> construcción original del contenido de CIS Windows Server 2025, cuando
> todo vivía en un único módulo `CISHarden/`. Esa estructura se generalizó
> después a `CISHarden.Core` (motor genérico, reutilizable) +
> `Benchmarks/WS2025/CISHarden.WS2025` (contenido de este benchmark), para
> poder agregar otros benchmarks con el tiempo — ver
> [`README.md`](README.md#arquitectura-core--un-módulo-por-benchmark). Las
> rutas de archivo mencionadas más abajo (`CISHarden/...`, `inventory/...`)
> son las de ANTES de la migración; el contenido y las decisiones que
> documentan siguen siendo válidos, pero hoy esos archivos viven bajo
> `Benchmarks/WS2025/CISHarden.WS2025/` y las funciones `Test-CIS_*`/
> `Set-CIS_*` tienen el tag `WS2025` (ej. `Test-CIS_1_1_1` → `Test-CIS_WS2025_1_1_1`).

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
  >
  > **Confirmado en DC01 real (2026-07-14):** tras el fix, los 7 controles
  > `'No One'` (2.2.1, 2.2.4, 2.2.14, 2.2.16, 2.2.35, 2.2.39, 2.2.47) pasaron
  > a `Pass` como corresponde; el resto de los 48 se mantuvo igual (los
  > `Fail` restantes son defaults reales de Windows, no bugs). `status_tested`
  > marcado `OK` para las 48 filas 2.2.\* del CSV. Falta el ciclo de
  > remediación completo (forzar Fail → `Set-CIS_*` → re-audit Pass →
  > restaurar backup → confirmar estado original) para marcar
  > `status_validated`.
- **2b. Security Options (70) — ✅ implementada.** 6 controles reutilizan
  `Get-CISSecurityPolicy`/`Set-CISSecurityPolicyValue` (secedit
  `[System Access]`: `EnableGuestAccount`, `NewAdministratorName`,
  `NewGuestName`, `SubmitControl`, `RefusePasswordChange`,
  `LSAAnonymousNameLookup`). El resto vía `CISHarden/Private/RegistryEngine.ps1`
  (motor genérico `Test-CISRegistryValue`/`Set-CISRegistryValue` con
  validadores reutilizables: exacto, rango, bitmask, multi-string
  contains/empty, not-configured, one-of) +
  `CISHarden/Private/Chapter2-SecurityOptions.ps1` (70 funciones concretas).
  Tests en `CISHarden/Tests/Chapter2-SecurityOptions.Tests.ps1`.
  **3 controles quedaron en `ManualReviewRequired`** en vez de adivinar una
  clave de registro sin confirmar (regla 3 del system prompt): `2.3.11.5`
  (Manual en el propio benchmark), `2.3.5.4` y `2.3.11.7` (variantes de
  enforcement/encryption de LDAP sin una clave de registro distinta de las
  ya usadas por controles vecinos confirmada con certeza). Pendiente correr
  Pester y validar en server de lab.

  > **Bug encontrado auditando un DC real (2026-07-14):** `2.3.1.3` y
  > `2.3.1.4` (rename de Administrator/Guest) daban `Pass` siempre, sin
  > importar si la cuenta estaba renombrada o no -- confirmado en el DC de
  > prueba, que sigue con los nombres default y aun asi marcaba `Pass`.
  > Causa: `secedit /export` envuelve los valores string de
  > `[System Access]` entre comillas literales (`NewAdministratorName =
  > "Administrator"`), y la comparacion contra el valor prohibido sin
  > comillas (`'Administrator'`) nunca coincidia -- el string con comillas
  > siempre parecia "distinto" del prohibido. Corregido con
  > `-replace '^"|"$', ''` antes de comparar en `Test-CIS_2_3_1_3` y
  > `Test-CIS_2_3_1_4`. Se agrego un test de regresion que mockea
  > `Get-CISSecurityPolicy` devolviendo el valor con comillas (como lo hace
  > secedit de verdad) en vez de un string limpio -- los tests originales no
  > lo detectaban porque el mock no reproducia el formato real. Misma
  > leccion que el bug de `@($null)` en Etapa 2a: el mock tiene que imitar
  > la forma exacta en que la herramienta real devuelve el dato.
  >
  > **Confirmado en DC01 real (2026-07-14):** tras el fix, `2.3.1.3` y
  > `2.3.1.4` dan `Fail` con `ActualValue` limpio (`Administrator`/`Guest`,
  > sin comillas) -- el estado real de ese DC, que no tiene esas cuentas
  > renombradas. `status_tested` marcado `OK` para las 70 filas 2.3.\* del
  > CSV. Capitulo 2 completo (118/118) auditado sin errores de PowerShell en
  > un DC real. Falta el ciclo de remediacion completo para marcar
  > `status_validated`.

Validación por sub-etapa (2a/2b) antes de pasar a la siguiente, y validación
agregada del capítulo completo (118/118 en el CSV) antes de Etapa 3.

## Etapa 3 — Windows Defender Firewall (23 controles) — ✅ implementada

9.1 Domain (7) + 9.2 Private (7) + 9.3 Public (9, incluye los 2 controles
exclusivos de ese perfil: Apply local firewall rules / Apply local
connection security rules). Reutiliza el mismo `RegistryEngine.ps1` de la
Etapa 2b (no hizo falta motor nuevo) sobre
`HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\<Perfil>Profile` y su
subclave `\Logging`. Código en
`CISHarden/Private/Chapter9-Firewall.ps1`, tests en
`CISHarden/Tests/Chapter9-Firewall.Tests.ps1`.

  > **Confirmado en DC01 real (2026-07-14):** los 23 controles dieron `Fail`
  > con `ActualValue` vacío. Verificado que NO es un bug: `Get-NetFirewallProfile`
  > muestra el firewall `Enabled: True` a nivel de servicio (config local por
  > defecto), pero `HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\...`
  > directamente no existe -- este DC no tiene ninguna GPO de firewall
  > aplicada. El benchmark audita específicamente si hay política
  > centralizada forzada (que es lo correcto: firewall "prendido por
  > default" no es lo mismo que firewall "gestionado y auditable via GPO").
  > `status_tested` marcado `OK` para las 23 filas. Falta el ciclo de
  > remediación completo para `status_validated`.

## Etapa 4 — Advanced Audit Policy Configuration (34 controles) — ✅ implementada

17.1 a 17.9 (Account Logon, Account Management, Detailed Tracking, DS Access,
Logon/Logoff, Object Access, Policy Change, Privilege Use, System). Motor en
`CISHarden/Private/AuditPolicyEngine.ps1`: lee con
`auditpol /get /subcategory:"<nombre>" /r` (formato CSV, más confiable de
parsear que la salida de texto libre) y escribe con
`auditpol /set /subcategory:"<nombre>" /success:.. /failure:..`, con 4 modos
de validación (`SuccessAndFailure`, `SuccessOnly`, `IncludeSuccess`,
`IncludeFailure` — estos últimos dos porque varios controles piden "incluye
Success" sin exigir Failure, o viceversa). La remediación de los modos
`Include*` no apaga el flag contrario si ya estaba prendido, para no reducir
auditoría existente al remediar un mínimo. 34 funciones en
`CISHarden/Private/Chapter17-AdvancedAudit.ps1`, tests en
`CISHarden/Tests/Chapter17-AdvancedAudit.Tests.ps1`.

  > **Confirmado en DC01 real (2026-07-14):** las 34 subcategorías se
  > leyeron sin errores; la mezcla de `Pass`/`Fail`/`No Auditing` es
  > coherente con el baseline de auditoría real que trae Windows Server de
  > fábrica (no arranca en blanco: `Logon`, `Other System Events`,
  > `System Integrity`, etc. ya vienen en `Success and Failure` por
  > defecto). `status_tested` marcado `OK` para las 34 filas. Falta el ciclo
  > de remediación completo para `status_validated`.

## Etapa 5 — Administrative Templates (Computer) — 255 controles

El capítulo más grande, y el más afectado por el bug de profundidad de
numeración (algunos IDs de 18.10 llegan a 7 niveles, ej.
`18.10.42.11.1.1.1`). Se divide en sub-etapas por subsección para no perder
foco ni saltear nada:

| Sub-etapa | Sección | Controles | Estado |
|---|---|---|---|
| 5a | 18.1 Control Panel | 4 | ✅ implementada |
| 5b | 18.4 MS Security Guide | 6 | ✅ implementada |
| 5c | 18.5 MSS (Legacy) | 11 | ✅ implementada |
| 5d | 18.6 Network | 31 | ✅ implementada (17 registro + 14 Manual) |
| 5e | 18.7 Printers | 18 | ✅ implementada (5 registro + 13 Manual) |
| 5f | 18.8 Start Menu and Taskbar | 1 | ✅ implementada |
| 5g | 18.9 System | 68 | ✅ implementada (62 registro + 6 Manual) |
| 5h | 18.10 Windows Components | 114 | ✅ implementada (103 registro + 11 Manual) |
| 5i | 18.11 Custom Settings | 2 | ✅ implementada (18.11.2 Manual) |

Casi todo es registro puro (`HKLM:\SOFTWARE\Policies\...` o
`HKLM:\SOFTWARE\Microsoft\...`), así que el patrón Test-*/Set-* es muy
repetitivo — pero **cada uno de los 255 se implementa individualmente**, no se
colapsan en una función "aplicar plantilla GPO". Validación por sub-etapa
(tabla de arriba) y validación agregada de todo el capítulo 18 al final.

**Primer bloque (5a+5b+5c+5f+5i, 24 controles) implementado** en
`CISHarden/Private/Chapter18a-SmallSections.ps1`, reutilizando
`RegistryEngine.ps1` (sin motor nuevo). `18.11.2` quedó
`ManualReviewRequired` — es un "Custom Setting" del propio benchmark sin
ADMX oficial de Microsoft detrás, y no encontré con certeza la clave de
registro correspondiente. Tests en
`CISHarden/Tests/Chapter18a-SmallSections.Tests.ps1`.

  > **Confirmado en DC01 real (2026-07-14):** las 24 corrieron sin errores
  > de PowerShell. 22 dieron `Fail` con `ActualValue` vacío -- esperado,
  > mismo patrón que el Capítulo 9 (Administrative Templates solo escribe
  > la clave de registro cuando una GPO la define; en un DC sin esas GPOs
  > aplicadas, la clave no existe). `18.4.1` dio `NotApplicable` (MS only,
  > correcto en un DC) y `18.11.2` `ManualReviewRequired` como se esperaba.
  > `status_tested` marcado `OK` para las 24 filas. Falta el ciclo de
  > remediación completo para `status_validated`.

**Bloque 18.6+18.7 (49 controles) implementado** en
`CISHarden/Private/Chapter18b-Network.ps1`: 20 con `RegistryEngine.ps1`
(incluye `18.6.14.1` Hardened UNC Paths, caso especial con dos entradas en
una misma clave, validación a medida) y **29 declarados
`ManualReviewRequired`** por decisión explícita (ver pregunta al usuario del
2026-07-14): son funcionalidades nuevas de Windows Server 2025 (hardening
SMB client/server, Redirection Guard, Windows Protected Print, políticas
TLS/SSL para IPP, bloque RPC del Print Spooler) donde no había certeza
suficiente sobre la clave de registro exacta como para automatizar sin
riesgo de reportar mal. Tests en
`CISHarden/Tests/Chapter18b-Network.Tests.ps1` (incluye un test que confirma
que los 29 Manual efectivamente devuelven ese estado, no un valor
inventado).

  > **Confirmado en DC01 real (2026-07-14):** las 49 corrieron sin errores.
  > El caso especial `18.6.14.1` (Hardened UNC Paths, dos entradas en una
  > misma clave) funcionó correctamente (`Fail` con detalle de qué faltaba:
  > `\\*\NETLOGON, \\*\SYSVOL`). Los 29 `ManualReviewRequired` se
  > comportaron como corresponde. `status_tested` marcado `OK` para las 49
  > filas. Falta el ciclo de remediación completo para `status_validated`.

**Bloque 18.9 System (68 controles) implementado** en
`CISHarden/Private/Chapter18c-System.ps1`: 62 vía `RegistryEngine.ps1`
(Device Guard/VBS/Credential Guard, Windows LAPS —esquema muy documentado,
confianza alta—, Kernel DMA Protection, LSASS protected process, power
management, RPC, NTP, y el bloque clásico de "Internet Communication
settings" 18.9.20.1.x) + **6 `ManualReviewRequired`** (`18.9.17.1`,
`18.9.23.1`, `18.9.31.1.1`, `18.9.41.1`, `18.9.41.2`, `18.9.41.3` —
controles 2022+ poco documentados sin clave de registro confirmada con
certeza). Tests en `CISHarden/Tests/Chapter18c-System.Tests.ps1`.

  > **Confirmado en DC01 real (2026-07-14):** las 68 corrieron sin errores.
  > Las ramas DC/MS funcionaron correctamente: `18.9.5.5` (Credential
  > Guard, MS only) `NotApplicable` en el DC, `18.9.5.6` (misma
  > configuración, DC only) sí evaluó, `18.9.38.1/38.2` y `18.9.41.3` (MS
  > only) `NotApplicable`, `18.9.41.2` (DC only) evaluó y dio
  > `ManualReviewRequired` como corresponde. `18.9.53.1.1` (NTP Client) dio
  > `Pass` real -- único habilitado por default en Windows. `status_tested`
  > marcado `OK` para las 68 filas. Falta el ciclo de remediación completo
  > para `status_validated`.

**Bloque 18.10 Windows Components (114 controles) implementado** en
`CISHarden/Private/Chapter18d-WindowsComponents.ps1`: 103 vía
`RegistryEngine.ps1` (bloques clásicos de 10-20 años: Remote Desktop
Services/Terminal Services ~20 controles, Event Log, Windows Installer,
Winlogon, AutoPlay, WinRM/WinRS, Windows Update, RSS, Software Protection
Platform, PowerShell logging; más Microsoft Defender ya establecido: MAPS,
Attack Surface Reduction, Network Protection, Real-time Protection
clásica, exclusiones/PUA) + **11 `ManualReviewRequired`** (features de
Microsoft Defender 2023-2025: EDR block mode, Brute-Force Protection,
Remote Encryption Protection/anti-ransomware, "Convert warn verdict to
block", más `18.10.16.4`, `18.10.29.2` y `18.10.93.2.1` sin clave/sección
confirmada con certeza). Tests en
`CISHarden/Tests/Chapter18d-WindowsComponents.Tests.ps1`.

  > **Confirmado en DC01 real (2026-07-14):** las 114 corrieron sin
  > errores; el CSV exportado tiene exactamente 255 filas (todo el
  > capítulo 18), sin excepciones. Se verificaron especialmente Event Log
  > (`Retention` como string `'0'` en las 4 categorías), el bloque RDP
  > (~20 controles, incluyendo valores en milisegundos) y WinRM
  > Client/Service (mismos nombres de valor, rutas distintas, sin
  > colisión). Dos `Pass` reales adicionales: `18.10.83.2` (Sign-in
  > automático tras reinicio, default real de Windows). `status_tested`
  > marcado `OK` para las 114 filas. Falta el ciclo de remediación
  > completo para `status_validated`.

**Con esto, el Capítulo 18 completo (255/255 controles) queda
implementado y auditado sin errores en un DC real.**

## Etapa 6 — Administrative Templates (User) — 11 controles — ✅ implementada

19.5.1.1, 19.6.6.1.1, 19.7.5.x, 19.7.8.x, 19.7.26.1, 19.7.46.2.1. Reutiliza
`RegistryEngine.ps1` sobre `HKCU:\...` (son "User Configuration" GPO
settings). **Limitación documentada**: como el script corre bajo la sesión
del usuario/servicio que lo ejecuta (no bajo cada usuario del servidor),
`Test-CIS_19_*` audita el `HKCU` de esa sesión puntual, no "todos los
usuarios" — mismo enfoque que usan la mayoría de las herramientas de
hardening públicas para este tipo de control. La auditoría definitiva de
que la GPO llega a los usuarios reales sigue siendo `gpresult /h` desde una
sesión de usuario representativa, o revisar la GPO directamente en el DC.
Ver comentario en `CISHarden/Private/Chapter19-UserTemplates.ps1`.

Durante esta etapa se encontró y corrigió un bug real en
`RegistryEngine.ps1`: el backup automático de `Set-CISRegistryValue` solo
traducía el prefijo `HKLM:\` para `reg export`, así que para estos 11
controles (que usan `HKCU:\`) el backup habría fallado silenciosamente
antes de remediar — violando la regla 5 del system prompt (siempre backup
antes de tocar nada). Corregido para soportar `HKLM`, `HKCU`, `HKCR`, `HKU`
y `HKCC`, con test de regresión en `CISHarden/Tests/Chapter5-19.Tests.ps1`.

## Etapa 7 — System Services (2 controles) — ✅ implementada

5.1 (DC only) y 5.2 (MS only), Print Spooler (Spooler) — vía
`Get-Service`/`Set-Service` (`StartupType`), no vía registro directo, en
`CISHarden/Private/Chapter5-SystemServices.ps1`.

**Con esto, los 454 controles del benchmark tienen `status_impl=OK`.**

  > **Confirmado en DC01 real (2026-07-14):** las 13 corrieron sin errores.
  > `5.1` detectó `Automatic` (default real de Windows Server), `5.2` dio
  > `NotApplicable` correctamente, y los 11 de capítulo 19 leyeron
  > `HKCU:\` sin problema en la sesión de Administrator. `status_tested`
  > marcado `OK` para las 13 filas. De paso se corrigió un descuido de
  > bookkeeping: las 11 filas del capítulo 1 (las primeras que se
  > validaron contra el DC, en la sesión inicial) nunca habían quedado
  > marcadas `status_tested` en el CSV -- ya corregido retroactivamente.
  > **Con esto: 454/454 `status_impl=OK` y 454/454 `status_tested=OK`.**

## Etapa 8 — Consolidación y orquestador final

- [x] `Invoke-CISAudit.ps1` soporta `-Chapter`, `-ControlId`, `-ControlIds`,
  `-Section`, `-OutputPath`, `-ReportCoverage` y funciona sin cambios contra
  los 454 controles.
- [x] **`Invoke-CISRemediate.ps1` ampliado (2026-07-14)** con 5 niveles de
  alcance explícitos: `-ControlId` (uno), `-ControlIds` (lista/"grupo"),
  `-Section` (subsección por prefijo, ej. `18.9`), `-Chapter` (capítulo
  completo), `-All` (los 454, requiere el switch explícito — sin alcance
  tira error en vez de asumir "todo", para que una remediación masiva nunca
  se dispare por accidente). Agregado: `-Force` para saltear la
  confirmación de lote en corridas desatendidas, `-LogPath` para exportar
  el detalle (`Remediated`/`Failed`/`SkippedNoFunction`/`WhatIf` +
  `PostStatus`) a CSV — pensado para importar en `CIS-Dashboard`, y
  manejo de errores por control (un `Set-CIS_*` que tira excepción no
  aborta el resto del lote, queda registrado como `Failed`). Tests en
  `CISHarden/Tests/InvokeCISRemediate.Tests.ps1`. Nota de diseño: no se
  reenvían `-WhatIf`/`-Confirm` explícitamente a los `Set-CIS_*` (muchos
  son wrappers simples sin `[CmdletBinding(SupportsShouldProcess)]` propio
  y no los aceptarían) — se apoya en la propagación automática de
  `$WhatIfPreference`/`$ConfirmPreference` de PowerShell hacia las
  funciones anidadas, que es el mecanismo estándar para esto.
- [ ] Reporte HTML (hoy solo CSV) con resumen por capítulo
  (Pass/Fail/NA/Manual) y detalle por control.
- [ ] Ejecutar el audit completo (454/454) contra el server de lab una vez
  más de punta a punta y confirmar que la cobertura del CSV es 100% en
  `status_tested`.
- [ ] Ciclo de remediación real (`Set-CIS_*`) probado end-to-end en al
  menos un puñado de controles por capítulo antes de marcar
  `status_validated` en el CSV — sigue pendiente en todos los capítulos
  (ver notas de cada etapa arriba). Ahora hay herramienta para probar los 5
  niveles de alcance (`-ControlId`/`-ControlIds`/`-Section`/`-Chapter`/`-All`),
  falta correrlo en el DC real.

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
