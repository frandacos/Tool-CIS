# CISHarden — Herramienta de auditoría/remediación CIS Windows Server 2025

Módulo de PowerShell para auditar y remediar el **CIS Microsoft Windows
Server 2025 Benchmark v2.0.0**, control por control, contra el checklist
canónico de `inventory/cis2025_controls_master.csv`.

Ver [`SYSTEM_PROMPT.md`](SYSTEM_PROMPT.md) para las reglas de construcción y
[`PLAN.md`](PLAN.md) para el estado de avance por etapas.

## Requisitos

- **Windows Server 2025** (o Windows 10/11 con PowerShell 5.1+ para testear
  lógica, aunque varios controles solo tienen sentido en un Server real).
- **PowerShell 5.1** o superior (Windows PowerShell o `pwsh`/PowerShell 7).
- Ejecutarse **como Administrador** — `secedit`, el registro de HKLM y los
  cambios de política local requieren privilegios elevados.
- **[Pester](https://pester.dev/)** si querés correr los tests (`Install-Module Pester -Force -SkipPublisherCheck`).
- Nada de esto corre en macOS/Linux: `secedit`, `auditpol`, `Win32_OperatingSystem`,
  el registro `HKLM:\...`, etc. son exclusivos de Windows. Este repo se editó
  en Mac, pero **hay que copiarlo/clonarlo a un servidor o VM Windows para
  ejecutarlo de verdad.**

## Cómo importar el módulo

Desde una consola de PowerShell **elevada** (Ejecutar como administrador), parado
en la carpeta del proyecto (`Tool-CIS`):

```powershell
Import-Module .\CISHarden\CISHarden.psd1 -Force
```

Si la política de ejecución bloquea el import:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module .\CISHarden\CISHarden.psd1 -Force
```

## Auditar (solo lectura, no cambia nada)

```powershell
# Los 454 controles del benchmark de una sola vez
Invoke-CISAudit -ReportCoverage -OutputPath .\CISHarden\Reports\audit_full_$(Get-Date -Format yyyyMMdd_HHmmss).csv

# Un capítulo puntual (ej. 2 = Local Policies, 18 = Administrative Templates Computer)
Invoke-CISAudit -Chapter 2 -OutputPath .\audit2.csv

# Un control puntual
Invoke-CISAudit -ControlId '1.1.4'
```

Cada fila del resultado trae `ControlId`, `Title`, `Status`, `ExpectedValue`,
`ActualValue`, `Notes`, `Hostname` y `Timestamp`. Los `Status` posibles y qué
significan:

| Status | Qué significa |
|---|---|
| `Pass` | El servidor ya cumple el control. |
| `Fail` | No cumple — candidato a `Invoke-CISRemediate`. |
| `NotApplicable` | Control `(DC only)`/`(MS only)` que no aplica al rol de este servidor. |
| `ManualReviewRequired` | El benchmark exige revisión manual (2 casos), o el control depende de una clave de registro de una feature nueva de Server 2025 que no se automatizó por falta de certeza (71 casos, todos documentados en `PLAN.md`) — **revisar a mano vía RSOP/gpresult, no hay `Set-CIS_*` para estos**. |
| `Error` | Algo falló al leer el valor (ej. un principal que no existe en este servidor) — mirar `Notes`. |

`-ReportCoverage` avisa si faltan controles del CSV sin `Test-CIS_*`
implementada en ese alcance (hoy no debería avisar nada: los 454 están
implementados).

### Un primer vistazo rápido antes de la corrida completa

Antes de auditar los 454 de una, es útil ver cuántos van a salir `Fail` sin
generar el CSV entero:

```powershell
$resultado = Invoke-CISAudit
$resultado | Group-Object Status | Select Name, Count
```

## Remediar (hace cambios reales en el servidor)

**No lo corras contra los 454 de una sin revisar antes.** Andá capítulo por
capítulo, revisando qué va a cambiar:

```powershell
# 1. Simular primero, siempre
Invoke-CISRemediate -Chapter 1 -WhatIf

# 2. Revisar la salida a ojo, y recién ahí aplicar de verdad
Invoke-CISRemediate -Chapter 1

# También se puede remediar un control puntual
Invoke-CISRemediate -ControlId '1.1.4'
```

`Invoke-CISRemediate` solo toca controles que la auditoría marcó `Fail`
(nunca `Pass`, `NotApplicable` ni `ManualReviewRequired` — para estos
últimos no hay `Set-CIS_*` que aplicar, hay que resolverlos a mano). Antes
de tocar cualquier cosa hace backup en `CISHarden\Reports\backups\`, con un
formato distinto según qué motor use el control:

| Backup | Cuándo se genera | Formato |
|---|---|---|
| `secedit_backup_<fecha>.cfg` | Controles de Cap. 1 y parte de Cap. 2 (secedit `[System Access]`) | INF exportado por `secedit /export` |
| `reg_<clave>_<fecha>.reg` | Controles de registro (Cap. 2.3, 9, 18, 19 — la mayoría) | Export de `reg.exe` de la clave completa |
| `auditpol_backup_<fecha>.csv` | Controles de Cap. 17 (Advanced Audit) | Backup completo de `auditpol /backup` |

Al final de cada `Invoke-CISRemediate` se vuelve a auditar automáticamente
para confirmar que los controles remediados pasaron a `Pass`.

### Restaurar un backup si algo sale mal

Según qué tipo de backup sea (mirá el nombre del archivo en
`CISHarden\Reports\backups\`):

```powershell
# secedit (Account Policies / User Rights / algunos de Security Options)
secedit /configure /db C:\Windows\security\database\secedit.sdb `
  /cfg .\CISHarden\Reports\backups\secedit_backup_<timestamp>.cfg /overwrite

# Un valor de registro puntual
reg import .\CISHarden\Reports\backups\reg_<clave>_<timestamp>.reg

# Advanced Audit Policy (capítulo 17)
auditpol /restore /file:.\CISHarden\Reports\backups\auditpol_backup_<timestamp>.csv
```

## Correr los tests (Pester)

```powershell
Install-Module Pester -Force -SkipPublisherCheck   # si no lo tenés

# Un capítulo puntual
Invoke-Pester .\CISHarden\Tests\Chapter1.Tests.ps1 -Output Detailed

# Todos los tests del módulo (incluye el test de cobertura total: confirma
# que existen las 454 funciones Test-CIS_*/Set-CIS_* contra el inventario)
Invoke-Pester .\CISHarden\Tests\ -Output Detailed
```

Los tests mockean `secedit`/registro/rol de servidor, así que corren en
cualquier Windows con PowerShell — no necesitan que la máquina esté realmente
hardening-eada. Esto valida la **lógica** de cada `Test-CIS_*`; la validación
real (que el cambio efectivamente aplique y persista) se hace en el server de
laboratorio siguiendo el procedimiento de `PLAN.md`
("Cómo se valida cada control a medida que se avanza").

## Estructura

```
CISHarden/
  CISHarden.psd1 / .psm1                    # manifest + loader del módulo
  Public/
    Invoke-CISAudit.ps1                      # orquestador de auditoría
    Invoke-CISRemediate.ps1                  # orquestador de remediación
  Private/
    Helpers.ps1                               # rol DC/MS, secedit System Access, backups
    UserRightsEngine.ps1                      # motor de Privilege Rights (secedit)
    RegistryEngine.ps1                        # motor genérico de valores de registro
    AuditPolicyEngine.ps1                     # motor de auditpol (Advanced Audit)
    Chapter1-AccountPolicies.ps1              # Cap. 1 — 11 controles
    Chapter2-UserRightsAssignment.ps1         # Cap. 2.2 — 48 controles
    Chapter2-SecurityOptions.ps1              # Cap. 2.3 — 70 controles
    Chapter5-SystemServices.ps1               # Cap. 5 — 2 controles
    Chapter9-Firewall.ps1                     # Cap. 9 — 23 controles
    Chapter17-AdvancedAudit.ps1               # Cap. 17 — 34 controles
    Chapter18a-SmallSections.ps1              # Cap. 18.1/18.4/18.5/18.8/18.11 — 24
    Chapter18b-Network.ps1                    # Cap. 18.6/18.7 — 49
    Chapter18c-System.ps1                     # Cap. 18.9 — 68
    Chapter18d-WindowsComponents.ps1          # Cap. 18.10 — 114
    Chapter19-UserTemplates.ps1               # Cap. 19 — 11 controles
  Tests/
    Chapter<N>*.Tests.ps1                     # Pester, uno por etapa/bloque
  Reports/
    backups/                                  # backups antes de remediar (secedit/reg/auditpol)
inventory/
  cis2025_controls_master.csv   # checklist canónico de los 454 controles
  parse_toc.py                  # script que generó el inventario (por si hay que re-auditarlo)
SYSTEM_PROMPT.md                # contrato/reglas de construcción
PLAN.md                         # plan por etapas, estado de avance y bugs encontrados/corregidos
```

## Estado actual

**Los 454 controles del benchmark tienen `status_impl=OK` y
`status_tested=OK`** (auditados sin un solo error de PowerShell en un DC
real, ver el detalle y las correcciones aplicadas en `PLAN.md`). 73
controles quedaron `ManualReviewRequired` (2 por definición del propio
benchmark, el resto por baja confianza deliberada en features nuevas de
Server 2025 sin clave de registro confirmada — nunca se inventó un valor).

Lo que falta para cerrar la Etapa 8 (consolidación final, ver `PLAN.md`):
correr Pester y validar Capítulos 5 y 19 en el server de lab; un reporte
HTML (hoy el orquestador ya exporta CSV); y el ciclo completo de
remediación (`Set-CIS_*` → re-audit → restaurar backup) probado en una
muestra de controles por capítulo antes de marcar `status_validated`.
