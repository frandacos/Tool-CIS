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
# Todo lo implementado hasta ahora (por ahora: capítulo 1, 11 controles)
Invoke-CISAudit -ReportCoverage

# Un capítulo puntual
Invoke-CISAudit -Chapter 1 -ReportCoverage

# Un control puntual
Invoke-CISAudit -ControlId '1.1.4'

# Exportar el resultado a CSV para el reporte
Invoke-CISAudit -Chapter 1 -OutputPath .\CISHarden\Reports\audit_$(Get-Date -Format yyyyMMdd_HHmmss).csv
```

Cada fila del resultado trae `ControlId`, `Title`, `Status`
(`Pass`/`Fail`/`NotApplicable`/`ManualReviewRequired`/`Error`),
`ExpectedValue`, `ActualValue`, `Hostname` y `Timestamp`.

`-ReportCoverage` además avisa si en ese capítulo faltan controles del CSV sin
`Test-CIS_*` implementada todavía — es el chequeo de "no te saltees ningún
control" que exige `PLAN.md`.

## Remediar (hace cambios reales en el servidor)

Remediar **siempre** primero en modo simulación:

```powershell
Invoke-CISRemediate -Chapter 1 -WhatIf
```

Revisar la salida, y recién ahí aplicar de verdad:

```powershell
Invoke-CISRemediate -Chapter 1
```

`Invoke-CISRemediate` solo toca controles que la auditoría marcó `Fail` (nunca
`Pass`, `NotApplicable` ni `ManualReviewRequired`), hace backup de la política
de seguridad actual antes de tocar nada (`CISHarden/Reports/backups/*.cfg` y,
para 1.1.6, un `.reg` de la clave `HKLM\System\CurrentControlSet\Control\SAM`),
y al final vuelve a auditar para confirmar que quedó en `Pass`.

### Restaurar un backup si algo sale mal

```powershell
secedit /configure /db C:\Windows\security\database\secedit.sdb `
  /cfg .\CISHarden\Reports\backups\secedit_backup_<timestamp>.cfg /overwrite
```

## Correr los tests (Pester)

```powershell
Install-Module Pester -Force -SkipPublisherCheck   # si no lo tenés
Invoke-Pester .\CISHarden\Tests\Chapter1.Tests.ps1 -Output Detailed
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
  CISHarden.psd1 / .psm1      # manifest + loader del módulo
  Public/
    Invoke-CISAudit.ps1        # orquestador de auditoría
    Invoke-CISRemediate.ps1    # orquestador de remediación
  Private/
    Helpers.ps1                 # rol DC/MS, secedit export/set, backups
    Chapter1-AccountPolicies.ps1
    Chapter<N>-...ps1           # se van agregando etapa por etapa
  Tests/
    Chapter<N>.Tests.ps1        # Pester, uno por etapa
  Reports/
    backups/                    # backups de secedit/registro antes de remediar
inventory/
  cis2025_controls_master.csv   # checklist canónico de los 454 controles
SYSTEM_PROMPT.md                # contrato/reglas de construcción
PLAN.md                         # plan por etapas y estado de avance
```

## Estado actual

Ver la tabla de `PLAN.md`. Hoy: **Etapa 0 (esqueleto), Etapa 1 (Account
Policies, 11/11) y Etapa 2a (User Rights Assignment, 48/48) implementadas**;
falta correrlas en un server real para pasar de `status_impl` a
`status_tested`/`status_validated` en el CSV antes de seguir con la Etapa 2b
(Security Options, 70 controles).
