# CISHarden — Herramienta de auditoría/remediación de benchmarks CIS

Arquitectura genérica de PowerShell para auditar y remediar benchmarks CIS,
control por control, pensada para ir agregando benchmarks nuevos con el
tiempo (otras versiones de Windows Server/Client, y a futuro otras
plataformas) sin tocar el motor común.

Hoy trae dos benchmarks de contenido:

- **CIS Microsoft Windows Server 2025 Benchmark v2.0.0** (`CISHarden.WS2025`),
  contra el checklist canónico de
  `Benchmarks/WS2025/CISHarden.WS2025/inventory/cis2025_controls_master.csv`.
- **CIS Debian Linux 13 Benchmark v1.0.0** (`CISHarden.Debian13`) — **343 controles
  (capítulos 1-7) implementados y testeados con Pester** (mockeando el sistema),
  pendientes de validación en una Debian 13 real. Es el benchmark Linux más
  completo del proyecto. Ver [`Benchmarks/Debian13/PLAN_Debian13.md`](Benchmarks/Debian13/PLAN_Debian13.md)
  (decisiones, riesgos y desviaciones del benchmark control por control) y
  `Benchmarks/Debian13/CISHarden.Debian13/inventory/cis_debian13_controls_master.csv`.
- **CIS Debian Linux 10 Benchmark v2.0.0** (`CISHarden.Debian10`) — primer
  benchmark Unix/Linux del proyecto. Por ahora solo cubre el **Capítulo 1
  (Initial Setup, 67 controles)**; los capítulos 2-6 (~207 controles más)
  quedan pendientes. Ver `Benchmarks/Debian10/CISHarden.Debian10/inventory/cis_debian10_controls_master.csv`.

Ver [`SYSTEM_PROMPT.md`](SYSTEM_PROMPT.md) para las reglas de construcción y
[`PLAN.md`](PLAN.md) para el estado de avance por etapas.

## Arquitectura: Core + un módulo por benchmark

- **`CISHarden.Core`**: motor genérico, reutilizable por cualquier
  benchmark — más los orquestadores `Invoke-CISAudit` / `Invoke-CISRemediate`
  y el registro de benchmarks (`Get-CISBenchmarks`). No sabe nada del
  contenido de ningún benchmark en particular. Trae dos familias de motores
  de bajo nivel, según la plataforma del benchmark:
  - **Windows**: registro (`RegistryEngine`), políticas locales vía
    `secedit` (`Helpers`), `auditpol` (`AuditPolicyEngine`), user rights
    (`UserRightsEngine`).
  - **Linux/Unix**: módulos de kernel (`LinuxKernelModuleEngine`), particiones
    y opciones de montaje vía `findmnt`/fstab (`LinuxFstabEngine`), archivos
    de configuración/permisos (`LinuxFileEngine`), paquetes `dpkg`/`apt-get`
    (`LinuxPackageEngine`), servicios `systemd` (`LinuxServiceEngine`),
    parámetros de kernel vía `sysctl` (`LinuxSysctlEngine`), y una heurística
    de perfil Server/Workstation (`LinuxHelpers`, `Get-CISLinuxProfile`) —
    análoga a `Get-CISServerRole` (DC/MS) del lado Windows.
- **`Benchmarks/<Tag>/CISHarden.<Tag>`**: un módulo por benchmark (hoy
  `WS2025` y `Debian10`). Contiene sus funciones
  `Test-CIS_<Tag>_*`/`Set-CIS_<Tag>_*` (una por control), su inventario CSV,
  y una función `Get-CISBenchmarkInfo_<Tag>` que le dice a Core dónde está
  el inventario y con qué prefijo nombra sus funciones. `RequiredModules` en
  su manifest apunta a `CISHarden.Core`.
- El tag en el nombre de las funciones (`Test-CIS_WS2025_1_1_1`, no
  `Test-CIS_1_1_1`) existe para que dos benchmarks con el mismo `control_id`
  (ej. "1.1.1" en CIS WS2025 y en CIS Debian10) puedan convivir cargados en
  la misma sesión sin pisarse.

### Cómo agregar un benchmark nuevo

1. Crear `Benchmarks/<Tag>/CISHarden.<Tag>/` con la misma forma que
   `Benchmarks/WS2025/CISHarden.WS2025/` o `Benchmarks/Debian10/CISHarden.Debian10/`
   (`Private/` con los controles, `Public/Get-CISBenchmarkInfo_<Tag>.ps1`,
   `inventory/`, `Tests/`, manifest + loader).
2. Nombrar todas las funciones `Test-CIS_<Tag>_*`/`Set-CIS_<Tag>_*` y
   exportarlas junto con `Get-CISBenchmarkInfo_<Tag>` desde el `.psm1`.
3. `RequiredModules = @('CISHarden.Core')` en el `.psd1` del benchmark.
4. Si la plataforma del benchmark ya tiene motores en
   `CISHarden.Core/Public/Engines/` (Windows o Linux/Unix, ver arriba),
   reutilizalos. Si es una plataforma nueva (Azure, macOS, etc.), hay que
   evaluar aparte qué motores nuevos hacen falta antes de escribir el
   contenido del benchmark, siguiendo el mismo patrón (funciones
   `Test-CIS*`/`Get-CIS*`/`Set-CIS*` agnósticas de benchmark, agregadas a
   `CISHarden.Core/Public/Engines/` y exportadas desde el `.psd1`/`.psm1`
   de Core).

No hace falta tocar `CISHarden.Core` para agregar un benchmark nuevo cuya
plataforma ya tenga motores (Windows o Linux/Unix): solo se importa el
módulo nuevo y se lo referencia por `-Benchmark`.

## Requisitos

### Para CISHarden.WS2025 (Windows)

- **Windows Server 2025** (o Windows 10/11 con PowerShell 5.1+ para testear
  lógica, aunque varios controles solo tienen sentido en un Server real).
- **PowerShell 5.1** o superior (Windows PowerShell o `pwsh`/PowerShell 7).
- Ejecutarse **como Administrador** — `secedit`, el registro de HKLM y los
  cambios de política local requieren privilegios elevados.
- Nada de esto corre de verdad en macOS/Linux: `secedit`, `auditpol`, `reg.exe`,
  `Get-Service`, el registro `HKLM:\...`, etc. son exclusivos de Windows.
  Este repo se editó en Mac, pero **hay que copiarlo/clonarlo a un servidor
  o VM Windows para ejecutarlo de verdad.**

### Para CISHarden.Debian10 (Linux/Unix)

- **Debian 10** real (o cualquier Linux con `systemd`/`dpkg`/`apt` para
  testear lógica — los `Test-CIS_Debian10_*` llaman `modprobe`, `lsmod`,
  `findmnt`, `dpkg-query`, `systemctl`, `sysctl`, `stat`, `dconf`, etc., que
  no existen en macOS/Windows).
- **PowerShell 7+ (`pwsh`)** — es multiplataforma y corre nativo en Debian
  (`apt install powershell` o el paquete `.deb` de Microsoft).
- Ejecutarse como **root** (o con `sudo`) — leer `/etc/shadow`, editar
  `/etc/fstab`, `/etc/modprobe.d/`, `/etc/sysctl.d/`, instalar paquetes, etc.
  requieren privilegios elevados.
- Por ahora solo cubre el Capítulo 1 del benchmark (67 de ~274 controles) —
  ver "Estado actual" mas abajo.

### Para CISHarden.Debian13 (Linux)

Igual que Debian10 (Debian 13 real, `pwsh` 7+, root), más los binarios que usan
sus controles: `sshd`, `ufw`, `auditd`/`auditctl`, `chage`, `usermod`, `apt`,
`systemctl`, `findmnt`, `sysctl`, `dconf`/`pam-auth-update` (según qué esté
instalado; sin un componente instalado su control da `NotApplicable`/`Pass` o
`Fail` según lo defina el benchmark). Sin sistema Debian los `Test-*` devuelven
`Error` por binarios ausentes (esperado) — la lógica se valida con Pester.

**Antes de remediar (`Invoke-CISRemediate -Benchmark Debian13`) leé los riesgos
del `PLAN_Debian13.md`**: SSH (5.1), UFW (4.1), PAM (5.3), sudoers (5.2),
forwarding de red (3.3), `disk_full_action` de auditd (6.2.2.3) y `-e 2` (6.2.3.36)
pueden dejar el host sin acceso o inmutable. Los `Set-*` peligrosos exigen un
switch explícito (`-AllowSsh`, `-AcceptOutboundBlock`, `-RemoveNoPasswd`,
`-AcceptImmutable`, `-Purge`, ...) y validan/revierten (`sshd -t`, `visudo -cf`,
restauración de `/etc/pam.d/common-*`). Probar siempre con `-WhatIf` y con una
**segunda sesión abierta**.

```powershell
Import-Module ./CISHarden.Core/CISHarden.Core.psd1 -Force
Import-Module ./Benchmarks/Debian13/CISHarden.Debian13/CISHarden.Debian13.psd1 -Force
Invoke-CISAudit -Benchmark Debian13 -ReportCoverage -OutputPath ./audit_debian13.csv
Invoke-CISRemediate -Benchmark Debian13 -Chapter 1 -WhatIf
```

### Para ambos

- **[Pester](https://pester.dev/)** si querés correr los tests (`Install-Module Pester -Force -SkipPublisherCheck`).
  Los tests mockean los motores de Core (registro/secedit en Windows,
  modprobe/systemctl/dconf/etc. en Linux), así que corren en cualquier SO
  con PowerShell — no necesitan un servidor real hardening-eado. Esto valida
  la **lógica** de cada `Test-CIS_*`; la validación real (que el cambio
  efectivamente aplique y persista) se hace contra un servidor/VM real de la
  plataforma correspondiente.

## Cómo importar los módulos

Desde una consola de PowerShell **elevada** (Ejecutar como administrador), parado
en la carpeta del proyecto (`Script-CIS`):

```powershell
Import-Module .\CISHarden.Core\CISHarden.Core.psd1 -Force
Import-Module .\Benchmarks\WS2025\CISHarden.WS2025\CISHarden.WS2025.psd1 -Force
```

Si la política de ejecución bloquea el import:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Para ver qué benchmarks están instalados sin importarlos:

```powershell
Get-CISBenchmarks
```

## Auditar (solo lectura, no cambia nada)

Todos los comandos de `Invoke-CISAudit`/`Invoke-CISRemediate` requieren
`-Benchmark` (ej. `WS2025`) — es el único dato nuevo respecto a antes de la
generalización.

```powershell
# Los 454 controles del benchmark WS2025 de una sola vez
Invoke-CISAudit -Benchmark WS2025 -ReportCoverage -OutputPath .\CISHarden.Core\Reports\audit_full_$(Get-Date -Format yyyyMMdd_HHmmss).csv

# Un capítulo puntual (ej. 2 = Local Policies, 18 = Administrative Templates Computer)
Invoke-CISAudit -Benchmark WS2025 -Chapter 2 -OutputPath .\audit2.csv

# Un control puntual
Invoke-CISAudit -Benchmark WS2025 -ControlId '1.1.4'
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

`-ReportCoverage` avisa si faltan controles del CSV sin `Test-CIS_<Tag>_*`
implementada en ese alcance (hoy no debería avisar nada: los 454 de WS2025
están implementados).

### Un primer vistazo rápido antes de la corrida completa

```powershell
$resultado = Invoke-CISAudit -Benchmark WS2025
$resultado | Group-Object Status | Select Name, Count
```

### Ejemplo equivalente con Debian10 (Linux)

Desde una sesión de `pwsh` como root, parado en `Script-CIS`:

```powershell
Import-Module ./CISHarden.Core/CISHarden.Core.psd1 -Force
Import-Module ./Benchmarks/Debian10/CISHarden.Debian10/CISHarden.Debian10.psd1 -Force

# Los 67 controles del Capitulo 1 (unico implementado por ahora)
Invoke-CISAudit -Benchmark Debian10 -Chapter 1 -ReportCoverage

# Remediar en seco primero, despues de verdad
Invoke-CISRemediate -Benchmark Debian10 -Chapter 1 -WhatIf
Invoke-CISRemediate -Benchmark Debian10 -Chapter 1
```

## Remediar (hace cambios reales en el servidor)

`Invoke-CISRemediate` tiene 5 niveles de alcance además de `-Benchmark`
(obligatorio). **Siempre exige un alcance explícito** (`-ControlId`,
`-ControlIds`, `-Section`, `-Chapter`, `-Level` o `-All`) — si no pasás
ninguno, tira error en vez de asumir "remediar todo", para que nunca se
dispare una remediación masiva sin querer:

```powershell
# 1. Un control puntual
Invoke-CISRemediate -Benchmark WS2025 -ControlId '1.1.4' -WhatIf
Invoke-CISRemediate -Benchmark WS2025 -ControlId '1.1.4'

# 2. Un grupo de controles a mano (ej. una tanda curada de "quick wins")
Invoke-CISRemediate -Benchmark WS2025 -ControlIds '1.1.4','2.3.17.6','9.1.1' -WhatIf

# 3. Una subseccion por prefijo de ID (ej. todo 18.9.*)
Invoke-CISRemediate -Benchmark WS2025 -Section '18.9' -WhatIf

# 4. Un capitulo completo
Invoke-CISRemediate -Benchmark WS2025 -Chapter 2 -WhatIf
Invoke-CISRemediate -Benchmark WS2025 -Chapter 2

# 5. Los 454 controles del benchmark de una — requiere -All explicito
Invoke-CISRemediate -Benchmark WS2025 -All -WhatIf
Invoke-CISRemediate -Benchmark WS2025 -All -Force -LogPath .\remediacion_full_$(Get-Date -Format yyyyMMdd_HHmmss).csv
```

**Regla de oro: simulá primero con `-WhatIf` y revisá la salida antes de
correr sin él**, sobre todo en `-Chapter`/`-Section`/`-All`. Con `-WhatIf`
cada `Set-CIS_<Tag>_*` muestra su propio mensaje específico (qué clave de
registro/right/subcategoría va a tocar), no un mensaje genérico de lote.

Sin `-WhatIf`, antes de aplicar nada te pide una única confirmación de lote
("vas a remediar N controles, ¿seguís?") — pasá `-Force` para saltearla en
corridas desatendidas/programadas. `-LogPath` exporta un CSV con el detalle
de cada control (`Remediated`/`Failed`/`SkippedNoFunction`/`WhatIf`, y el
estado post-remediación) — pensado para importarlo después en
`CIS-Dashboard`. Si un `Set-CIS_<Tag>_*` puntual tira error, no aborta el
resto del lote: queda registrado como `Failed` y sigue con los demás.

`Invoke-CISRemediate` solo toca controles que la auditoría marcó `Fail`
(nunca `Pass`, `NotApplicable` ni `ManualReviewRequired` — para estos
últimos no hay `Set-CIS_<Tag>_*` que aplicar, hay que resolverlos a mano).
Antes de tocar cualquier cosa hace backup en `CISHarden.Core\Reports\backups\`
(el backup es responsabilidad de Core, no del benchmark — cualquier
benchmark de Windows que use los mismos motores queda cubierto), con un
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
`CISHarden.Core\Reports\backups\`):

```powershell
# secedit (Account Policies / User Rights / algunos de Security Options)
secedit /configure /db C:\Windows\security\database\secedit.sdb `
  /cfg .\CISHarden.Core\Reports\backups\secedit_backup_<timestamp>.cfg /overwrite

# Un valor de registro puntual
reg import .\CISHarden.Core\Reports\backups\reg_<clave>_<timestamp>.reg

# Advanced Audit Policy (capítulo 17)
auditpol /restore /file:.\CISHarden.Core\Reports\backups\auditpol_backup_<timestamp>.csv
```

## Correr los tests (Pester)

```powershell
Install-Module Pester -Force -SkipPublisherCheck   # si no lo tenés

# Importar los módulos ANTES de correr Pester -- InModuleScope necesita que
# ya esten cargados en la sesion al momento del discovery, la importacion
# que hace el BeforeAll de cada archivo de test no alcanza para eso.
Import-Module .\CISHarden.Core\CISHarden.Core.psd1 -Force
Import-Module .\Benchmarks\WS2025\CISHarden.WS2025\CISHarden.WS2025.psd1 -Force

# Los tests de Core (orquestador, alcance/seguridad de Invoke-CISRemediate)
Invoke-Pester .\CISHarden.Core\Tests\ -Output Detailed

# Los tests de contenido de WS2025 (un capítulo puntual o todos)
Invoke-Pester .\Benchmarks\WS2025\CISHarden.WS2025\Tests\Chapter1.Tests.ps1 -Output Detailed
Invoke-Pester .\Benchmarks\WS2025\CISHarden.WS2025\Tests\ -Output Detailed
```

Los tests mockean `secedit`/registro/rol de servidor, así que corren en
cualquier Windows con PowerShell — no necesitan que la máquina esté realmente
hardening-eada. Esto valida la **lógica** de cada `Test-CIS_WS2025_*`; la
validación real (que el cambio efectivamente aplique y persista) se hace en
el server de laboratorio siguiendo el procedimiento de `PLAN.md`
("Cómo se valida cada control a medida que se avanza").

Para `CISHarden.Debian10` (corre igual en cualquier SO con `pwsh`+Pester,
mockeando los motores Linux de Core en vez de invocar Debian real):

```powershell
Import-Module ./CISHarden.Core/CISHarden.Core.psd1 -Force
Import-Module ./Benchmarks/Debian10/CISHarden.Debian10/CISHarden.Debian10.psd1 -Force

Invoke-Pester ./Benchmarks/Debian10/CISHarden.Debian10/Tests/ -Output Detailed
```

## Estructura

```
CISHarden.Core/
  CISHarden.Core.psd1 / .psm1               # manifest + loader del motor generico
  Public/
    Invoke-CISAudit.ps1                      # orquestador de auditoria (-Benchmark, generico)
    Invoke-CISRemediate.ps1                  # orquestador de remediacion (-Benchmark, generico)
    BenchmarkRegistry.ps1                    # Get-CISBenchmarks / Resolve-CISBenchmarkModule / Get-CISBenchmarkInfo
    Engines/
      Helpers.ps1                             # rol DC/MS, secedit System Access, backups (Windows)
      UserRightsEngine.ps1                    # motor de Privilege Rights via secedit (Windows)
      RegistryEngine.ps1                      # motor generico de valores de registro (Windows)
      AuditPolicyEngine.ps1                   # motor de auditpol / Advanced Audit (Windows)
      LinuxHelpers.ps1                        # perfil Server/Workstation, wrapper de bash (Linux)
      LinuxKernelModuleEngine.ps1             # modulos de kernel: modprobe/lsmod/blacklist (Linux)
      LinuxFstabEngine.ps1                    # particiones y opciones de montaje: findmnt/fstab (Linux)
      LinuxFileEngine.ps1                     # contenido/permisos/owner de archivos (Linux)
      LinuxPackageEngine.ps1                  # paquetes dpkg/apt-get (Linux)
      LinuxServiceEngine.ps1                  # servicios systemd (Linux)
      LinuxSysctlEngine.ps1                   # parametros de kernel via sysctl (Linux)
  Tests/
    InvokeCISRemediate.Tests.ps1              # tests del orquestador con un benchmark ficticio
  Reports/
    backups/                                  # backups antes de remediar (secedit/reg/auditpol), de cualquier benchmark
Benchmarks/
  WS2025/
    CISHarden.WS2025/
      CISHarden.WS2025.psd1 / .psm1           # manifest + loader (RequiredModules: CISHarden.Core)
      Private/
        Chapter1-AccountPolicies.ps1          # Cap. 1 — 11 controles
        Chapter2-UserRightsAssignment.ps1     # Cap. 2.2 — 48 controles
        Chapter2-SecurityOptions.ps1          # Cap. 2.3 — 70 controles
        Chapter5-SystemServices.ps1           # Cap. 5 — 2 controles
        Chapter9-Firewall.ps1                 # Cap. 9 — 23 controles
        Chapter17-AdvancedAudit.ps1           # Cap. 17 — 34 controles
        Chapter18a-SmallSections.ps1          # Cap. 18.1/18.4/18.5/18.8/18.11 — 24
        Chapter18b-Network.ps1                # Cap. 18.6/18.7 — 49
        Chapter18c-System.ps1                 # Cap. 18.9 — 68
        Chapter18d-WindowsComponents.ps1      # Cap. 18.10 — 114
        Chapter19-UserTemplates.ps1           # Cap. 19 — 11 controles
      Public/
        Get-CISBenchmarkInfo_WS2025.ps1       # metadata que Core usa para orquestar este benchmark
      Tests/
        Chapter<N>*.Tests.ps1                 # Pester, uno por etapa/bloque
      inventory/
        cis2025_controls_master.csv           # checklist canonico de los 454 controles
        parse_toc.py                          # script que genero el inventario
  Debian10/
    cis_debian_10.md                          # benchmark original (fuente), UTF-16LE/CRLF
    CISHarden.Debian10/
      CISHarden.Debian10.psd1 / .psm1         # manifest + loader (RequiredModules: CISHarden.Core)
      Private/
        Chapter1a-FilesystemConfiguration.ps1 # 1.1.x — 34 controles (modulos, particiones, mount options)
        Chapter1b-SoftwareUpdatesAndAIDE.ps1  # 1.2.x-1.3.x — 5 controles (AIDE, updates/repos/GPG)
        Chapter1c-BootAndProcessHardening.ps1 # 1.4.x-1.5.x — 8 controles (bootloader, ASLR, core dumps)
        Chapter1d-MACBannersAndGDM.ps1        # 1.6.x-1.8.x — 20 controles (AppArmor, banners, GDM)
      Public/
        Get-CISBenchmarkInfo_Debian10.ps1     # metadata que Core usa para orquestar este benchmark
      Tests/
        Chapter1*.Tests.ps1, Coverage.Tests.ps1  # Pester, uno por bloque + cobertura del inventario
      inventory/
        cis_debian10_controls_master.csv      # checklist canonico (67 controles del Cap. 1 por ahora)
        cis_debian_10_utf8.md                 # benchmark convertido a UTF-8 (paso previo al parseo)
        parse_toc.py / parse_levels.py / build_master_csv.py  # scripts que generaron el inventario
SYSTEM_PROMPT.md                # contrato/reglas de construccion
PLAN.md                         # plan por etapas, estado de avance y bugs encontrados/corregidos
```

## Estado actual

**Los 454 controles de CIS WS2025 tienen `status_impl=OK` y
`status_tested=OK`** (auditados sin un solo error de PowerShell en un DC
real, ver el detalle y las correcciones aplicadas en `PLAN.md`). 73
controles quedaron `ManualReviewRequired` (2 por definición del propio
benchmark, el resto por baja confianza deliberada en features nuevas de
Server 2025 sin clave de registro confirmada — nunca se inventó un valor).

La estructura se generalizó a `CISHarden.Core` + `CISHarden.WS2025` para
poder agregar otros benchmarks (otras versiones de Windows Server/Client)
con el tiempo sin reescribir el motor. Todos los `Test-CIS_*`/`Set-CIS_*`
se renombraron con el tag `WS2025` y todo el flujo (audit → remediate →
backup → re-audit → tests) se revalidó tras la migración.

Lo que falta para cerrar la Etapa 8 (consolidación final, ver `PLAN.md`):
un reporte HTML (hoy el orquestador ya exporta CSV); y el ciclo completo de
remediación (`Set-CIS_WS2025_*` → re-audit → restaurar backup) probado en
una muestra de controles por capítulo antes de marcar `status_validated`.

**CIS Debian13: los 343 controles del benchmark (`status_impl=OK`,
`status_tested=OK` con Pester 5.6.1 — `status_validated` vacío hasta correrlo en
una Debian 13 real).** El inventario se verificó contra una segunda fuente (la
tabla del Appendix del benchmark: 343 = 343 controles). Detalle por etapa,
motores nuevos de Core (sysctl, systemd, dconf, sshd, PAM/sudoers en el módulo)
y desviaciones justificadas en `Benchmarks/Debian13/PLAN_Debian13.md`.

**CIS Debian10 arrancó con el Capítulo 1 (Initial Setup) como piloto: 67/67
controles tienen `Test-CIS_Debian10_*`/`Set-CIS_Debian10_*` implementados**,
`Invoke-CISAudit -Benchmark Debian10 -ReportCoverage` confirma cobertura
completa del inventario, y los 68 tests de Pester (67 controles + cobertura)
pasan mockeando los motores Linux de Core. Esto se armó y probó en macOS —
**no se validó todavía contra una Debian 10 real** (correr
`Invoke-CISAudit`/`-Remediate` en una VM/servidor real de Debian 10 como
root es el próximo paso antes de marcar `status_validated`). Los capítulos
2 (Services), 3 (Network Configuration), 4 (Access/Auth/Authorization), 5
(Logging and Auditing) y 6 (System Maintenance) — unos ~207 controles más —
quedan pendientes para etapas siguientes, siguiendo el mismo patrón
(inventario CSV → motores nuevos si hacen falta → `Test-*`/`Set-*` → Pester).
