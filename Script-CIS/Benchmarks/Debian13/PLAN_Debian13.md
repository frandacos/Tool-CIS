# Plan por etapas — CIS Debian Linux 13 Benchmark v1.0.0

Módulo: `CISHarden.Debian13` (tag `Debian13`), mismo patrón que `Debian10`
(ver [`../../README.md`](../../README.md) y [`../../SYSTEM_PROMPT.md`](../../SYSTEM_PROMPT.md)).
Fuente de verdad: [`cis_debian_13.md`](cis_debian_13.md).

## Estado actual (Etapa 0 ✅)

- [x] Módulo esqueleto: `CISHarden.Debian13.psd1/.psm1`, `Public/Get-CISBenchmarkInfo_Debian13.ps1`.
- [x] Inventario canónico generado por
  [`inventory/build_master_csv.py`](CISHarden.Debian13/inventory/build_master_csv.py) →
  [`inventory/cis_debian13_controls_master.csv`](CISHarden.Debian13/inventory/cis_debian13_controls_master.csv):
  **343 controles** (327 Automated + 16 Manual; 265 Level 1 / 78 Level 2), 7 capítulos.
  Perfiles (Server/Workstation, L1/L2) leídos del bloque *Profile Applicability* de cada control.
- [x] Validación cruzada del conteo con una segunda fuente (lección de WS2025: nunca confiar en un solo parseo) —
  contar filas de la tabla del *Appendix: Summary Table* y comparar contra 343.
- [ ] Definir VM de laboratorio: Debian 13 limpia con snapshot, `pwsh` 7+, acceso root.

## Avance

- **Etapa 1 (1.1 Filesystem, 37) implementada y testeada con Pester 5.6.1 (12 tests OK, motores mockeados);
  pendiente `status_validated` en una Debian 13 real.** Archivo: `Private/Chapter1a-FilesystemConfiguration.ps1`.
  - Core: `Test-CISKernelModuleDisabled` gana `-DirName` (overlay -> `overlayfs`, firewire-core -> `firewire`), exige directorio no vacio y acepta `/usr/bin/{true,false}`, como pide el benchmark 13.
  - 1.1.1.11 es Manual (`ManualReviewRequired`); las particiones separadas (1.1.2.x.1) no se automatizan (solo advertencia), salvo `systemctl unmask tmp.mount` en 1.1.2.1.1.
  - Los tests usan `BeforeDiscovery` para importar el modulo: con `BeforeAll`, `InModuleScope` falla en discovery (asi tambien fallan hoy los tests de Debian10/Core).

- **Etapa 2 (1.2 Packages 10, 1.3 AppArmor 4, 1.4 Bootloader 2 = 16) implementada y testeada con mocks** (`Private/Chapter1b-PackagesAppArmorBootloader.ps1`); pendiente `status_validated` en VM real.
  - Core nuevo (reutilizable en etapas 3, 6, 15): `Test-CISPathAccess` (modo "igual o mas restrictivo" por bits, no por numero), `Get-CISSysctlPersistedValue` / `Test-CISSysctlSetting` (valor en ejecucion + primer valor persistido en los archivos de systemd-sysctl/UFW, como el Audit del benchmark) y `Set-CISSysctlEnforced` (comenta valores en conflicto, persiste y aplica).
  - Manuales: 1.2.1.1 y 1.2.2.1. Sin automatizar: 1.4.1 (hash interactivo). 1.3.1.2 requiere reinicio; 1.3.1.3 no confina procesos sin perfil.
  - Un array vacio devuelto por una funcion llega como `$null`: los helpers que distinguen "vacio" de "no existe" deben separar ambas condiciones (bug detectado por Pester en 1.3.1.2).

- **Etapa 3 (1.5 Process Hardening 13, 1.6 Banners 6, 1.7 GDM 11 = 30) implementada y testeada con mocks** (`Chapter1c-ProcessHardening.ps1`, `Chapter1d-BannersAndGDM.ps1`). **Capitulo 1 completo: 83/83 (`status_validated` pendiente en VM real).**
  - Core nuevo: `LinuxSystemdConfigEngine` (`Get/Set-CISSystemdConfigValue`, drop-in `/etc/<conf>.d/60-cis.conf`; lo reutilizan 2.3 timesyncd/chrony y 6.1 journald) y `LinuxDconfEngine` (`Get-CISDconfValue`, `Test-CISDconfPathLocked`, `Set-CISDconfKeyFile`, `Set-CISDconfLock`). `Test-CISSysctlSetting` acepta varios valores (1.5.3/1.5.8) y `Set-CISSysctlEnforced -AcceptValues`.
  - 1.5.3 y 1.5.10 son la misma clave (`kernel.yama.ptrace_scope`) en dos recomendaciones distintas del benchmark; se implementan las dos.
  - 1.6.x: el benchmark exige ademas revisar el contenido contra la politica del sitio; el Test solo automatiza el criterio objetivo (sin `\v \r \m \s` ni ID del SO) y lo aclara en `Notes`.
  - 1.7.x: sin GDM instalado son `Pass`; 1.7.1 es `NotApplicable` en Workstation. Los `Set-*` de dconf/gdm escriben rutas fijas de `/etc` y **no** tienen test con archivos reales (solo los Test/lectores): validar en VM.

- **Etapa 4 (2.1 Server Services 23, 2.2 Client Services 6 = 29) implementada y testeada con mocks** (`Chapter2a-ServicesServerClient.ps1`); acumulado 112/343. `status_validated` pendiente.
  - 2.1.1-2.1.20 ("not in use"): `Pass` si el paquete no esta instalado **o** si esta instalado pero sus unidades no estan enabled ni active (caso "requerido como dependencia" del benchmark). Tabla paquete/unidades tomada de cada control (ej. 2.1.19 = apache2+nginx / apache2.socket, apache2.service, nginx.service).
  - **Decision de diseno:** `Set-*` de 2.1.x hace la variante NO destructiva del benchmark (`systemctl stop` + `mask`); solo desinstala el paquete con `-Purge` explicito (`Set-CIS_Debian13_2_1_9 -Purge`). Como `Invoke-CISRemediate` no pasa parametros, nunca purga solo. Los clientes 2.2.x y 2.1.21 (xserver-common) si hacen `apt purge` (es la unica remediacion del benchmark).
  - **Desviacion consciente en 2.1.22:** el script del benchmark acepta `0.0.0.0` como valor "loopback" de `inet_interfaces`, pero 0.0.0.0 son todas las interfaces; aqui solo se aceptan loopback-only/loopback/127.0.0.1/::1/localhost. Es mas estricto que el script literal.
  - 2.1.23 es Manual. 2.1.21 es Level 2 - Server (`NotApplicable` en Workstation).

- **Etapa 5 (2.3 Time sync 6, 2.4 Job schedulers 10 = 16) implementada y testeada con mocks** (`Chapter2b-TimeSyncAndCron.ps1`). **Capitulo 2 completo: 45/45; acumulado 128/343.** `status_validated` pendiente.
  - 2.3: "en uso" = enabled o active. Los controles de un daemon son `Pass` si el otro es el que esta en uso (regla "seguir solo la subseccion del daemon elegido"). 2.3.1.1 exige exactamente uno.
  - **Los servidores NTP son politica del sitio:** 2.3.2.1/2.3.3.1 verifican que NTP/FallbackNTP (o server/pool) esten definidos explicitamente; `Set-*` no inventa servidores: exige `-Ntp/-FallbackNtp` (timesyncd) o `-Pool/-Server` (chrony) y de lo contrario solo advierte.
  - 2.3.1.1 Set: si hay dos daemons, conserva chrony y enmascara timesyncd (opcion 1 del benchmark); si no hay ninguno solo advierte.
  - 2.4.1.x: sin `cron` instalado son `Pass`. Modos maximos: `/etc/crontab` 600, directorios `/etc/cron.*` 700, `cron.allow` 640 (root:root o root:crontab; debe existir), `cron.deny` inexistente o igual. `at`: `at.allow` root:daemon o root:root.
  - `Test-CISPathAccess -Owner` ahora acepta varios `owner:group`.

- **Etapa 6 (3.1 Devices 3, 3.2 Kernel modules 6, 3.3 sysctl 26 = 35) implementada y testeada con mocks** (`Chapter3-Network.ps1`). **Capitulo 3 completo: 35/35; acumulado 163/343.** `status_validated` pendiente.
  - 3.3.x reutiliza `Test-CISSysctlSetting`/`Set-CISSysctlEnforced` (ejecucion + persistido). 3.3.2.x (IPv6) da `NotApplicable` si `/sys/module/ipv6/parameters/disable` != 0. 3.3.1.1 (`ip_forward`) admite la omision que permite el benchmark si `conf.all/default.forwarding` ya son 0.
  - **Riesgo:** los `Set-*` de forwarding (3.3.1.1-3, 3.3.2.1-2) rompen routers/VPN/Docker/Kubernetes/nube; simular con `-WhatIf` antes.
  - 3.1.2 (wireless): por diseno falla mientras haya una NIC wireless con su driver cargado; su `Set-*` agrega `install /bin/false` + `blacklist` de todos los drivers de `kernel/drivers/net/wireless` en `/etc/modprobe.d/blacklist-wireless.conf`. 3.1.1 es Manual; 3.1.3 reutiliza el patron "service not in use" (bluez / bluetooth.service, `-Purge` opcional).
  - Los modulos de red 3.2.x reutilizan el helper de 1.1.1.x con `Type net`.

- **Etapa 7 (4.1 UFW, 5 controles) implementada y testeada con mocks** (`Chapter4-Firewall.ps1`). **Capitulo 4 completo; acumulado 168/343.** `status_validated` pendiente.
  - **Guardas anti-lockout:** `Set-CIS_Debian13_4_1_2` y `_4_1_3` no habilitan ufw ni cambian la politica si sshd esta activo y ufw no tiene regla allow/limit para SSH, salvo `-AllowSsh [-SshPort N]` (agrega `ufw allow proto tcp from any to any port N` ANTES de habilitar; es la regla del propio benchmark, restringirla luego). `-WhatIf` no ejecuta nada.
  - 4.1.4 (`deny outgoing`, Level 2) exige `-AcceptOutboundBlock`: bloquea DNS/apt/NTP si no hay reglas de salida previas.
  - **Desviacion en 4.1.5:** el benchmark dice `ufw default disabled routed`, que no es sintaxis valida de ufw; se usa `ufw default deny routed` (cumple el criterio "disabled o deny").
  - Con ufw inactivo, `ufw status verbose` no informa politicas: 4.1.3-4.1.5 dan `Fail` (no determinable), igual que el Audit del benchmark.

- **Etapa 8 (5.1 SSH Server, 23 controles) implementada y testeada con mocks** (`Chapter5a-SshServer.ps1`); acumulado 191/343. `status_validated` pendiente.
  - Core nuevo `LinuxSshdEngine`: `Get-CISSshdConfig` (parsea `sshd -T`, configuracion efectiva), `Get-CISSshdVersion`, `Set-CISSshdOption`. **`Set-CISSshdOption` escribe el drop-in `/etc/ssh/sshd_config.d/00-cis-hardening.conf`** (sshd toma la primera ocurrencia; el `Include` de Debian va al principio), valida con `sshd -t`, **revierte y lanza error si falla** y recarga con `reload-or-restart` (no corta sesiones abiertas). Probado con un "sshd" falso y archivos temporales reales (5 tests).
  - Sin openssh-server: `NotApplicable` (Test) / advertencia (Set). `sshd -T` no evalua bloques `Match`; 5.1.18 revisa ademas los archivos por `MaxSessions` > 10 (como el benchmark).
  - **Decisiones:** 5.1.4 (AllowUsers/...) es politica del sitio: `Set` exige `-AllowUsers/-AllowGroups` y no inventa listas. 5.1.6 usa la sintaxis de exclusion de sshd (`Ciphers -3des-cbc,...`) en vez del `crypto-policies` del benchmark (que es de RHEL); chacha20-poly1305 se conserva (CVE-2023-48795: revisar parches). 5.1.12 y 5.1.13 comparten `KexAlgorithms`: el ultimo `Set` gana y ambos quedan satisfechos (5.1.13 escribe la lista completa; mlkem solo si OpenSSH >= 9.9).
  - **Riesgo:** `PermitRootLogin no` (5.1.21) o `AllowUsers` mal puestos pueden dejar sin acceso; probar desde una segunda sesion antes de cerrar la actual.

- **Etapa 9 (5.2 sudo/su, 7 controles) implementada y testeada** (`Chapter5b-PrivilegeEscalation.ps1`); acumulado 198/343. `status_validated` pendiente.
  - Los cambios a sudoers van en `/etc/sudoers.d/60-cis` (**sin punto en el nombre: sudo ignora archivos con `.`**), modo 0440, validados con `visudo -cf` y **revertidos si falla** (`Update-Debian13SudoersFile`); probado con archivos temporales reales y visudo mockeado.
  - **Desviacion en 5.2.4:** el benchmark dice "remover toda linea con NOPASSWD", lo que eliminaria el permiso de sudo entero; `Set` solo quita la etiqueta `NOPASSWD:` (la regla queda y pide password) y exige `-RemoveNoPasswd` porque cuentas sin password (ej. cloud-init) perderian sudo. 5.2.5 quita `!authenticate` con el mismo criterio.
  - 5.2.6: sin valor explicito se usa el default de `sudo -V`; Fail si es negativo o > 15. 5.2.7: `Set` crea el grupo vacio (`-Group`, por defecto `sugroup`) y agrega `auth required pam_wheel.so use_uid group=<g>` al principio de las lineas `auth` de `/etc/pam.d/su`.
  - Bug corregido por los tests: de nuevo el array vacio como `$null` (miembros de grupo); existencia y miembros ahora se consultan por separado.

- **Etapa 10 (5.3 PAM, 25 controles) implementada y testeada con un arbol de archivos temporal real** (`Chapter5c-Pam.ps1`, `5d-PamArguments.ps1`, `5e-PamUnixAndRoot.ps1`); acumulado 223/343. `status_validated` pendiente (**validar en VM con una segunda sesion abierta**).
  - **Seguridad:** todo `pam-auth-update` pasa por `Invoke-Debian13PamAuthUpdateSafe`: respalda `/etc/pam.d/common-*`, ejecuta y, si `common-auth` pierde `pam_unix.so`, **restaura y lanza error** (probado). Los archivos de perfil/conf modificados se respaldan con sufijo `.bak_<fecha>`.
  - **Diseno:** las reglas 5.3.3.1.x/2.x/3.x son tabla de datos (`$script:Debian13PamRules`) y sus `Test-/Set-CIS_*` se generan con un solo motor: el valor se evalua en el conf (`faillock.conf`, `pwquality.conf[.d]`, `pwhistory.conf`) **y** como argumento del modulo en `common-*`; Pass = nada fuera de rango + (si es obligatorio) al menos un valor valido; `remember` (5.3.3.3.1) exige un solo metodo. `Set`: comenta lo fuera de rango, escribe el valor del benchmark (archivo dedicado `50-pw*.conf` para pwquality; en archivos compartidos solo agrega la linea si falta) y quita el argumento duplicado de `/usr/share/pam-configs/*`.
  - Bug encontrado por los tests: la primera version sobrescribia todo `faillock.conf`/`pwhistory.conf` al escribir una opcion (perdia las demas); ahora agrega.
  - 5.3.1.1: el titulo dice "pam" pero el Audit/Remediation verifican `libpam-runtime` (se sigue el Audit). Los 5.3.1.x dependen de la cache de apt (`apt update` antes de auditar). 5.3.3.2.3 (complejidad) es Manual.
  - Limitacion: si el sitio usa archivos PAM propios en `/etc/pam.d` (sin pam-auth-update) hay que editarlos a mano, como advierte el benchmark.

- **Etapa 11 (5.4 Cuentas y entorno, 17 controles) implementada y testeada con un `/etc` temporal real** (`Chapter5f-UserAccounts.ps1`). **Capitulo 5 completo: 72/72; acumulado 240/343.** `status_validated` pendiente.
  - **Conservador en cuentas reales:** solo se automatiza lo que el benchmark da inequivoco: `login.defs`, `chage --maxdays/--warndays/--inactive`, `useradd -D -f`, `usermod -s nologin` (5.4.2.7), `usermod -L` (5.4.2.8), `umask`/`TMOUT`/`/etc/shells`. **No** se cambian UID/GID de cuentas, password de root, PATH de root ni fechas futuras (5.4.1.6, 5.4.2.1/.3/.4/.5): solo advertencia. 5.4.1.1 omite (con aviso) cuentas sin fecha de ultimo cambio, porque `chage --maxdays` las expiraria de inmediato.
  - 5.4.1.2 es Manual (informa `PASS_MIN_DAYS` y los usuarios con mindays < 1 en `ActualValue`).
  - `umask`: se interpreta octal y simbolico (`u=rwx,g=rx,o=`); "027 o mas restrictivo" = bits `g-w` y `o-rwx` presentes. 5.4.3.2 replica el criterio del script: en cada archivo con TMOUT, valor 1-900 + readonly + export; un valor fuera de rango en cualquiera falla.
  - **Lecciones de test (Pester 5):** los nombres de `It` con `<...>` se expanden como plantillas (`<= 45 y >` intentaba evaluar `$=`); `stat -c` es GNU-only, asi que en macOS los tests mockean `Get-CISFileMode`; los parametros tipo `-D` pasados sin comillas a una funcion avanzada se enlazan a `-Debug`, por eso los binarios con flags cortos se llaman desde helpers dedicados.
  - **Hallazgo de proceso:** el `.md` tiene saltos de pagina (`\f`) pegados al inicio de algunos encabezados (ej. `5.4.1.1`); los parseos que usan `^` deben limpiar `\f` (mi parser del inventario usa `strip()` y no perdio controles, pero un `grep '^5.4.1.1'` directo si falla).

- **Etapa 12 (6.1 journald/rsyslog/logfiles, 22 controles) implementada y testeada** (`Chapter6a-Logging.ps1`); acumulado 262/343. `status_validated` pendiente.
  - **Metodo de registro inferido:** el benchmark ofrece journald *o* rsyslog. Se considera rsyslog "en uso" si el paquete esta instalado; los controles del metodo no elegido dan `Pass` con nota. Consecuencia: en un host solo-journald 6.1.2.x son `Pass` (no aplican) y 6.1.1.x se evaluan; al instalar rsyslog se invierte. Para elegir rsyslog, `Set-CIS_Debian13_6_1_2_1` lo instala. Lo mismo aplica a `ForwardToSyslog` (6.1.1.1.4 = no / 6.1.2.3 = yes, mutuamente excluyentes por diseno del benchmark).
  - 7 Manual: 6.1.1.1.2/.3, 6.1.1.2.2, 6.1.2.5/.6/.8/.11. 6.1.2.10 (gtls) y el reenvio remoto son politica del sitio: `Set` solo advierte.
  - Usa el motor systemd de la Etapa 3 (`Get/Set-CISSystemdConfigValue`, drop-in `journald.conf.d/60-cis.conf`) y reinicia `systemd-journald`. 6.1.3.1 replica el script de permisos por nombre de archivo (`syslog`, `wtmp`, `*.journal`, `/var/log/apt`, cuentas de servicio duenas de sus logs).
  - Bug encontrado por los tests: `'{0:o}' -f <int>` no es un formato valido en PowerShell (para octal usar `[Convert]::ToString($n, 8)`).

- **Etapa 13 (6.2.1 auditd 4, 6.2.2 retencion 4, 6.2.4 acceso 10, 6.3 AIDE 3 = 21) implementada y testeada** (`Chapter6b-AuditdAndAide.ps1`); acumulado 283/343. `status_validated` pendiente.
  - `auditd.conf` se edita en sitio (reemplaza la clave o agrega; backup `.bak_<fecha>`) y se reinicia auditd. **Riesgo 6.2.2.3:** `disk_full_action` halt/single detiene o degrada el host al llenarse el disco de auditoria (`Set -Action halt|single`, por defecto halt como el ejemplo del benchmark). 6.2.2.4 con `email` exige MTA (avisa si no hay sendmail). 6.2.2.1 (tamano) es politica del sitio: Pass si esta definido; `Set` exige `-SizeMB`.
  - **Desviacion segura en GRUB (6.2.1.3/.4):** el benchmark propone un drop-in `GRUB_CMDLINE_LINUX="audit=1"` que **reemplaza** los parametros de `/etc/default/grub` (quiet, etc.); aqui se **anexa** (`"$GRUB_CMDLINE_LINUX audit=1"`) en `/etc/default/grub.d/40-cis-audit.cfg` / `41-cis-audit-backlog.cfg`, luego `update-grub` (requiere reinicio). El Audit solo exige que `audit_backlog_limit=N` este presente (se remedia con 8192).
  - 6.2.4.x: modos por mascara de bits (logs 0640, directorio 0750, config 0640, tools 0755); si falta `/etc/audit/auditd.conf` los de logs fallan (como el benchmark: "verify auditd is installed"); herramientas ausentes se omiten. `log_group` debe ser adm o root.
  - 6.3.3 lee `aide.conf` (no ejecuta `aide -p` como el script del benchmark) y exige `p+i+n+u+g+s+b+acl+xattrs+sha512` para las 5 herramientas resueltas con `readlink -f`; `Set` agrega el bloque `# Audit Tools`. 6.3.1 ejecuta `aideinit` solo si no hay base de datos.

- **Etapa 14 (6.2.3 reglas de auditd, 37 controles) implementada y testeada** (`Chapter6c-AuditRules.ps1` + `inventory/auditd_rules.json`); **Capitulo 6 completo: 80/80; acumulado 320/343.** `status_validated` pendiente.
  - Las reglas esperadas (47 en 33 controles) se **extrajeron de la seccion Remediation** de cada control a `auditd_rules.json` (con `{ARCH}` = b64/b32 y `{UID_MIN}`); las funciones `Test-/Set-CIS_Debian13_6_2_3_N` se generan desde ese dato. 6.2.3.10 (setuid/setgid) es dinamico (como el script del benchmark), 6.2.3.35/.36 se codifican y 6.2.3.37 es Manual.
  - **Comparacion semantica**, no textual: mismos campos `-F` (sin `-k`), syscalls contenidas, `path`/`dir` equivalentes a `-w` (estado "passing" deprecado del benchmark, permisos suficientes), y normalizando lo que `auditctl -l` reescribe (`exit=-EACCES`→`-13`, `auid!=unset`→`-1`, `a0=0x0`→`0`, arch ausente). Probado con muestras de salida real de auditctl.
  - Audit exige la regla **en disco y cargada**; la cargada no se exige si la ruta vigilada no existe (auditctl no puede cargarla). `Set` agrega solo las reglas faltantes (sin pisar las del sitio), hace backup y `augenrules --load` (avisa si auditd esta en modo inmutable).
  - **Riesgo 6.2.3.36 (`-e 2`):** la configuracion queda inmutable hasta reiniciar; `Set` exige `-AcceptImmutable` y solo escribe `99-finalize.rules` (aplicar antes todas las demas reglas). 6.2.3.35 (`-c`) evita que una vigilancia de ruta inexistente detenga la carga.
  - El JSON se lee con `Join-Path $PSScriptRoot '../inventory/...'` (barras normales; las barras invertidas de los `Get-CISBenchmarkInfo_*` funcionan en pwsh pero no son portables).

- **Etapa 15 (7.1 permisos 13, 7.2 usuarios/grupos 10 = 23) implementada y testeada** (`Chapter7-SystemMaintenance.ps1`); **343/343 controles implementados.** `status_validated` pendiente en todas las etapas.
  - 7.1.1-7.1.10 son una tabla de datos (ruta, modo maximo, owners aceptados: shadow/gshadow `root:root` o `root:shadow`); `Set` solo toca archivos existentes y no conformes. 7.1.11/7.1.12 recorren los filesystems locales (mismas exclusiones que el benchmark; puede tardar); 7.1.11 Set aplica `chmod o-w` a archivos y `chmod a+t` a directorios; 7.1.12 y 7.1.13 (Manual) no se remedian.
  - 7.2.1 `pwconv`; 7.2.2 `passwd -l` (bloquea, no borra); 7.2.4 vacia la lista de miembros de `shadow`; 7.2.9/7.2.10 corrigen owner/modo/grupo de home y dot files de usuarios interactivos (no borran `.forward`/`.rhost`/`.netrc`: advierten). 7.2.3 y duplicados 7.2.5-7.2.8: solo advertencia.
  - Nota de test: una funcion de Core que llama a otra de Core (`Test-CISPathAccess` -> `Get-CISFileMode`) solo se puede mockear con `-ModuleName CISHarden.Core`; y `$Home` es una variable de solo lectura de PowerShell (el parametro se llama `$HomeDir`).

## Etapa 16 — Consolidación (hecha) y estado final

- **Segunda fuente verificada:** las hojas de la tabla del *Appendix: Summary Table* del benchmark dan **343 IDs únicos, idénticos a los del inventario** (sin faltantes ni sobrantes).
- **Cobertura 343/343:** cada fila del CSV tiene `Test-CIS_Debian13_*` y `Set-CIS_Debian13_*` (`Invoke-CISAudit -Benchmark Debian13 -ReportCoverage`); `Coverage.Tests.ps1` lo exige. **261 tests de Pester 5.6.1 en verde** (Debian13 + motores nuevos de Core).
- **Humo del orquestador en macOS** (sin Debian): los 343 `Test-*` corren en ~50 s sin colgarse; los que necesitan binarios Linux devuelven `Error` (excepcion capturada por Core) como se espera fuera de Debian.
- **Bug real encontrado por esa corrida:** en PowerShell 7.6, `Get-ChildItem <ruta inexistente> -Recurse -Filter ...` **se cuelga**. Se guardaron con `Test-Path` todos los usos con `-Recurse` (`/boot`, `/etc/audit`, `/etc/sudoers.d`, `/etc/dconf/db` en el motor dconf de Core). Regla para futuro codigo: nunca `-Recurse` sobre una ruta que pueda no existir sin `Test-Path` previo.
- **`su - root -c env` (5.4.2.5)** ahora solo se intenta como root (sin root podria esperar un password en el tty).
- **README de Script-CIS actualizado** (Debian13, riesgos, comandos) y **CIS-Dashboard con soporte multi-benchmark** (ver abajo).

### CIS-Dashboard multi-benchmark (hecho)

- Esquema: `control_catalog` con PK `(benchmark, control_id)`; `server.benchmark` y `audit_run.benchmark`. Migracion automatica al arrancar (con backup previo); probada sobre una copia de la base real: 454 controles WS2025 conservados y 3 corridas previas quedan `WS2025`.
- Importar: el catalogo/guias se cargan a un benchmark elegido (probado con el CSV de Debian13: 343 controles conviven con los 454 de WS2025); las corridas toman el benchmark del servidor y solo se pueden asignar a servidores del mismo benchmark.
- Los enlaces a `/controls/<id>` resuelven el benchmark por servidor o `?benchmark=` (default `WS2025` para enlaces viejos). Registro `BENCHMARKS` en `app.py` con nombre, niveles y titulos de capitulo (Debian13, Debian10, WS2025).
- Pendiente (no bloqueante): perfil `Server/Workstation` del `profile_scope` de Debian13 aun no se filtra en la UI (se muestra solo el nivel minimo), y los graficos por nivel ignoran `Next Generation Windows Security` para Debian (no aplica).

### Pendiente global

1. **Validar `status_validated` en una VM Debian 13 real** (auditar, remediar con `-WhatIf`, remediar, re-auditar), empezando por los capitulos sin riesgo de acceso (1, 2, 3, 6, 7) y dejando SSH/UFW/PAM/sudoers para el final con una segunda sesion abierta.
2. Correr los `Set-*` que escriben archivos de sistema fuera de un arbol temporal (dconf/gdm, limits.conf, sysctl, journald): tienen tests de `Test-*` y de lectura, no del `Set-*` sobre `/etc` real.

## Reglas (heredadas)

1. Un control = `Test-CIS_Debian13_<id_con_guiones_bajos>` + `Set-CIS_Debian13_<id>`, 1 a 1 con el CSV.
2. Releer la sección del `.md` (Audit/Remediation/Default) antes de codificar; nunca inventar valores.
3. Controles `(Manual)` (16): `Test` devuelve `ManualReviewRequired`, sin `Set`.
4. `Set-*` con `SupportsShouldProcess`, backup previo, sólo tras `Fail`.
5. Cada etapa cierra con: Pester en verde + cobertura 100 % del capítulo/sección + corrida real en la VM.
6. Perfil Server vs Workstation resuelto con `Get-CISLinuxProfile` (Core).
7. Al cerrar una etapa se marcan `status_impl` / `status_tested` / `status_validated` en el CSV.

## Motores de Core: disponibles vs. a crear

Ya existen (`CISHarden.Core/Public/Engines/`): kernel modules, fstab/findmnt, archivos (permisos/contenido),
paquetes dpkg/apt, servicios systemd, sysctl, perfil Server/Workstation.

Faltan y se crean **antes** de la etapa que los necesita (genéricos, sin conocimiento del benchmark, con Pester):

| Motor nuevo | Lo usan | Notas |
|---|---|---|
| `LinuxConfigEngine` (clave/valor en archivos + drop-ins, con backup) | 1.5, 2.x, 5.x, 6.1 | Base de journald, chrony, timesyncd, login.defs, sudoers |
| `LinuxSshdEngine` (`sshd -T` + `Match`) | 5.1 | Audit sobre config efectiva, no sobre el archivo |
| `LinuxPamEngine` (`/etc/pam.d`, `pam-auth-update`, faillock/pwquality/pwhistory) | 5.3 | Riesgo de lockout: `-WhatIf` obligatorio |
| `LinuxAuditdRulesEngine` (reglas on-disk vs. `auditctl -l`) | 6.2.3 (37) | Genera `/etc/audit/rules.d/*.rules` |
| `LinuxFirewallEngine` (ufw; nftables sólo si el benchmark lo exige) | 4.1 | Riesgo: cortar SSH; regla de acceso previa |
| `LinuxAccountEngine` (passwd/shadow/group, shells, UID/GID, home dirs) | 5.4, 7.2 | Sólo lectura en la mayoría; `Set` cuidadoso |
| `LinuxNetworkEngine` (interfaces wireless/IPv6) | 3.1 | Pequeño |

## Etapas (orden por dependencias y riesgo)

| Etapa | Alcance | Controles | Motores | Riesgo de remediar |
|---|---|---|---|---|
| **1 ✅** | 1.1 Filesystem (kernel modules 11 + particiones/mount options 26) | 37 | Existentes (kernel, fstab) | Medio: editar `fstab` puede impedir el boot → backup + `mount -a` de validación |
| **2 ✅** | 1.2 Package Management (10), 1.3 AppArmor (4), 1.4 Bootloader (2) | 16 | Existentes + Config | Medio: GRUB password / initramfs |
| **3 ✅** | 1.5 Process Hardening (13), 1.6 Banners (6), 1.7 GDM (11) | 30 | Existentes + Config (dconf) | Bajo. 1.7 sólo aplica si hay GDM |
| **4 ✅** | 2.1 Server Services (23), 2.2 Client Services (6) | 29 | Paquetes/Servicios | Bajo-medio: no romper servicios en uso; 2.1.23 es Manual |
| **5 ✅** | 2.3 Time sync (6), 2.4 Job schedulers (10) | 16 | Config + File | Bajo |
| **6 ✅** | 3.1 Devices (3), 3.2 Kernel modules (6), 3.3 sysctl IPv4/IPv6 (26) | 35 | Existentes + Network | Medio: `ip_forward` rompe routers/docker |
| **7 ✅** | 4.1 UFW (5) | 5 | **Firewall (nuevo)** | **Alto:** dejar SSH permitido antes de `enable` |
| **8 ✅** | 5.1 SSH Server (23) | 23 | **Sshd (nuevo)** | **Alto:** validar con `sshd -t`, no cerrar sesión activa |
| **9 ✅** | 5.2 sudo (7) | 7 | Config | Medio: validar con `visudo -c` |
| **10 ✅** | 5.3 PAM (3+4+18) | 25 | **Pam (nuevo)** | **Alto:** lockout de cuentas; probar en 2ª sesión |
| **11 ✅** | 5.4 Cuentas y entorno (17) | 17 | Account | Medio |
| **12 ✅** | 6.1 journald/rsyslog/logfiles (22) | 22 | Config + File | Bajo |
| **13 ✅** | 6.2.1, 6.2.2, 6.2.4 auditd (18) + 6.3 AIDE (3) | 21 | Paquetes/Servicios/File | Bajo |
| **14 ✅** | 6.2.3 reglas auditd (37) | 37 | **AuditdRules (nuevo)** | Medio: reglas inmutables (`-e 2`) requieren reboot |
| **15 ✅** | 7.1 Permisos de archivos (13) + 7.2 Usuarios/grupos (10) | 23 | File + Account | Medio: `chmod`/`chown` masivos; 7.1.13 Manual |
| **16 ✅** | Consolidación: `Invoke-CISAudit -Benchmark Debian13 -All` + cobertura 100 % + README | — | Core | — |
| | **Total** | **343** | | |

Cobertura por capítulo: Cap.1 = 83 (etapas 1-3) · Cap.2 = 45 (4-5) · Cap.3 = 35 (6) · Cap.4 = 5 (7) ·
Cap.5 = 72 (8-11) · Cap.6 = 80 (12-14) · Cap.7 = 23 (15).

### Recomendación de orden de ejecución

Las etapas 1-6 no requieren motores nuevos: dan ~200 controles (58 %) rápido y validan el módulo
contra la VM. Luego los motores de mayor riesgo (7, 8, 10) con snapshot previo y prueba de sesión
paralela. Las etapas 12-15 son casi sólo lectura y cierran el resto.

## Integración con CIS-Dashboard (paralela, cuando exista al menos la Etapa 1)

Hoy el Dashboard asume WS2025 (catálogo único `cis2025_controls_master.csv`, niveles "Next Generation
Windows Security", capítulos con títulos de Windows). Para Debian13 hace falta:

1. **Catálogo por benchmark:** columna `benchmark` en las tablas de controles/corridas (`schema.sql` + migración con
   backup, como ya hace en cada arranque); importar `cis_debian13_controls_master.csv` bajo `Debian13`.
2. **Servidor con benchmark:** al crear un servidor elegir benchmark (WS2025 / Debian10 / Debian13); el dashboard
   filtra catálogo y corridas por el benchmark del servidor.
3. **Niveles/perfiles:** soportar `Server:Level 1;Workstation:Level 2` (columna `profile_scope`) y filtrar por perfil.
4. **Títulos de capítulo por benchmark** (Initial Setup, Services, Network, Host Based Firewall, Access Control,
   Logging and Auditing, System Maintenance).
5. **Importar CSV de `Invoke-CISAudit -Benchmark Debian13`** (mismo formato de salida, ya lo genera Core).

## Fuera de alcance / decisiones abiertas

- Ejecución remota (SSH/PSRemoting) desde el Dashboard: sigue siendo un cambio de arquitectura aparte.
- Controles de red/firewall sobre hosts productivos: sólo se remedian con `-WhatIf` previo y ventana acordada.
- ¿Se soporta nftables/iptables como alternativa a UFW? El benchmark 13 sólo cubre UFW en 4.1 → se sigue eso.
