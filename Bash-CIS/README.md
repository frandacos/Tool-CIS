# CISHarden-Bash — Auditoría/remediación CIS Debian 13, en bash

Puerto en **bash puro** (sin PowerShell) del proyecto `Script-CIS` (que está en
PowerShell/`pwsh`). Es un **proyecto paralelo e independiente**: no comparte
código ni estado con `Script-CIS`, no lo modifica, y ambos pueden convivir en
el repo. Misma idea de fondo — un `test_<control_id>` (auditoría) y un
`set_<control_id>` (remediación) por control del benchmark, un orquestador con
alcance explícito, y un CSV de salida con las mismas columnas que ya entiende
`CIS-Dashboard` — pero reescrita en bash para no depender de instalar `pwsh`
en cada servidor Debian.

Motivo: instalar `pwsh` en una Debian 13 recién armada puede complicarse (sin
paquete oficial para "trixie" todavía, problemas de red, etc.). Bash 5.x viene
de fábrica en cualquier Debian.

## Estado actual — MVP, no completo

**Implementado y probado (con `bash -n` y ejecución real en macOS/Linux):**

- El motor genérico (`lib/`): resultados en CSV, backups, engines de
  kernel modules, fstab/mount options, archivos (permisos/owner), paquetes
  (dpkg/apt), servicios (systemd) y sysctl.
- Los dos orquestadores (`bin/cis-audit.sh`, `bin/cis-remediate.sh`), con la
  misma filosofía que `Invoke-CISAudit`/`Invoke-CISRemediate`: alcance
  explícito para remediar, confirmación salvo `--force`, `--dry-run` antes de
  aplicar, log opcional por control.
- **Capítulo 1.1 Filesystem completo: 37/37 controles** (`test_*`/`set_*`),
  igual alcance que la primera etapa que se hizo del lado PowerShell.

**Pendiente: los otros 306 controles** (capítulos 1.2 en adelante — Package
Management, AppArmor, Bootloader, Process Hardening, Banners, GDM, Services,
Time Sync, Cron, Network, Firewall, SSH, sudo, PAM, cuentas, Logging, auditd,
AIDE, System Maintenance). Se agregan igual que el capítulo 1.1: un archivo
nuevo en `controls/debian13/` por sección, siguiendo el mismo patrón de
`test_<id>`/`set_<id>` y los helpers de `lib/`.

**Nunca se corrió contra una Debian 13 real** — se armó y probó en macOS
(sintaxis + registro de funciones + generación de CSV). Antes de confiar en
él hay que validarlo en una VM, igual que con `Script-CIS`.

## Por qué no es una traducción 1:1 automática

Cada control del benchmark tiene su propia lógica de comparación (parsear
`sshd -T`, reglas de `auditd`, permisos con máscaras de bits, etc.). Portar
eso a bash no es mecánico — hay que releer cada control del benchmark y
reescribir su lógica con `grep`/`awk`/`stat`, sin los objetos estructurados
que tiene PowerShell. Por eso este proyecto avanza **capítulo por capítulo**,
igual que `Script-CIS` (ver su `PLAN_Debian13.md` como referencia de orden y
riesgos), no todo de una vez.

## Requisitos

- **Debian 13** real (o cualquier Linux con `bash` 4+, `systemd`, `dpkg`/`apt`,
  `findmnt`, `modprobe`/`lsmod` para que la lógica tenga sentido).
- Para auditar: cualquier usuario (aunque leer `/etc/shadow` y algunos
  `/etc/audit/*` requiere root).
- Para remediar: **root** (`cis-remediate.sh` lo exige explícitamente).

## Uso

```bash
# Auditar el capítulo 1 completo, con reporte de cobertura, a un CSV
bin/cis-audit.sh --chapter 1 --report-coverage --output audit_ch1.csv

# Auditar un control puntual
bin/cis-audit.sh --control-id 1.1.1.1

# Simular una remediación del capítulo 1 (no cambia nada)
sudo bin/cis-remediate.sh --chapter 1 --dry-run

# Remediar de verdad, con confirmación de lote
sudo bin/cis-remediate.sh --chapter 1

# Remediar sin confirmación (para correr desatendido) y con log
sudo bin/cis-remediate.sh --chapter 1 --force --log remediacion_ch1.csv
```

`cis-remediate.sh` solo toca controles que la auditoría marcó `Fail` (nunca
`Pass`/`NotApplicable`/`ManualReviewRequired`), igual que el lado PowerShell.
Antes de tocar un archivo, cada `set_*` que edita configuración hace un backup
con `cis_backup_file` (por defecto en `/var/lib/cisharden-bash/backups/`,
configurable con la variable de entorno `CIS_BACKUP_DIR`).

## Verificar sin una Debian real (smoke test)

```bash
bash tests/smoke_test.sh
```

Corre en cualquier bash (incluido el `/bin/bash` 3.2 de macOS): chequea
sintaxis de todos los `.sh` y cuenta cuántos controles del inventario tienen
`test_*`/`set_*` definidas, sin ejecutarlas. No reemplaza probar de verdad en
Linux — solo detecta errores de sintaxis y controles sin implementar antes de
copiar el proyecto a una VM.

## Estructura

```
Bash-CIS/
  lib/                          # motor generico, equivalente a CISHarden.Core
    core.sh                     # cis_result (CSV), backups, cis_conf_set_kv
    kernel.sh                   # modulos de kernel
    fstab.sh                    # particiones/opciones de montaje
    file.sh                     # permisos/owner/contenido de archivos
    package.sh                  # dpkg/apt
    service.sh                  # systemd
    sysctl.sh                   # parametros de kernel
  controls/debian13/
    chapter1a_filesystem.sh     # 1.1.x -- unico capitulo implementado hoy
  inventory/
    cis_debian13_controls_master.csv   # copia del inventario canonico (343 filas)
  bin/
    cis-audit.sh                # equivalente a Invoke-CISAudit
    cis-remediate.sh            # equivalente a Invoke-CISRemediate
  tests/
    smoke_test.sh                # sintaxis + cobertura, sin ejecutar controles
```

## Cómo copiar a una Debian 13 y probar

```bash
# desde tu Mac
rsync -av --exclude '.git' \
  "/ruta/a/Tool-CIS/Tool-CIS/Bash-CIS/" \
  root@vm-debian13:/root/Bash-CIS/

# en la VM
cd /root/Bash-CIS
bin/cis-audit.sh --chapter 1 --report-coverage --output audit_ch1.csv
cat audit_ch1.csv
```

Si algún `test_*`/`set_*` tira un error de bash (no un `Fail` normal del
benchmark, sino un mensaje de sintaxis o "command not found" inesperado),
avisá con el `control_id` — son los bugs reales que hay que cazar fuera de
macOS.

## Cómo seguir agregando capítulos

1. Elegí la sección siguiente del benchmark (ver el orden y los riesgos en
   `Script-CIS/Benchmarks/Debian13/PLAN_Debian13.md`, que aplica igual acá).
2. Releé esa sección de `Script-CIS/Benchmarks/Debian13/cis_debian_13.md`
   (Audit/Remediation/Default Value) — nunca inventar un valor.
3. Creá `controls/debian13/chapterNx-<nombre>.sh` con un `test_<id>`/`set_<id>`
   por control, reutilizando los helpers de `lib/` (o agregando uno nuevo si
   hace falta un motor que no existe todavía, ej. sshd/PAM/auditd rules).
4. Corré `bash tests/smoke_test.sh` — la cobertura tiene que subir en la
   cantidad exacta de controles agregados.
5. Copiá a una VM Debian 13 y corré `bin/cis-audit.sh --control-id <id>` para
   cada control nuevo, comparando el resultado contra lo que dice el propio
   servidor (ej. `systemctl is-active auditd`, `sshd -T | grep ...`).
