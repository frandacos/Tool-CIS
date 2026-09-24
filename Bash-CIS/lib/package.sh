# Motor de paquetes via dpkg/apt-get. Puerto de LinuxPackageEngine.ps1.

package_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q '^install ok installed$'
}

package_install() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$1"
}

package_remove() {
    # package_remove <name> [purge]
    local name="$1" verb="remove"
    [[ "${2:-}" == "purge" ]] && verb="purge"
    DEBIAN_FRONTEND=noninteractive apt-get "$verb" -y "$name"
}
