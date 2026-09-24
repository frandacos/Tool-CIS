# Motor de servicios systemd. Puerto de LinuxServiceEngine.ps1.

service_enabled() {
    [[ "$(systemctl is-enabled "$1" 2>/dev/null)" == "enabled" ]]
}

service_active() {
    systemctl is-active --quiet "$1"
}

# service_enable_now <unit...>
service_enable_now() {
    systemctl unmask "$@" >/dev/null 2>&1 || true
    systemctl enable --now "$@"
}

service_disable() {
    systemctl disable "$@" 2>&1 || true
}

# service_stop_mask <unit...>
service_stop_mask() {
    systemctl stop "$@" >/dev/null 2>&1 || true
    systemctl mask "$@"
}
