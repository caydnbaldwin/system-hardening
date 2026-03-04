#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

APP_NAME="$(basename "$0")"

APPLY=false
NON_INTERACTIVE=false
SSH_PASSWORD_ONLY=false
LOCK_USERS=true
DELETE_USERS=false
ROTATE_PASSWORDS=false
PURGE=false
FIREWALL_ROLLBACK_SECONDS=0

SERVICES=""
USERS=""
GROUPS=""
PORTS=""
MIN_UID=""

CONFIG_FILE=""

OS_FAMILY=""
PKG_MGR=""
SERVICE_MGR=""
FIREWALL_TOOL=""

SSH_PORTS=()

FIREWALL_ROLLBACK_TOKEN=""
FIREWALL_ROLLBACK_FILE=""

CRITICAL_SERVICES=(
  "sshd.service"
  "NetworkManager.service"
  "network.service"
  "networking.service"
  "systemd-journald.service"
  "rsyslog.service"
  "chronyd.service"
  "systemd-timesyncd.service"
  "cloud-init.service"
)

UNSAFE_PACKAGES=(
  "telnet"
  "rsh-server"
  "rsh"
  "tftp"
  "xinetd"
)

declare -A ALLOW_USERS=()
declare -A PROTECTED_USERS=()
declare -A REQUIRED_SERVICES=()
declare -A ALLOWED_PORTS=()

log_info() {
  printf '[INFO] %s\n' "$*"
}

log_warn() {
  printf '[WARN] %s\n' "$*" >&2
}

log_error() {
  printf '[ERROR] %s\n' "$*" >&2
}

die() {
  log_error "$*"
  exit 1
}

usage() {
  cat <<EOF
Usage:
  $APP_NAME [flags]
  $APP_NAME config.txt

Flags:
  --services "ssh,http"       Required services (comma-separated)
  --users "root,devteam"      Required users (comma-separated)
  --groups "wheel,sudo"       Required groups (comma-separated)
  --ports "22,80,443"         Allowed inbound ports (comma-separated)
  --apply                      Apply changes (default is report-only)
  --ssh-password-only          Disable SSH key auth, require passwords
  --non-interactive            Fail if required inputs are missing
  --lock-users                 Lock non-required users (default)
  --delete-users               Delete non-required users (dangerous)
  --rotate-passwords           Rotate passwords for eligible users
  --purge                      Uninstall known unsafe packages
  --min-uid 1000               Override minimum UID threshold
  --firewall-rollback 60        Roll back nftables/iptables after N seconds
EOF
}

is_true() {
  case "${1:-}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

csv_to_lines() {
  local input="$1"
  local part
  IFS=',' read -r -a parts <<< "$input"
  for part in "${parts[@]}"; do
    part="$(trim "$part")"
    if [[ -n "$part" ]]; then
      printf '%s\n' "$part"
    fi
  done
}

add_allow_user() {
  local user="$1"
  [[ -n "$user" ]] || return 0
  ALLOW_USERS["$user"]=1
}

add_protected_user() {
  local user="$1"
  [[ -n "$user" ]] || return 0
  PROTECTED_USERS["$user"]=1
  add_allow_user "$user"
}

add_required_service() {
  local unit="$1"
  [[ -n "$unit" ]] || return 0
  REQUIRED_SERVICES["$unit"]=1
}

add_allowed_port() {
  local port="$1"
  local proto="$2"
  [[ -n "$port" && -n "$proto" ]] || return 0
  ALLOWED_PORTS["$port/$proto"]=1
}

is_positive_int() {
  [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -gt 0 ]]
}

schedule_firewall_rollback() {
  local tool="$1"
  local backup="$2"
  local seconds="$3"
  local token

  token="$(mktemp -t harden-firewall-rollback.XXXXXX)"
  FIREWALL_ROLLBACK_TOKEN="$token"
  FIREWALL_ROLLBACK_FILE="$backup"

  (
    sleep "$seconds"
    if [[ -f "$token" ]]; then
      case "$tool" in
        nft)
          nft -f "$backup" >/dev/null 2>&1 || true
          ;;
        iptables)
          iptables-restore < "$backup" >/dev/null 2>&1 || true
          ;;
      esac
    fi
    rm -f "$token" "$backup"
  ) &
}

cancel_firewall_rollback() {
  if [[ -n "$FIREWALL_ROLLBACK_TOKEN" ]]; then
    rm -f "$FIREWALL_ROLLBACK_TOKEN"
  fi
}

parse_args() {
  local arg base
  for arg in "$@"; do
    base="$(basename "$arg")"
    if [[ "$base" == "config.txt" ]]; then
      CONFIG_FILE="$arg"
      load_config
      return 0
    fi
  done

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --services)
        SERVICES="$2"
        shift 2
        ;;
      --users)
        USERS="$2"
        shift 2
        ;;
      --groups)
        GROUPS="$2"
        shift 2
        ;;
      --ports)
        PORTS="$2"
        shift 2
        ;;
      --apply)
        APPLY=true
        shift
        ;;
      --ssh-password-only)
        SSH_PASSWORD_ONLY=true
        shift
        ;;
      --non-interactive)
        NON_INTERACTIVE=true
        shift
        ;;
      --lock-users)
        LOCK_USERS=true
        shift
        ;;
      --delete-users)
        DELETE_USERS=true
        shift
        ;;
      --rotate-passwords)
        ROTATE_PASSWORDS=true
        shift
        ;;
      --purge)
        PURGE=true
        shift
        ;;
      --min-uid)
        MIN_UID="$2"
        shift 2
        ;;
      --firewall-rollback)
        FIREWALL_ROLLBACK_SECONDS="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
  done
}

load_config() {
  [[ -f "$CONFIG_FILE" ]] || die "Config file not found: $CONFIG_FILE"

  while IFS='=' read -r raw_key raw_value; do
    local key value
    key="$(trim "${raw_key:-}")"
    value="$(trim "${raw_value:-}")"

    [[ -z "$key" ]] && continue
    [[ "$key" == \#* ]] && continue

    case "$key" in
      services) SERVICES="$value" ;;
      users) USERS="$value" ;;
      groups) GROUPS="$value" ;;
      ports) PORTS="$value" ;;
      apply) is_true "$value" && APPLY=true || APPLY=false ;;
      ssh_password_only) is_true "$value" && SSH_PASSWORD_ONLY=true || SSH_PASSWORD_ONLY=false ;;
      non_interactive) is_true "$value" && NON_INTERACTIVE=true || NON_INTERACTIVE=false ;;
      lock_users) is_true "$value" && LOCK_USERS=true || LOCK_USERS=false ;;
      delete_users) is_true "$value" && DELETE_USERS=true || DELETE_USERS=false ;;
      rotate_passwords) is_true "$value" && ROTATE_PASSWORDS=true || ROTATE_PASSWORDS=false ;;
      purge) is_true "$value" && PURGE=true || PURGE=false ;;
      min_uid) MIN_UID="$value" ;;
      firewall_rollback_seconds) FIREWALL_ROLLBACK_SECONDS="$value" ;;
      *) log_warn "Unknown config key: $key" ;;
    esac
  done < "$CONFIG_FILE"
}

prompt_if_missing() {
  local label="$1"
  local var_name="$2"
  local required="${3:-false}"
  local current_value
  local suffix="optional"

  current_value="${!var_name}"
  if is_true "$required"; then
    suffix="required"
  fi

  if [[ -z "$current_value" ]]; then
    if $NON_INTERACTIVE; then
      if is_true "$required"; then
        die "Missing required input: $label"
      fi
      return 0
    fi
    read -r -p "Enter $label (comma-separated, $suffix): " current_value
    printf -v "$var_name" '%s' "$current_value"
  fi
}

get_default_min_uid() {
  local uid_min=""
  if [[ -r /etc/login.defs ]]; then
    uid_min="$(awk '/^UID_MIN/ {print $2; exit}' /etc/login.defs)"
  fi
  printf '%s' "${uid_min:-1000}"
}

detect_platform() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "${ID_LIKE:-$ID}" in
      *debian*|*ubuntu*) OS_FAMILY="debian" ;;
      *rhel*|*fedora*|*centos*|*rocky*|*almalinux*|*ol*) OS_FAMILY="rhel" ;;
      *) OS_FAMILY="unknown" ;;
    esac
  else
    OS_FAMILY="unknown"
  fi

  if [[ -z "$MIN_UID" ]]; then
    MIN_UID="$(get_default_min_uid)"
  fi
}

detect_tools() {
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt-get"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
  else
    PKG_MGR=""
  fi

  if command -v systemctl >/dev/null 2>&1; then
    SERVICE_MGR="systemctl"
  elif command -v service >/dev/null 2>&1; then
    SERVICE_MGR="service"
  else
    SERVICE_MGR=""
  fi

  FIREWALL_TOOL=""
  if command -v ufw >/dev/null 2>&1; then
    local ufw_status
    ufw_status="$(ufw status 2>/dev/null || true)"
    if echo "$ufw_status" | grep -qi "Status: active"; then
      FIREWALL_TOOL="ufw"
    fi
  fi

  if [[ -z "$FIREWALL_TOOL" ]] && command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active firewalld >/dev/null 2>&1; then
      FIREWALL_TOOL="firewalld"
    fi
  fi

  if [[ -z "$FIREWALL_TOOL" ]] && command -v nft >/dev/null 2>&1; then
    FIREWALL_TOOL="nft"
  fi

  if [[ -z "$FIREWALL_TOOL" ]] && command -v iptables >/dev/null 2>&1; then
    FIREWALL_TOOL="iptables"
  fi
}

require_root_if_applying() {
  if $APPLY; then
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      die "Apply mode requires root. Re-run with sudo."
    fi
  fi
}

collect_ssh_ports() {
  local ports
  ports="$(sshd -T 2>/dev/null | awk '/^port / {print $2}' | tr '\n' ' ' || true)"
  if [[ -n "$ports" ]]; then
    read -r -a SSH_PORTS <<< "$ports"
  else
    SSH_PORTS=("22")
  fi
}

recon() {
  local os_name="unknown"
  if [[ -r /etc/os-release ]]; then
    os_name="$(awk -F= '/^PRETTY_NAME/ {gsub(/\"/, "", $2); print $2}' /etc/os-release)"
  fi

  log_info "Recon: OS=$os_name Kernel=$(uname -r)"
  log_info "Recon: PackageManager=${PKG_MGR:-unknown} ServiceManager=${SERVICE_MGR:-unknown} Firewall=${FIREWALL_TOOL:-none}"

  if command -v ss >/dev/null 2>&1; then
    log_info "Recon: Listening sockets (ss -lptun)"
    ss -lptun 2>/dev/null || true
  fi

  if [[ "$SERVICE_MGR" == "systemctl" ]]; then
    log_info "Recon: Enabled services"
    systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null || true
  fi

  log_info "Recon: Users with shells"
  awk -F: '{print $1":"$3":"$7}' /etc/passwd 2>/dev/null || true

  log_info "Recon: Sudoers groups"
  getent group sudo 2>/dev/null || true
  getent group wheel 2>/dev/null || true
  if [[ -d /etc/sudoers.d ]]; then
    log_info "Recon: /etc/sudoers.d entries"
    ls -1 /etc/sudoers.d 2>/dev/null || true
  fi

  if command -v sshd >/dev/null 2>&1; then
    log_info "Recon: Effective SSH config"
    sshd -T 2>/dev/null || true
  fi

  if [[ "$SERVICE_MGR" == "systemctl" ]]; then
    log_info "Recon: Systemd timers"
    systemctl list-timers --all --no-legend 2>/dev/null || true
  fi

  if [[ -d /etc/cron.d ]]; then
    log_info "Recon: /etc/cron.d entries"
    ls -1 /etc/cron.d 2>/dev/null || true
  fi

  case "$FIREWALL_TOOL" in
    ufw)
      log_info "Recon: UFW status"
      ufw status verbose 2>/dev/null || true
      ;;
    firewalld)
      log_info "Recon: Firewalld status"
      firewall-cmd --state 2>/dev/null || true
      firewall-cmd --list-all 2>/dev/null || true
      ;;
    nft)
      log_info "Recon: nftables ruleset"
      nft list ruleset 2>/dev/null || true
      ;;
    iptables)
      log_info "Recon: iptables rules"
      iptables -S 2>/dev/null || true
      ;;
  esac
}

resolve_required_users() {
  local current_user uid shell user
  current_user="${SUDO_USER:-${USER:-}}"
  if [[ -n "$current_user" ]]; then
    add_protected_user "$current_user"
  fi

  while IFS=: read -r user _ uid _ _ _ shell; do
    if [[ "$uid" -eq 0 ]]; then
      add_protected_user "$user"
    fi
    if [[ "$uid" -lt "$MIN_UID" ]]; then
      add_protected_user "$user"
    fi
  done < /etc/passwd

  mapfile -t input_users < <(csv_to_lines "$USERS")
  for user in "${input_users[@]}"; do
    add_allow_user "$user"
  done

  mapfile -t input_groups < <(csv_to_lines "$GROUPS")
  for group in "${input_groups[@]}"; do
    local members
    members="$(getent group "$group" | awk -F: '{print $4}' || true)"
    if [[ -n "$members" ]]; then
      IFS=',' read -r -a group_users <<< "$members"
      for user in "${group_users[@]}"; do
        add_allow_user "$user"
      done
    fi
  done

  if command -v ss >/dev/null 2>&1; then
    local pid_list pid owner
    pid_list="$(ss -lptun 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u || true)"
    for pid in $pid_list; do
      owner="$(ps -o user= -p "$pid" 2>/dev/null || true)"
      if [[ -n "$owner" ]]; then
        add_protected_user "$owner"
      fi
    done
  fi

  if [[ "$SERVICE_MGR" == "systemctl" ]]; then
    local unit_list unit svc_user
    unit_list="$(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' || true)"
    for unit in $unit_list; do
      svc_user="$(systemctl show -p User --value "$unit" 2>/dev/null || true)"
      if [[ -n "$svc_user" ]]; then
        add_allow_user "$svc_user"
      fi
    done
  fi
}

resolve_required_services() {
  local service
  mapfile -t input_services < <(csv_to_lines "$SERVICES")

  for service in "${input_services[@]}"; do
    local unit="$service"
    case "$service" in
      ssh|sshd)
        unit="sshd.service"
        ;;
      http|apache|apache2)
        if [[ "$OS_FAMILY" == "rhel" ]]; then
          unit="httpd.service"
        else
          unit="apache2.service"
        fi
        ;;
      nginx)
        unit="nginx.service"
        ;;
      ftp)
        unit="vsftpd.service"
        ;;
    esac

    if [[ "$unit" != *.service ]]; then
      unit="$unit.service"
    fi

    add_required_service "$unit"
  done

  for service in "${CRITICAL_SERVICES[@]}"; do
    add_required_service "$service"
  done

  if [[ "$SERVICE_MGR" == "systemctl" ]]; then
    local unit
    for unit in "${!REQUIRED_SERVICES[@]}"; do
      local svc_user
      svc_user="$(systemctl show -p User --value "$unit" 2>/dev/null || true)"
      if [[ -n "$svc_user" ]]; then
        add_allow_user "$svc_user"
      fi
    done
  fi
}

enforce_users() {
  local user uid shell
  local nologin="/usr/sbin/nologin"
  if [[ ! -x "$nologin" ]]; then
    nologin="/sbin/nologin"
  fi
  if [[ ! -x "$nologin" ]]; then
    nologin="/bin/false"
  fi

  local -a candidates=()
  while IFS=: read -r user _ uid _ _ _ shell; do
    if [[ "$uid" -lt "$MIN_UID" ]]; then
      continue
    fi
    if [[ -n "${ALLOW_USERS[$user]:-}" ]]; then
      continue
    fi
    if [[ -n "${PROTECTED_USERS[$user]:-}" ]]; then
      continue
    fi
    candidates+=("$user")
  done < /etc/passwd

  if [[ ${#candidates[@]} -eq 0 ]]; then
    log_info "User enforcement: no non-required users found"
    return 0
  fi

  if ! $APPLY; then
    if $DELETE_USERS; then
      log_info "User enforcement: would delete users: ${candidates[*]}"
    else
      log_info "User enforcement: would lock users: ${candidates[*]}"
    fi
    return 0
  fi

  if $DELETE_USERS; then
    read -r -p "Delete ${#candidates[@]} users? Type 'yes' to continue: " confirm
    if [[ "$confirm" != "yes" ]]; then
      log_warn "User deletion canceled"
    else
      for user in "${candidates[@]}"; do
        if userdel -r "$user" >/dev/null 2>&1; then
          log_info "Deleted user: $user"
        else
          log_warn "Failed to delete user: $user"
        fi
      done
    fi
  fi

  if $LOCK_USERS && ! $DELETE_USERS; then
    for user in "${candidates[@]}"; do
      if usermod -L "$user" >/dev/null 2>&1 && chage -E 0 "$user" >/dev/null 2>&1 && usermod -s "$nologin" "$user" >/dev/null 2>&1; then
        log_info "Locked user: $user"
      else
        log_warn "Failed to lock user: $user"
      fi
    done
  fi

  if $ROTATE_PASSWORDS; then
    rotate_passwords
  fi
}

prompt_password() {
  local pass confirm
  read -r -s -p "Enter new shared password: " pass
  printf '\n'
  read -r -s -p "Confirm new shared password: " confirm
  printf '\n'
  if [[ -z "$pass" ]]; then
    die "Password cannot be empty"
  fi
  if [[ "$pass" != "$confirm" ]]; then
    die "Passwords do not match"
  fi
  printf '%s' "$pass"
}

rotate_passwords() {
  if ! $APPLY; then
    log_info "Password rotation: skipped in report-only mode"
    return 0
  fi

  local password
  password="$(prompt_password)"

  local user uid shell shadow
  while IFS=: read -r user _ uid _ _ _ shell; do
    if [[ "$uid" -lt "$MIN_UID" ]]; then
      continue
    fi
    if [[ -z "${ALLOW_USERS[$user]:-}" ]]; then
      continue
    fi
    if echo "$shell" | grep -qiE 'nologin|false'; then
      continue
    fi
    shadow="$(getent shadow "$user" | awk -F: '{print $2}' || true)"
    if [[ -z "$shadow" ]]; then
      continue
    fi
    if echo "$shadow" | grep -qE '^[!*]'; then
      continue
    fi

    if printf '%s:%s' "$user" "$password" | chpasswd >/dev/null 2>&1; then
      log_info "Rotated password for user: $user"
    else
      log_warn "Failed to rotate password for user: $user"
    fi
  done < /etc/passwd
}

enforce_services() {
  if [[ "$SERVICE_MGR" != "systemctl" ]]; then
    log_warn "Service enforcement skipped: systemctl not available"
    return 0
  fi

  local enabled
  enabled="$(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' || true)"
  if [[ -z "$enabled" ]]; then
    log_info "Service enforcement: no enabled services detected"
    return 0
  fi

  local -a to_disable=()
  local unit
  for unit in $enabled; do
    if [[ -n "${REQUIRED_SERVICES[$unit]:-}" ]]; then
      continue
    fi
    to_disable+=("$unit")
  done

  if [[ ${#to_disable[@]} -eq 0 ]]; then
    log_info "Service enforcement: no non-required services to disable"
    return 0
  fi

  if ! $APPLY; then
    log_info "Service enforcement: would stop/disable: ${to_disable[*]}"
    return 0
  fi

  for unit in "${to_disable[@]}"; do
    systemctl stop "$unit" >/dev/null 2>&1 || true
    if systemctl disable "$unit" >/dev/null 2>&1; then
      log_info "Disabled service: $unit"
    else
      log_warn "Failed to disable service: $unit"
    fi
  done

  if $PURGE; then
    purge_packages
  fi
}

is_package_installed() {
  local pkg="$1"
  case "$PKG_MGR" in
    apt-get)
      dpkg -s "$pkg" >/dev/null 2>&1
      ;;
    dnf|yum)
      rpm -q "$pkg" >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

purge_packages() {
  if [[ -z "$PKG_MGR" ]]; then
    log_warn "Package purge skipped: no package manager detected"
    return 0
  fi

  local pkg
  for pkg in "${UNSAFE_PACKAGES[@]}"; do
    if is_package_installed "$pkg"; then
      case "$PKG_MGR" in
        apt-get)
          apt-get -y purge "$pkg" >/dev/null 2>&1 && log_info "Purged package: $pkg" || log_warn "Failed to purge: $pkg"
          ;;
        dnf|yum)
          "$PKG_MGR" -y remove "$pkg" >/dev/null 2>&1 && log_info "Removed package: $pkg" || log_warn "Failed to remove: $pkg"
          ;;
      esac
    fi
  done
}

resolve_ports() {
  local port_entry port proto

  mapfile -t input_ports < <(csv_to_lines "$PORTS")
  for port_entry in "${input_ports[@]}"; do
    if [[ "$port_entry" == */* ]]; then
      port="${port_entry%%/*}"
      proto="${port_entry##*/}"
    else
      port="$port_entry"
      proto="tcp"
    fi
    add_allowed_port "$port" "$proto"
  done

  local service
  mapfile -t input_services < <(csv_to_lines "$SERVICES")
  for service in "${input_services[@]}"; do
    case "$service" in
      ssh|sshd)
        collect_ssh_ports
        local ssh_port
        for ssh_port in "${SSH_PORTS[@]}"; do
          add_allowed_port "$ssh_port" "tcp"
        done
        ;;
      http|apache|apache2|nginx)
        add_allowed_port "80" "tcp"
        add_allowed_port "443" "tcp"
        ;;
      ftp)
        add_allowed_port "21" "tcp"
        ;;
    esac
  done

  if [[ ${#ALLOWED_PORTS[@]} -eq 0 ]]; then
    collect_ssh_ports
    local ssh_port
    for ssh_port in "${SSH_PORTS[@]}"; do
      add_allowed_port "$ssh_port" "tcp"
    done
  fi
}

apply_firewall_policy() {
  if [[ -z "$FIREWALL_TOOL" ]]; then
    log_warn "Firewall enforcement skipped: no firewall tool detected"
    return 0
  fi

  if [[ -n "$FIREWALL_ROLLBACK_SECONDS" ]] && ! is_positive_int "$FIREWALL_ROLLBACK_SECONDS"; then
    if [[ "$FIREWALL_ROLLBACK_SECONDS" != "0" ]]; then
      die "Invalid firewall rollback seconds: $FIREWALL_ROLLBACK_SECONDS"
    fi
  fi

  if is_positive_int "$FIREWALL_ROLLBACK_SECONDS"; then
    if [[ "$FIREWALL_TOOL" != "nft" && "$FIREWALL_TOOL" != "iptables" ]]; then
      log_warn "Firewall rollback only supported for nftables/iptables"
    fi
  fi

  resolve_ports

  local ports_list
  ports_list="${!ALLOWED_PORTS[*]}"

  if ! $APPLY; then
    log_info "Firewall policy: would enforce allowlist on $FIREWALL_TOOL"
    log_info "Firewall policy: allowed ports: $ports_list"
    return 0
  fi

  case "$FIREWALL_TOOL" in
    ufw)
      ufw --force reset >/dev/null 2>&1 || true
      ufw default deny incoming >/dev/null 2>&1 || true
      ufw default allow outgoing >/dev/null 2>&1 || true
      local entry
      for entry in "${!ALLOWED_PORTS[@]}"; do
        ufw allow "$entry" >/dev/null 2>&1 || log_warn "Failed to allow $entry via ufw"
      done
      ufw --force enable >/dev/null 2>&1 || true
      ;;
    firewalld)
      local zone
      zone="$(firewall-cmd --get-default-zone 2>/dev/null || echo public)"
      local entry
      for entry in "${!ALLOWED_PORTS[@]}"; do
        firewall-cmd --zone="$zone" --add-port="$entry" >/dev/null 2>&1 || true
      done
      local svc
      for svc in $(firewall-cmd --permanent --zone="$zone" --list-services 2>/dev/null || true); do
        firewall-cmd --permanent --zone="$zone" --remove-service="$svc" >/dev/null 2>&1 || true
      done
      for entry in $(firewall-cmd --permanent --zone="$zone" --list-ports 2>/dev/null || true); do
        firewall-cmd --permanent --zone="$zone" --remove-port="$entry" >/dev/null 2>&1 || true
      done
      firewall-cmd --permanent --zone="$zone" --set-target=DROP >/dev/null 2>&1 || true
      for entry in "${!ALLOWED_PORTS[@]}"; do
        firewall-cmd --permanent --zone="$zone" --add-port="$entry" >/dev/null 2>&1 || log_warn "Failed to allow $entry via firewalld"
      done
      firewall-cmd --reload >/dev/null 2>&1 || log_warn "Failed to reload firewalld"
      ;;
    nft)
      local rules
      local backup
      backup=""
      if is_positive_int "$FIREWALL_ROLLBACK_SECONDS"; then
        if $NON_INTERACTIVE; then
          log_warn "Firewall rollback disabled in non-interactive mode"
        else
          backup="$(mktemp -t harden-nft-backup.XXXXXX)"
          nft list ruleset > "$backup" 2>/dev/null || true
          schedule_firewall_rollback "nft" "$backup" "$FIREWALL_ROLLBACK_SECONDS"
        fi
      fi
      rules=$(mktemp)
      {
        echo "table inet filter {"
        echo "  chain input {"
        echo "    type filter hook input priority 0; policy drop;"
        echo "    ct state established,related accept"
        echo "    iif lo accept"
        for entry in "${!ALLOWED_PORTS[@]}"; do
          local port="${entry%%/*}"
          local proto="${entry##*/}"
          echo "    $proto dport $port accept"
        done
        echo "  }"
        echo "  chain forward { type filter hook forward priority 0; policy drop; }"
        echo "  chain output { type filter hook output priority 0; policy accept; }"
        echo "}"
      } > "$rules"
      nft -f "$rules" >/dev/null 2>&1 || log_warn "Failed to apply nftables rules"
      rm -f "$rules"
      if [[ -n "$backup" ]] && ! $NON_INTERACTIVE; then
        if read -r -t "$FIREWALL_ROLLBACK_SECONDS" -p "Confirm firewall changes? Press Enter to keep: " _; then
          cancel_firewall_rollback
          log_info "Firewall rollback canceled"
        else
          log_warn "Firewall rollback will trigger in ${FIREWALL_ROLLBACK_SECONDS}s"
        fi
      fi
      ;;
    iptables)
      local rules
      local backup
      backup=""
      if is_positive_int "$FIREWALL_ROLLBACK_SECONDS"; then
        if $NON_INTERACTIVE; then
          log_warn "Firewall rollback disabled in non-interactive mode"
        else
          backup="$(mktemp -t harden-iptables-backup.XXXXXX)"
          iptables-save > "$backup" 2>/dev/null || true
          schedule_firewall_rollback "iptables" "$backup" "$FIREWALL_ROLLBACK_SECONDS"
        fi
      fi
      rules=$(mktemp)
      {
        echo "*filter"
        echo ":INPUT DROP [0:0]"
        echo ":FORWARD DROP [0:0]"
        echo ":OUTPUT ACCEPT [0:0]"
        echo "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        echo "-A INPUT -i lo -j ACCEPT"
        for entry in "${!ALLOWED_PORTS[@]}"; do
          local port="${entry%%/*}"
          local proto="${entry##*/}"
          echo "-A INPUT -p $proto --dport $port -j ACCEPT"
        done
        echo "COMMIT"
      } > "$rules"
      iptables-restore < "$rules" >/dev/null 2>&1 || log_warn "Failed to apply iptables rules"
      rm -f "$rules"
      if [[ -n "$backup" ]] && ! $NON_INTERACTIVE; then
        if read -r -t "$FIREWALL_ROLLBACK_SECONDS" -p "Confirm firewall changes? Press Enter to keep: " _; then
          cancel_firewall_rollback
          log_info "Firewall rollback canceled"
        else
          log_warn "Firewall rollback will trigger in ${FIREWALL_ROLLBACK_SECONDS}s"
        fi
      fi
      ;;
  esac
}

harden_ssh() {
  if ! command -v sshd >/dev/null 2>&1; then
    log_warn "SSH hardening skipped: sshd not found"
    return 0
  fi

  local allow_users=""
  local user uid shell
  while IFS=: read -r user _ uid _ _ _ shell; do
    if [[ "$uid" -lt "$MIN_UID" ]]; then
      continue
    fi
    if [[ -z "${ALLOW_USERS[$user]:-}" ]]; then
      continue
    fi
    if echo "$shell" | grep -qiE 'nologin|false'; then
      continue
    fi
    allow_users+="$user "
  done < /etc/passwd

  local config_content
  config_content="PermitRootLogin no\nMaxAuthTries 3\nLoginGraceTime 30\nClientAliveInterval 300\nClientAliveCountMax 2\n"
  if $SSH_PASSWORD_ONLY; then
    config_content+="PasswordAuthentication yes\nPubkeyAuthentication no\n"
  else
    config_content+="PasswordAuthentication no\nPubkeyAuthentication yes\n"
  fi
  if [[ -n "$allow_users" ]]; then
    config_content+="AllowUsers $allow_users\n"
  fi

  if ! $APPLY; then
    log_info "SSH hardening: would apply config"
    printf '%b' "$config_content"
    return 0
  fi

  local target_file
  if [[ -d /etc/ssh/sshd_config.d ]]; then
    target_file="/etc/ssh/sshd_config.d/99-hardening.conf"
  else
    target_file="/etc/ssh/sshd_config"
  fi

  printf '%b' "$config_content" > "$target_file"

  if sshd -t >/dev/null 2>&1; then
    if systemctl reload sshd >/dev/null 2>&1; then
      log_info "SSH hardening applied"
    elif systemctl restart sshd >/dev/null 2>&1; then
      log_info "SSH hardening applied (restart)"
    else
      log_warn "SSH reload failed; manual restart may be required"
    fi
  else
    log_error "SSH config validation failed; changes not applied"
  fi
}

apply_password_policy() {
  if ! $APPLY; then
    log_info "Password policy: skipped in report-only mode"
    return 0
  fi

  if [[ -f /etc/login.defs ]]; then
    sed -i.bak 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs 2>/dev/null || true
    sed -i.bak 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs 2>/dev/null || true
    sed -i.bak 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs 2>/dev/null || true
  fi
}

apply_updates() {
  if ! $APPLY; then
    log_info "System updates: skipped in report-only mode"
    return 0
  fi

  case "$PKG_MGR" in
    apt-get)
      apt-get update -y >/dev/null 2>&1 || true
      apt-get upgrade -y >/dev/null 2>&1 || true
      ;;
    dnf|yum)
      "$PKG_MGR" -y update >/dev/null 2>&1 || true
      ;;
  esac
}

main() {
  parse_args "$@"

  if $DELETE_USERS; then
    LOCK_USERS=false
  fi

  prompt_if_missing "required services" SERVICES true
  prompt_if_missing "users" USERS false
  prompt_if_missing "groups" GROUPS false
  prompt_if_missing "allowed ports" PORTS false

  detect_platform
  detect_tools
  require_root_if_applying

  recon

  resolve_required_users
  resolve_required_services

  enforce_users
  enforce_services

  harden_ssh
  apply_firewall_policy
  apply_password_policy
  apply_updates

  log_info "Done"
}

main "$@"
