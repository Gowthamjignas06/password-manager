#!/usr/bin/env bash
# Password Manager — Bash + GPG (symmetric encryption)
# Implements: setup, registration/login, add/view/delete credentials,
# password generation, and a simple test mode.
# Dependencies: bash, gpg, grep, sed, awk, column, head, tr, mktemp, mkdir, rm, mv

set -euo pipefail

VERSION="1.0.0"
BASE_DIR="$HOME/.password_manager"
USERS_DIR="$BASE_DIR/users"
MASTER_FILE_ENC="$BASE_DIR/master_passwords.csv.gpg"
# We add an explicit OWNER column in the master index so multiple users can coexist safely.
MASTER_HEADER="owner,label,username,password"

GPG_COMMON=("--batch" "--yes" "--pinentry-mode" "loopback")

# --- Utilities ---------------------------------------------------------------
log() { printf "[pm] %s\n" "$*"; }
err() { printf "[pm:ERR] %s\n" "$*" 1>&2; }

die() { err "$*"; exit 1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

require_deps() {
  local deps=(gpg grep sed awk column head tr mktemp mkdir rm mv)
  for d in "${deps[@]}"; do
    have_cmd "$d" || die "Missing dependency: $d"
  done
}

cleanup_files=()
cleanup() {
  for f in "${cleanup_files[@]:-}"; do
    [[ -f "$f" ]] && shred -u "$f" 2>/dev/null || rm -f "$f" 2>/dev/null || true
  done
}
trap cleanup EXIT

mktemp_secure() {
  local f
  f=$(mktemp) || die "mktemp failed"
  cleanup_files+=("$f")
  printf "%s" "$f"
}

# --- Environment setup -------------------------------------------------------
setup_env() {
  mkdir -p "$USERS_DIR"
  chmod 700 "$BASE_DIR" "$USERS_DIR"
  # Initialize master file if missing (encrypted, with header)
  if [[ ! -f "$MASTER_FILE_ENC" ]]; then
    local tmp
    tmp=$(mktemp_secure)
    printf "%s\n" "$MASTER_HEADER" >"$tmp"
    # Use a setup passphrase only for the initial encryption; re-encrypted per-session when updated.
    gpg "${GPG_COMMON[@]}" --passphrase "init" -c -o "$MASTER_FILE_ENC" "$tmp"
  fi
}

# --- Authentication ----------------------------------------------------------
USER_NAME=""
USER_PASS=""
USER_FILE_ENC=""
USER_HEADER="label,username,password"

prompt_credentials() {
  read -rp "Enter your login name: " USER_NAME
  [[ -n "$USER_NAME" ]] || die "Empty username not allowed"
  read -rsp "Enter master passphrase: " USER_PASS; echo
  [[ -n "$USER_PASS" ]] || die "Empty passphrase not allowed"
  USER_FILE_ENC="$USERS_DIR/${USER_NAME}.csv.gpg"
}

register_user() {
  # Create a new encrypted CSV with header
  local tmp
  tmp=$(mktemp_secure)
  printf "%s\n" "$USER_HEADER" >"$tmp"
  gpg "${GPG_COMMON[@]}" --passphrase "$USER_PASS" -c -o "$USER_FILE_ENC" "$tmp"
  log "User '$USER_NAME' registered."
}

user_exists() { [[ -f "$USER_FILE_ENC" ]]; }

decrypt_to_tmp() {
  # $1: encrypted file, $2: passphrase -> prints path to temp plaintext
  local enc="$1" pass="$2" tmp
  tmp=$(mktemp_secure)
  gpg "${GPG_COMMON[@]}" --passphrase "$pass" -o "$tmp" -d "$enc" >/dev/null 2>&1 || return 1
  printf "%s" "$tmp"
}

encrypt_from_tmp() {
  # $1: tmp plaintext, $2: passphrase, $3: dest enc file
  gpg "${GPG_COMMON[@]}" --passphrase "$2" -c -o "$3" "$1"
}

login_or_register() {
  prompt_credentials
  if user_exists; then
    # Verify passphrase by decrypting
    if ! decrypt_to_tmp "$USER_FILE_ENC" "$USER_PASS" >/dev/null; then
      die "Incorrect passphrase for existing user."
    fi
    log "Welcome back, $USER_NAME."
  else
    read -rp "User not found. Register new user '$USER_NAME'? [y/N]: " yn
    [[ "${yn:-}" =~ ^[Yy]$ ]] || die "Registration cancelled"
    register_user
  fi
}

# --- Master index helpers ----------------------------------------------------
master_decrypt_for_edit() {
  # We will decrypt with a temporary session key == user's passphrase for simplicity.
  decrypt_to_tmp "$MASTER_FILE_ENC" "init" 2>/dev/null || decrypt_to_tmp "$MASTER_FILE_ENC" "$USER_PASS"
}

master_encrypt_save() {
  local tmp="$1"
  # Re-encrypt with the same simple passphrase used on init to avoid cross-user coupling.
  gpg "${GPG_COMMON[@]}" --passphrase "init" -c -o "$MASTER_FILE_ENC" "$tmp"
}

# --- Feature: Add password ---------------------------------------------------
random_password() {
  local len="$1"
  # Avoid locale issues, ensure C
  LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*()_+{}[]-=<>?' </dev/urandom | head -c "$len"
}

add_password() {
  local label acc pw gen
  read -rp "Label (e.g., github, bank): " label
  read -rp "Account username/login: " acc
  read -rp "Generate password automatically? [y/N]: " gen
  if [[ "$gen" =~ ^[Yy]$ ]]; then
    read -rp "Length (default 16): " l; l=${l:-16}
    pw=$(random_password "$l")
    log "Generated password."
  else
    read -rsp "Enter password: " pw; echo
  fi
  # Append to user file
  local user_tmp
  user_tmp=$(decrypt_to_tmp "$USER_FILE_ENC" "$USER_PASS") || die "Decrypt failed"
  printf "%s,%s,%s\n" "$label" "$acc" "$pw" >>"$user_tmp"
  encrypt_from_tmp "$user_tmp" "$USER_PASS" "$USER_FILE_ENC"

  # Update master index
  local mtmp
  mtmp=$(master_decrypt_for_edit) || die "Cannot open master index"
  # Remove any existing row for same owner+label+username to avoid dupes
  awk -F, -v OFS="," -v o="$USER_NAME" -v l="$label" -v a="$acc" 'NR==1 || !( $1==o && $2==l && $3==a )' "$mtmp" >"${mtmp}.new"
  mv "${mtmp}.new" "$mtmp"
  printf "%s,%s,%s,%s\n" "$USER_NAME" "$label" "$acc" "$pw" >>"$mtmp"
  master_encrypt_save "$mtmp"
  log "Saved credential '$label'."
}

# --- Feature: View passwords -------------------------------------------------
view_passwords() {
  local user_tmp
  user_tmp=$(decrypt_to_tmp "$USER_FILE_ENC" "$USER_PASS") || die "Decrypt failed"
  if [[ $(wc -l <"$user_tmp") -le 1 ]]; then
    log "No passwords stored yet."
    return 0
  fi
  column -s, -t <"$user_tmp"
}

# --- Feature: Delete by label ------------------------------------------------
delete_password() {
  local label
  read -rp "Label to delete: " label

  # Update user file
  local user_tmp
  user_tmp=$(decrypt_to_tmp "$USER_FILE_ENC" "$USER_PASS") || die "Decrypt failed"
  awk -F, -v OFS="," -v l="$label" 'NR==1 || $1!=l' "$user_tmp" >"${user_tmp}.new"
  mv "${user_tmp}.new" "$user_tmp"
  encrypt_from_tmp "$user_tmp" "$USER_PASS" "$USER_FILE_ENC"

  # Update master index (scoped to this owner)
  local mtmp
  mtmp=$(master_decrypt_for_edit) || die "Cannot open master index"
  awk -F, -v OFS="," -v o="$USER_NAME" -v l="$label" 'NR==1 || !($1==o && $2==l)' "$mtmp" >"${mtmp}.new"
  mv "${mtmp}.new" "$mtmp"
  master_encrypt_save "$mtmp"
  log "Deleted entries with label '$label' for user '$USER_NAME'."
}

# --- Menu --------------------------------------------------------------------
menu() {
  printf "\nPassword Manager (v%s) — user: %s\n" "$VERSION" "$USER_NAME"
  printf "1) Add password\n2) View passwords\n3) Delete by label\n4) Generate random password\n5) Logout\n"
}

generate_password_ui() {
  read -rp "Length (default 16): " l; l=${l:-16}
  pw=$(random_password "$l")
  printf "Generated: %s\n" "$pw"
}

# --- Test suite (very light) -------------------------------------------------
run_tests() {
  log "Running smoke tests..."
  local tmpdir; tmpdir=$(mktemp -d)
  cleanup_files+=("$tmpdir")
  local old_base="$BASE_DIR"; BASE_DIR="$tmpdir/.password_manager"; USERS_DIR="$BASE_DIR/users"; MASTER_FILE_ENC="$BASE_DIR/master_passwords.csv.gpg"
  setup_env
  USER_NAME="tester"; USER_PASS="secret"; USER_FILE_ENC="$USERS_DIR/${USER_NAME}.csv.gpg"
  register_user
  # add one
  label="example"; acc="user@example"; pw="p@ssW0rd"
  local user_tmp
  user_tmp=$(decrypt_to_tmp "$USER_FILE_ENC" "$USER_PASS")
  printf "%s,%s,%s\n" "$label" "$acc" "$pw" >>"$user_tmp"
  encrypt_from_tmp "$user_tmp" "$USER_PASS" "$USER_FILE_ENC"
  # verify view
  out=$(decrypt_to_tmp "$USER_FILE_ENC" "$USER_PASS")
  grep -q "$label,$acc,$pw" "$out" || die "Test failed: entry not found"
  log "Smoke tests passed."
}

# --- Main --------------------------------------------------------------------
main() {
  if [[ "${1:-}" == "--test" ]]; then
    require_deps; setup_env; run_tests; exit 0
  fi
  require_deps
  setup_env
  login_or_register
  while true; do
    menu
    read -rp "Choose: " choice
    case "$choice" in
      1) add_password ;;
      2) view_passwords ;;
      3) delete_password ;;
      4) generate_password_ui ;;
      5) log "Goodbye!"; break ;;
      *) echo "Invalid choice" ;;
    esac
  done
}

main "$@"
