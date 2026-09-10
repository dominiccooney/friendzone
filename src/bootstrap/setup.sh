# Run with sh (works when invoked from bash or zsh). Do not source this installer.
set -eu
umask 077
command -v curl >/dev/null 2>&1 || { echo 'curl is required in the guest.' >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo 'This script supports Linux only; select PowerShell for Windows.' >&2; exit 1; }
case $(uname -m) in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) echo 'Unsupported guest architecture (supported: x86_64, aarch64).' >&2; exit 1 ;;
esac
if [ -n "${SUDO_USER:-}" ]; then echo 'Run as the guest user, without sudo.' >&2; exit 1; fi
[ -n "$container" ] || container=$(hostname)
config=${XDG_CONFIG_HOME:-"$HOME/.config"}/friendzone
mkdir -p "$config"
staging=$(mktemp -d "$config/bootstrap.XXXXXXXX")
trap 'rm -rf "$staging"' 0
trap 'exit 1' HUP INT TERM
echo "Downloading Linux $arch fz from $broker (trusted host only)..."
# --noproxy works even before guest approval or with stale proxy variables.
# Never execute a partial download or follow redirects to another origin.
code=$(curl --noproxy '*' --silent --show-error --connect-timeout 5 --max-time 120 --output "$staging/fz" --write-out '%{http_code}' "$broker/bootstrap/fz?target=linux-$arch")
if [ "$code" != 200 ]; then
  cat "$staging/fz" >&2
  echo 'No guest configuration was changed. Ask the host to provide the exact guest build, then retry.' >&2
  exit 1
fi
chmod 700 "$staging/fz"
"$staging/fz" --version
echo 'Configuring this GUEST user, including shell profiles. Stop guest Cline first.'
"$staging/fz" setup --broker "$broker" --container "$container" --output "$config/friendzone-ca.pem" --shell sh --persist-profile
mv -f "$staging/fz" "$config/fz"
echo 'Setup complete. Profile hooks are installed; start a new login shell or source the activation command printed above.'
echo 'Non-interactive bash inherits BASH_ENV from an activated parent; zsh reads .zshenv. Plain sh/services need an activated launcher.'
echo 'No firewall or system trust store was changed. Approve the guest in the host Inbox.'