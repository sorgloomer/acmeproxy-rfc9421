#!/usr/bin/env sh
# shellcheck disable=SC2034
dns_acmeproxy_rfc9421_info='acmeproxy-rfc9421, using the cli-go client
Site: github.com/sorgloomer/acmeproxy-rfc9421
Options:
 ACMEPROXY_ENDPOINT API endpoint, e.g. "https://acmeproxy.example.com"
 KEY_ID Key ID of this client
 KEY_PATH PKCS#8 PEM private key file (see keygen.sh)
 KEY_VALUE PKCS#8 PEM private key text, instead of KEY_PATH
 ACMEPROXY_BIN Path of cli-go. Optional, default "cli-go"
'

dns_acmeproxy_rfc9421_add() {
  _acmeproxy9421 present "$1" "$2"
}

dns_acmeproxy_rfc9421_rm() {
  _acmeproxy9421 cleanup "$1" "$2"
}

_acmeproxy9421() {
  ACMEPROXY_ENDPOINT="${ACMEPROXY_ENDPOINT:-$(_readaccountconf_mutable ACMEPROXY_ENDPOINT)}"
  ACMEPROXY_BIN="${ACMEPROXY_BIN:-$(_readaccountconf_mutable ACMEPROXY_BIN)}"
  KEY_ID="${KEY_ID:-$(_readaccountconf_mutable KEY_ID)}"
  if [ -z "$KEY_PATH" ] && [ -z "$KEY_VALUE" ]; then
    KEY_PATH="$(_readaccountconf_mutable KEY_PATH)"
    KEY_VALUE="$(_readaccountconf_mutable KEY_VALUE)"
  fi
  _saveaccountconf_mutable ACMEPROXY_ENDPOINT "$ACMEPROXY_ENDPOINT"
  _saveaccountconf_mutable ACMEPROXY_BIN "$ACMEPROXY_BIN"
  _saveaccountconf_mutable KEY_ID "$KEY_ID"
  _saveaccountconf_mutable KEY_PATH "$KEY_PATH"
  _saveaccountconf_mutable KEY_VALUE "$KEY_VALUE" base64encode

  if ! _ap_out="$(ACMEPROXY_ENDPOINT="$ACMEPROXY_ENDPOINT" KEY_ID="$KEY_ID" KEY_PATH="$KEY_PATH" KEY_VALUE="$KEY_VALUE" \
    "${ACMEPROXY_BIN:-cli-go}" "$1" "$2" "$3" 2>&1)"; then
    _err "$_ap_out"
    return 1
  fi
  _info "$_ap_out"
}
