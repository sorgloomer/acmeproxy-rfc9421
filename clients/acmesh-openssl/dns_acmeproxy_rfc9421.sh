#!/usr/bin/env sh
# shellcheck disable=SC2034
dns_acmeproxy_rfc9421_info='acmeproxy-rfc9421, signing with OpenSSL 3
Site: github.com/sorgloomer/acmeproxy-rfc9421
Options:
 ACMEPROXY_ENDPOINT API endpoint, e.g. "https://acmeproxy.example.com"
 KEY_ID Key ID of this client
 KEY_PATH PKCS#8 PEM private key file (see keygen.sh)
 KEY_VALUE PKCS#8 PEM private key text, instead of KEY_PATH
'

dns_acmeproxy_rfc9421_add() {
  _acmeproxy9421 present "$1" "$2"
}

dns_acmeproxy_rfc9421_rm() {
  _acmeproxy9421 cleanup "$1" "$2"
}

_acmeproxy9421() {
  ACMEPROXY_ENDPOINT="${ACMEPROXY_ENDPOINT:-$(_readaccountconf_mutable ACMEPROXY_ENDPOINT)}"
  KEY_ID="${KEY_ID:-$(_readaccountconf_mutable KEY_ID)}"
  if [ -z "$KEY_PATH" ] && [ -z "$KEY_VALUE" ]; then
    KEY_PATH="$(_readaccountconf_mutable KEY_PATH)"
    KEY_VALUE="$(_readaccountconf_mutable KEY_VALUE)"
  fi
  if [ -z "$ACMEPROXY_ENDPOINT" ] || [ -z "$KEY_ID" ] || { [ -z "$KEY_PATH" ] && [ -z "$KEY_VALUE" ]; }; then
    _err "Please set ACMEPROXY_ENDPOINT, KEY_ID and KEY_PATH (or KEY_VALUE)."
    return 1
  fi
  _saveaccountconf_mutable ACMEPROXY_ENDPOINT "$ACMEPROXY_ENDPOINT"
  _saveaccountconf_mutable KEY_ID "$KEY_ID"
  _saveaccountconf_mutable KEY_PATH "$KEY_PATH"
  _saveaccountconf_mutable KEY_VALUE "$KEY_VALUE" base64encode

  _ap_dir="$(mktemp -d)" || return 1
  _acmeproxy9421_request "$@"
  _ap_ret=$?
  rm -rf "$_ap_dir"
  return $_ap_ret
}

# action fqdn value
_acmeproxy9421_request() {
  _ap_key="$KEY_PATH"
  if [ "$KEY_VALUE" ]; then
    _ap_key="$_ap_dir/key.pem"
    printf "%s\n" "$KEY_VALUE" >"$_ap_key"
  fi
  case "$(openssl pkey -in "$_ap_key" -noout -text 2>/dev/null)" in
  *ED25519*) _ap_alg=ed25519 ;;
  *prime256v1* | *P-256*) _ap_alg=ecdsa-p256-sha256 ;;
  *modulus:*) _ap_alg=rsa-pss-sha512 ;;
  *)
    _err "Unsupported or unreadable private key (need PKCS#8 Ed25519, ECDSA P-256 or RSA)"
    return 1
    ;;
  esac

  _ap_rest="${ACMEPROXY_ENDPOINT#*://}"
  _ap_authority="${_ap_rest%%/*}"
  _ap_path="$(printf "%s" "/${_ap_rest#"$_ap_authority"}/$1" | sed 's://*:/:g')"
  _ap_body="{\"fqdn\":\"${2%.}\",\"value\":\"$3\"}"
  _ap_digest="sha-256=:$(printf "%s" "$_ap_body" | openssl dgst -sha256 -binary | openssl base64 -A):"
  _ap_params="(\"@method\" \"@authority\" \"@path\" \"content-type\" \"content-digest\");created=$(date +%s);keyid=\"$KEY_ID\";alg=\"$_ap_alg\";nonce=\"$(openssl rand -hex 16)\""
  printf '"@method": POST\n"@authority": %s\n"@path": %s\n"content-type": application/json\n"content-digest": %s\n"@signature-params": %s' \
    "$_ap_authority" "$_ap_path" "$_ap_digest" "$_ap_params" >"$_ap_dir/base"

  case "$_ap_alg" in
  ed25519) openssl pkeyutl -sign -inkey "$_ap_key" -rawin -in "$_ap_dir/base" -out "$_ap_dir/sig" ;;
  ecdsa-p256-sha256) openssl dgst -sha256 -sign "$_ap_key" "$_ap_dir/base" | _acmeproxy9421_der_to_raw >"$_ap_dir/sig" ;;
  rsa-pss-sha512) openssl dgst -sha512 -sign "$_ap_key" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:64 -out "$_ap_dir/sig" "$_ap_dir/base" ;;
  esac || return 1

  export _H1="Content-Digest: $_ap_digest"
  export _H2="Signature-Input: sig1=$_ap_params"
  export _H3="Signature: sig1=:$(openssl base64 -A -in "$_ap_dir/sig"):"
  _ap_response="$(_post "$_ap_body" "${ACMEPROXY_ENDPOINT%/}/$1" "" "POST" "application/json")"
  export _H1="" _H2="" _H3=""
  if _contains "$_ap_response" "\"value\":\"$3\""; then
    return 0
  fi
  _err "acmeproxy-rfc9421 $1 failed: $_ap_response"
  return 1
}

# Converts a DER ECDSA P-256 signature (stdin) to the 64 byte r||s form.
_acmeproxy9421_der_to_raw() {
  _ap_hex="$(od -An -v -tx1 | tr -d ' \n')"
  _ap_hex="${_ap_hex#30??02}" # SEQUENCE, INTEGER r
  _ap_len=$((0x${_ap_hex%"${_ap_hex#??}"} * 2))
  _ap_hex="${_ap_hex#??}"
  _ap_r="$(printf "%s" "$_ap_hex" | cut -c1-$_ap_len)"
  _ap_hex="$(printf "%s" "$_ap_hex" | cut -c$((_ap_len + 5))-)" # skip r, INTEGER s, length
  for _ap_n in "$_ap_r" "$_ap_hex"; do
    _ap_n="$(printf "%64s" "${_ap_n#00}" | tr ' ' 0)"
    while [ -n "$_ap_n" ]; do
      printf "\\$(printf %o "0x${_ap_n%"${_ap_n#??}"}")"
      _ap_n="${_ap_n#??}"
    done
  done
}
