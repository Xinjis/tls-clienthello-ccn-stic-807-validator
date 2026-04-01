#!/usr/bin/env bash
set -euo pipefail

STANDARD="CCN-STIC-807"
REQUIREMENT_DESC="El cliente no debe iniciar canales de comunicación ofreciendo cipher suites clasificadas como Legacy o Not Recommended por ${STANDARD}"

if [[ $# -lt 1 ]]; then
  echo "Uso:"
  echo "  $0 <archivo1> [archivo2 ... archivoN]"
  echo
  echo "Ejemplos:"
  echo "  $0 captura1.txt"
  echo "  $0 captura1.txt captura2.txt captura3.txt"
  echo "  $0 *.txt"
  exit 1
fi

LEGACY_CIPHERS=(
  "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
  "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
  "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
  "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
  "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
  "TLS_RSA_WITH_AES_128_CBC_SHA256"
  "TLS_RSA_WITH_AES_128_GCM_SHA256"
  "TLS_RSA_WITH_AES_256_CBC_SHA256"
  "TLS_RSA_WITH_AES_256_GCM_SHA384"
)

NR_CIPHERS=(
  "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
  "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
  "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
  "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
  "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
  "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
  "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
  "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
  "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
  "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
  "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
  "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
  "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
  "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
  "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
  "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
  "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
  "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
  "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
  "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
  "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
  "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
  "TLS_RSA_WITH_AES_128_CBC_SHA"
  "TLS_RSA_WITH_AES_256_CBC_SHA"
)

LEGACY_GROUPS=(
  "ffdhe2048"
)

EXPECTED_ALLOWED_HINT=(
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
  "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
  "x25519"
)

overall_fail=0

normalize_file() {
  local file="$1"
  sed 's/\r$//' "$file"
}

check_file() {
  local file="$1"

  if [[ ! -f "$file" ]]; then
    echo
    echo "============================================================"
    echo "Analizando archivo: $file"
    echo "============================================================"
    echo "[-] El archivo no existe o no es accesible"
    overall_fail=1
    return
  fi

  local filename
  filename="$(basename -- "$file")"

  echo
  echo "============================================================"
  echo "Analizando archivo: $filename"
  echo "Ruta: $file"
  echo "============================================================"
  echo "Criterio normativo: ${STANDARD}"
  echo "Requisito evaluado: ${REQUIREMENT_DESC}"

  local content
  content="$(normalize_file "$file")"

  if ! grep -qiE 'Client Hello|Cipher Suite|Supported Group|Group:' <<< "$content"; then
    echo
    echo "[WARN] El archivo no parece contener un Client Hello exportado de Wireshark/TShark."
    echo "[WARN] La muestra puede ser incompleta o no corresponder al paquete correcto."
  fi

  echo
  echo "[i] Suites detectadas en $filename:"
  grep -oE 'TLS_[A-Z0-9_]+_WITH_[A-Z0-9_]+' <<< "$content" | sort -u | sed 's/^/  - /' || true

  echo
  echo "[i] Grupos detectados en $filename:"
  grep -oiE '(x25519|x448|secp256r1|secp384r1|secp521r1|ffdhe[0-9]+)' <<< "$content" | sort -u | sed 's/^/  - /' || true

  local file_fail=0
  local found_any_legacy=0
  local found_any_nr=0
  local found_any_group=0

  echo
  echo "[i] Buscando suites Legacy según ${STANDARD}:"
  for s in "${LEGACY_CIPHERS[@]}"; do
    if grep -Fqi "$s" <<< "$content"; then
      echo "  [FAIL][LEGACY] $s"
      file_fail=1
      found_any_legacy=1
    fi
  done
  [[ $found_any_legacy -eq 0 ]] && echo "  [OK] No aparecen suites Legacy del listado evaluado"

  echo
  echo "[i] Buscando suites Not Recommended según ${STANDARD}:"
  for s in "${NR_CIPHERS[@]}"; do
    if grep -Fqi "$s" <<< "$content"; then
      echo "  [FAIL][NOT_RECOMMENDED] $s"
      file_fail=1
      found_any_nr=1
    fi
  done
  [[ $found_any_nr -eq 0 ]] && echo "  [OK] No aparecen suites Not Recommended del listado evaluado"

  echo
  echo "[i] Buscando grupos Legacy según ${STANDARD}:"
  for g in "${LEGACY_GROUPS[@]}"; do
    if grep -Fqi "$g" <<< "$content"; then
      echo "  [FAIL][LEGACY_GROUP] $g"
      file_fail=1
      found_any_group=1
    fi
  done
  [[ $found_any_group -eq 0 ]] && echo "  [OK] No aparecen grupos Legacy del listado evaluado"

  echo
  echo "[i] Indicadores positivos esperables:"
  local found_positive=0
  for s in "${EXPECTED_ALLOWED_HINT[@]}"; do
    if grep -Fqi "$s" <<< "$content"; then
      echo "  [OK] Presente: $s"
      found_positive=1
    fi
  done
  [[ $found_positive -eq 0 ]] && echo "  [INFO] No se detectaron indicadores positivos del listado de referencia"

  echo
  if [[ $file_fail -eq 1 ]]; then
    echo "[RESULTADO][$filename] FAIL"
    echo "  Evidencia de NO conformidad con ${STANDARD}."
    echo "  Motivo: el Client Hello ofrece suites o grupos clasificados como Legacy o Not Recommended."
    echo "  Criterio evaluado: ${REQUIREMENT_DESC}"
    overall_fail=1
  else
    echo "[RESULTADO][$filename] PASS"
    echo "  No se ha detectado en esta muestra evidencia de no conformidad con ${STANDARD}."
    echo "  Nota: este resultado no acredita cumplimiento total; solo indica ausencia de suites/grupos prohibidos en la evidencia analizada."
  fi
}

for f in "$@"; do
  check_file "$f"
done

echo
echo "============================================================"
echo "Resultado global"
echo "============================================================"
echo "Criterio normativo: ${STANDARD}"
echo "Requisito evaluado: ${REQUIREMENT_DESC}"

if [[ $overall_fail -eq 1 ]]; then
  echo "[FAIL] Hay evidencia de NO conformidad con ${STANDARD} en los archivos analizados."
  echo "       Se detectan suites o grupos clasificados como Legacy o Not Recommended en la evidencia revisada."
  exit 2
else
  echo "[PASS] No se detecta evidencia de no conformidad con ${STANDARD} en los archivos analizados."
  echo "       No se observaron suites o grupos prohibidos del listado evaluado en la muestra revisada."
  exit 0
fi
