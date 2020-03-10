#!/bin/sh

pass="praxis"
tmp="$(mktemp -d)"
f1="${tmp}/f1"
f2="${tmp}/f2"

cleanup() {
	[ -n "${tmp}" ] && rm -fr "${tmp}"
}
trap cleanup 0

echo "testing this 123..." > "${f1}"
./aescrypt -e -p "${pass}" "${f1}"
cp "${f1}.aes" "${f2}.aes"
./aescrypt -d -p "${pass}" "${f2}.aes"
cmp "${f1}" "${f2}"
