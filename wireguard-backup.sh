#!/bin/bash

# Back up on-disk WireGuard settings and generated client configurations.
set -euo pipefail
umask 077

if [[ ${1:-} == '--help' || ${1:-} == '-h' ]]; then
	echo "Usage: bash wireguard-backup.sh [OUTPUT_DIRECTORY [EXTRA_CLIENT_DIRECTORY ...]]"
	echo "Defaults: output /root/wireguard-backups; search /root and /home for *-client-*.conf."
	exit 0
fi

if [[ ${EUID} -ne 0 ]]; then
	echo "Run this script as root." >&2
	exit 1
fi
if [[ ! -d /etc/wireguard ]]; then
	echo "/etc/wireguard does not exist; nothing to back up." >&2
	exit 1
fi

OUTPUT_DIR=${1:-/root/wireguard-backups}
if [[ $# -gt 0 ]]; then
	shift
fi
mkdir -p -- "${OUTPUT_DIR}"
OUTPUT_DIR=$(cd -- "${OUTPUT_DIR}" && pwd -P)
case "${OUTPUT_DIR}/" in
/etc/wireguard/*)
	echo "Store backups outside /etc/wireguard." >&2
	exit 1
	;;
esac
WORK_DIR=$(mktemp -d "${OUTPUT_DIR}/.wg-backup.XXXXXXXX")
trap 'rm -rf -- "${WORK_DIR}"' EXIT
mkdir -p "${WORK_DIR}/files/etc"

# Copy configuration files, never execute /etc/wireguard/params.
cp -pR /etc/wireguard "${WORK_DIR}/files/etc/"
if [[ -f /etc/sysctl.d/wg.conf ]]; then
	mkdir -p "${WORK_DIR}/files/etc/sysctl.d"
	cp -p /etc/sysctl.d/wg.conf "${WORK_DIR}/files/etc/sysctl.d/"
fi

SEARCH_DIRS=()
for directory in /root /home "$@"; do
	if [[ ! -d ${directory} ]]; then
		if [[ ${directory} == /root || ${directory} == /home ]]; then
			continue
		fi
		echo "Client directory does not exist: ${directory}" >&2
		exit 1
	fi
	SEARCH_DIRS+=("$(cd -- "${directory}" && pwd -P)")
done

# Prune our staging area even when the output directory is under a search root.
# A separate find command ensures search failures abort the backup.
find "${SEARCH_DIRS[@]}" -path "${WORK_DIR}" -prune -o -type f -name '*-client-*.conf' -print0 >"${WORK_DIR}/clients.list"
CLIENT_COUNT=0
while IFS= read -r -d '' client; do
	relative=${client#/}
	mkdir -p -- "${WORK_DIR}/files/$(dirname -- "${relative}")"
	cp -p -- "${client}" "${WORK_DIR}/files/${relative}"
	CLIENT_COUNT=$((CLIENT_COUNT + 1))
done <"${WORK_DIR}/clients.list"

ARCHIVE_NAME="wireguard-$(date -u +%Y%m%dT%H%M%SZ)-${WORK_DIR##*.}.tar.gz"
tar -czf "${WORK_DIR}/${ARCHIVE_NAME}" -C "${WORK_DIR}/files" .
tar -tzf "${WORK_DIR}/${ARCHIVE_NAME}" >/dev/null
chmod 600 "${WORK_DIR}/${ARCHIVE_NAME}"
mv -- "${WORK_DIR}/${ARCHIVE_NAME}" "${OUTPUT_DIR}/${ARCHIVE_NAME}"
echo "Backup created: ${OUTPUT_DIR}/${ARCHIVE_NAME}"
echo "Client files copied: ${CLIENT_COUNT} (overlapping search directories may count twice)."
echo "Contains private keys. Store securely; this archive is not encrypted."
