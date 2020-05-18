#!/bin/bash
set -uo pipefail

for i in $(seq 1 5); do
	python3 main.py

	echo
	read -p "Reissue [yN]? " -n 1 answer
	echo

	case "$answer" in
		[yY])
			# continuing
			;;

		*)
			exit 0
			;;
	esac
done

echo Too many failures, aborting issuance attepmt
