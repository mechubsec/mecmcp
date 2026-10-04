#!/usr/bin/env bash
set -euo pipefail
install -d -m 0755 /etc/systemd/system/svc.service.d
install -m 0755 bin/svc /usr/local/bin/svc
