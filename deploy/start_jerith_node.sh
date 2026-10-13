#!/usr/bin/env bash
# Launch script for the transient user unit `jerith-node-dev.service`
# (systemd-run equivalent: `systemd-run --user --unit jerith-node-dev ...`).
# Lives in-repo because /tmp scripts don't survive tmp cleanup; a restart of
# the unit must therefore restore it before the next `systemctl --user
# restart jerith-node-dev`. See jerith-mesh docs/DEPLOY-BOOTSTRAP.md for the
# live bootstrap counterpart on the mesh host.
export JERITH_PORT=8322
cd /home/noodly/Documents/Projects/jerithchain
exec python3 jerith_node.py
