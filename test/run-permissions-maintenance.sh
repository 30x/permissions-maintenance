export IPADDRESS="127.0.0.1"
export PORT=3001
export COMPONENT="permissions-api"
export SPEEDUP=10
export EXTERNAL_ROUTER_HOST="localhost"
export EXTERNAL_ROUTER_PORT="8080"
export INTERNAL_ROUTER_HOST="localhost"
export INTERNAL_ROUTER_PORT="8080"

source test/local-export-pg-connection-variables.sh
node permissions-maintenance.js