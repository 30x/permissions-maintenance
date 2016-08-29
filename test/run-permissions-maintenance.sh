export IPADDRESS="127.0.0.1"
export PORT=3001
export COMPONENT="permissions-api"
export SPEEDUP=10
export EXTERNAL_ROUTER="localhost:8080"
export INTERNAL_ROUTER="localhost:8080"

source ../export-pg-variables.sh
node permissions-maintenance.js