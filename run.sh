#!/usr/bin/with-contenv bashio

# ==============================================================================
# Home Assistant Community Add-on: Family Chore Tracker
# Runs the Family Chore Tracker
# ==============================================================================

bashio::log.info "Starting Family Chore Tracker..."

# Get options from add-on configuration
DATABASE_PATH=$(bashio::config 'database_path')
PORT=$(bashio::config 'port')
LOG_LEVEL=$(bashio::config 'log_level')
SSL=$(bashio::config 'ssl')
CERTFILE=$(bashio::config 'certfile')
KEYFILE=$(bashio::config 'keyfile')

# Set environment variables
export DATABASE_PATH="${DATABASE_PATH:-/data/chores.db}"
export PORT="${PORT:-3000}"
export LOG_LEVEL="${LOG_LEVEL:-info}"
export NODE_ENV="production"
export HASSIO="true"
export HASSIO_TOKEN="${HASSIO_TOKEN:-}"

# Log configuration
bashio::log.info "Database Path: ${DATABASE_PATH}"
bashio::log.info "Port: ${PORT}"
bashio::log.info "Log Level: ${LOG_LEVEL}"
bashio::log.info "SSL: ${SSL}"

# Check if SSL is enabled
if bashio::var.true "${SSL}"; then
    bashio::log.info "SSL is enabled"
    export SSL_CERT="/ssl/${CERTFILE}"
    export SSL_KEY="/ssl/${KEYFILE}"
    
    if [[ ! -f "${SSL_CERT}" ]]; then
        bashio::log.fatal "SSL certificate file not found: ${SSL_CERT}"
        bashio::exit.nok
    fi
    
    if [[ ! -f "${SSL_KEY}" ]]; then
        bashio::log.fatal "SSL key file not found: ${SSL_KEY}"
        bashio::exit.nok
    fi
else
    bashio::log.info "SSL is disabled"
fi

# Create database directory if it doesn't exist
mkdir -p "$(dirname "${DATABASE_PATH}")"

# Check if database is accessible
if [[ ! -w "$(dirname "${DATABASE_PATH}")" ]]; then
    bashio::log.fatal "Cannot write to database directory: $(dirname "${DATABASE_PATH}")"
    bashio::exit.nok
fi

# Start the application
bashio::log.info "Starting Family Chore Tracker on port ${PORT}"

# Run the Node.js application
exec node backend.js 