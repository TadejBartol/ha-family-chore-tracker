#!/bin/bash
set -e

# ==============================================================================
# Home Assistant Community Add-on: Family Chore Tracker
# Runs the Family Chore Tracker
# ==============================================================================

echo "Starting Family Chore Tracker..."

# Set default environment variables
export DATABASE_PATH="${DATABASE_PATH:-/data/chores.db}"
export PORT="${PORT:-3000}"
export NODE_ENV="production"
export HASSIO="true"
export HASSIO_TOKEN="${HASSIO_TOKEN:-}"

# Log configuration
echo "Database Path: ${DATABASE_PATH}"
echo "Port: ${PORT}"
echo "Node Environment: ${NODE_ENV}"
echo "Home Assistant Mode: ${HASSIO}"

# Create database directory if it doesn't exist
mkdir -p "$(dirname "${DATABASE_PATH}")"

# Check if database directory is writable
if [[ ! -w "$(dirname "${DATABASE_PATH}")" ]]; then
    echo "ERROR: Cannot write to database directory: $(dirname "${DATABASE_PATH}")"
    exit 1
fi

echo "Starting Family Chore Tracker on port ${PORT}"

# Start the Node.js application
exec node backend.js 