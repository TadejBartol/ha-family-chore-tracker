ARG BUILD_FROM
FROM $BUILD_FROM

# Set shell
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install Node.js and dependencies
RUN apk add --no-cache \
    nodejs \
    npm \
    sqlite \
    curl \
    python3 \
    make \
    g++ \
    && rm -rf /var/cache/apk/*

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install app dependencies (use npm install instead of npm ci)
RUN npm install --only=production --no-audit --no-fund

# Copy app source  
COPY backend.js ./
COPY public ./public/
COPY run.sh ./

# Force rebuild of run.sh layer
RUN echo "Rebuild for run.sh v1.1.0"

# Create data directory for persistent storage
RUN mkdir -p /data

# Make run script executable
RUN chmod a+x run.sh

# Labels for Home Assistant
LABEL \
    io.hass.name="Family Chore Tracker" \
    io.hass.description="Family chore management with points system" \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.type="addon" \
    io.hass.version="${BUILD_VERSION}" \
    maintainer="Tadej <tadej@example.com>" \
    org.opencontainers.image.title="Family Chore Tracker" \
    org.opencontainers.image.description="A comprehensive family chore management system" \
    org.opencontainers.image.vendor="Home Assistant Add-ons" \
    org.opencontainers.image.authors="Tadej" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.url="https://github.com/TadejBartol/ha-family-chore-tracker" \
    org.opencontainers.image.source="https://github.com/TadejBartol/ha-family-chore-tracker" \
    org.opencontainers.image.documentation="https://github.com/TadejBartol/ha-family-chore-tracker/blob/main/README.md" \
    org.opencontainers.image.created=${BUILD_DATE} \
    org.opencontainers.image.revision=${BUILD_REF} \
    org.opencontainers.image.version=${BUILD_VERSION}

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Run the app
CMD ["./run.sh"] 