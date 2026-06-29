# =========================================================================
# STAGE 1: Extract Core Static Tools & Certificates
# =========================================================================
# Grab your custom static tools image first
FROM ghcr.io/amf3/just_enough/busybox:latest AS tools

# =========================================================================
# STAGE 2: The Distroless Compilation Pipeline Layer
# =========================================================================
FROM ghcr.io/amf3/just_enough/python3.14:latest AS builder

WORKDIR /build

# 1. Bring in the independent static busybox binary
COPY --from=tools /bin/busybox /bin/busybox

# 2. Bring in the verified system root certificates from the certs cache layer
COPY --from=tools /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_DIR=/etc/ssl/certs

# Execute directory mapping utilizing EXEC form directly 
# This will now succeed because your busybox binary is statically linked!
RUN ["/bin/busybox", "mkdir", "-p", "src", "configs", "dist"]

# Copy tracking requirements to execute the package installation loop
COPY requirements.txt .

# Direct pipeline dependency resolution using kernel EXEC allocation
RUN ["python", "-m", "pip", "install", "--no-cache-dir", "-r", "requirements.txt"]

# Copy application code logic and target specifications
COPY src/ ./src/
COPY configs/ ./configs/
ENV PYTHONPATH=/build

# Fire the compiler toolchain directly using execution brackets
RUN ["python", "-m","src.main"]

# =========================================================================
# STAGE 3: The Production Immutable Unbound DNS Runtime
# =========================================================================
FROM ghcr.io/amf3/just_enough/unbound_dns:latest AS runner

WORKDIR /etc/unbound

# Extract the static configuration assets generated from the shell-less builder stage
COPY --from=builder /build/dist/unbound.conf ./unbound.conf
COPY --from=builder /build/dist/local_records.conf ./local_records.conf
COPY --from=builder /build/dist/adblock.conf ./adblock.conf

# Expose target networking layers
EXPOSE 53/udp
EXPOSE 53/tcp
