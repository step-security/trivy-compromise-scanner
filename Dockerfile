# Stage 1: Go base (matches go.mod)
FROM golang:1.25 AS base

# Stage 2: Build the binary
FROM base AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o trivy-compromise-scanner .

# Stage 3: Minimal runtime
FROM alpine:3.20 AS runtime
WORKDIR /workspace
COPY --from=builder /app/trivy-compromise-scanner /usr/local/bin/trivy-compromise-scanner
ENTRYPOINT ["/usr/local/bin/trivy-compromise-scanner"]
