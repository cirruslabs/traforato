# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:latest AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/traforato-broker ./cmd/broker

FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="traforato"
LABEL org.opencontainers.image.description="Traforato broker runtime image"
LABEL org.opencontainers.image.version=$VERSION
LABEL org.opencontainers.image.revision=$VCS_REF

COPY --from=builder /out/traforato-broker /usr/local/bin/traforato-broker

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/traforato-broker"]
