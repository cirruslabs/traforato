# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:latest AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/traforato-controller ./cmd/controller

FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="traforato"
LABEL org.opencontainers.image.description="Traforato controller runtime image"
LABEL org.opencontainers.image.version=$VERSION
LABEL org.opencontainers.image.revision=$VCS_REF

COPY --from=builder /out/traforato-controller /usr/local/bin/traforato-controller

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/traforato-controller"]
