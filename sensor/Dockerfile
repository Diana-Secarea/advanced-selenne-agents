# selenne-sensor: one static binary on a distroless base, running as nonroot.
# It only reads Tetragon's export file and posts to ingest — the privileged
# part is the Tetragon container next to it (docker-compose.yml).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/selenne-sensor ./cmd/selenne-sensor \
 && mkdir -p /out/state /out/policies

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/selenne-sensor /usr/local/bin/selenne-sensor
# owned by nonroot so named volumes mounted here start writable
COPY --from=build --chown=65532:65532 /out/state /var/lib/selenne-sensor
COPY --from=build --chown=65532:65532 /out/policies /policies
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/selenne-sensor"]
CMD ["run"]
