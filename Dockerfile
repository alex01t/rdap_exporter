# Build stage
FROM golang:1.24.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o rdap_exporter .

# Final image
FROM gcr.io/distroless/static-debian12
COPY --from=build /src/rdap_exporter /rdap_exporter
EXPOSE 9099
ENTRYPOINT ["/rdap_exporter"]
