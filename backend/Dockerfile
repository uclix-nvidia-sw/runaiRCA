FROM golang:1.22-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 go build -o /out/runai-rca-backend .

FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=build /out/runai-rca-backend /runai-rca-backend

EXPOSE 8080

ENTRYPOINT ["/runai-rca-backend"]
