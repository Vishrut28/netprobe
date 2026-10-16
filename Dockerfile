FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /netprobe ./cmd/netprobe

FROM gcr.io/distroless/static:nonroot
COPY --from=build /netprobe /netprobe
COPY targets.example.json /etc/netprobe/targets.json
EXPOSE 9115
USER nonroot
ENTRYPOINT ["/netprobe"]
CMD ["serve", "-config", "/etc/netprobe/targets.json", "-listen", ":9115"]
