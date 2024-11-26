FROM golang:1.23 as builder

# podman build -v $PWD:/build --security-opt label=disabled -t hop:latest .
ENV CGO_ENABLED=0
ENV GOOS=linux
WORKDIR /build
RUN go build -a -installsuffix cgo -o /hop ./main

FROM scratch

ENV PORT=8080
ENV PORT_HTTPS=8443
COPY --from=builder /hop /
ENTRYPOINT [ "/hop"]
