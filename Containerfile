FROM golang:1.25 AS builder

ENV CGO_ENABLED=0 GOOS=linux
WORKDIR /build
RUN --mount=type=bind,target=/build go build -a -o /hop .

FROM scratch

ENV PORT=8080 PORT_HTTPS=8443
EXPOSE ${PORT} ${PORT_HTTPS}
COPY --from=builder /hop /
ENTRYPOINT [ "/hop"]
