FROM golang:1.23 AS builder

ENV CGO_ENABLED=0
ENV GOOS=linux
WORKDIR /build
RUN --mount=type=bind,target=/build go build -a -o /hop ./main

FROM scratch

ENV PORT=8080
ENV PORT_HTTPS=8443
EXPOSE ${PORT}
EXPOSE ${PORT_HTTPS}
COPY --from=builder /hop /
ENTRYPOINT [ "/hop"]
