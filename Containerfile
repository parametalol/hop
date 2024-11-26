FROM go:1.22 as builder

ENV CGO_ENABLED=0
ENV GOOS=linux
RUN go build -a -installsuffix cgo -o hop .

FROM scratch

COPY --from=builder hop /
CMD ["/hop"]
