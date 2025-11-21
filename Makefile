.PHONY: all clean

all: hop

hop:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o hop ./main

clean:
	rm -f hop
