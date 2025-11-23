.PHONY: all clean

all: hop

hop:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o hop .

clean:
	rm -f hop
