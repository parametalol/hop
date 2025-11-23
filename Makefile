.PHONY: all clean

all: hop

hop:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o hop .

container:
	podman build -v "${PWD}":/build --security-opt label=disable -t hop:local .

clean:
	rm -f hop
