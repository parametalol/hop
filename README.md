# hop

A flexible HTTP proxy service that accepts configuration through URL paths. Perfect for testing, development, and debugging distributed systems.

## What is hop?

hop is an HTTP proxy that can be controlled entirely through URLs. Instead of configuration files or command-line flags for each request, you embed options directly in the URL path. This makes it ideal for:

- Testing HTTP clients and network behavior
- Simulating various server responses and conditions
- Debugging distributed systems
- Creating reproducible test scenarios
- Chain-proxying with different configurations per hop

## Quick Start

### Running the server

```console
# Using Go
go run .

# Or build and run
go build -o hop .
./hop --port-http 8080 --port-https 8443
```

### Basic usage

The general URL pattern is:

```text
http://hop-server/[options]/target-url
```

Options start with `-` and appear before the target URL. The slashes in the options might need to be URL-escaped as `%2f`.

For example:

```console
# Simple proxy request
curl http://localhost:8080/https:%2f%2fapi.example.com/users

# Or
./hop http://localhost:8080/https://api.example.com/users

# With custom method
curl http://localhost:8080/-method=POST/https:%2f%2fapi.example.com/users

# Forward headers from incoming request to target
curl -H "Authorization: Bearer token" \
  http://localhost:8080/-forward-headers=Authorization/https:%2f%2fapi.example.com/users

# Multiple options
curl http://localhost:8080/-method=POST/-headers=Content-Type:application%2fjson%2fhttps:%2f%2fapi.example.com/users
```

## Discovering Options

hop supports many options for controlling requests and responses. To see all available options:

1. **Check the source code**: All options are defined in [options/options.go](options/options.go) in the `supportedOptions` map
2. **Look at the tests**: The [options/options_test.go](options/options_test.go), [parser/parser_test.go](parser/parser_test.go), and [client/client_test.go](client/client_test.go) files contain numerous examples
3. **Examine the constants**: Client and server options are defined as constants in [options/options.go](options/options.go)

Each option has both a long form (`-option-name`) and a short form (`-X`). For example:

- `-method=POST` or `-X=POST` for HTTP method
- `-headers=...` or `-H=...` for custom headers
- `-forward-headers=...` or `-FH=...` for forwarding headers
- `-insecure` or `-k` for skipping TLS verification

## Option Categories

Options fall into two main categories:

**Client options**: Control outgoing requests to the target

- HTTP method, headers, body
- Timeouts and TLS settings
- Header forwarding
- Redirect behavior

**Server options**: Control hop's response to the caller

- Response status code and headers
- Delays and error simulation
- Process control (panic, exit)

## Build

### Using Go

```console
go build -o hop .
```

### Using Podman/Docker

```console
podman build -t hop:local .
podman run --rm -p 8080:8080 hop:local
```

## Examples

### Forward authentication headers

```console
curl -H "Authorization: Bearer token123" \
  http://localhost:8080/-forward-header=Authorization/https://api.example.com/protected
```

### POST with custom headers

```console
curl http://localhost:8080/-method=POST/-headers=Content-Type:application/json/-body='{"key":"value"}'/https://api.example.com/data
```

### Skip TLS verification

```console
curl http://localhost:8080/-insecure/https://self-signed.example.com/api
```

### Custom timeout

```console
curl http://localhost:8080/-timeout=5/https://slow-api.example.com/endpoint
```

### Chain proxying

```console
# hop1 forwards to hop2, which forwards to the final destination
curl http://hop1:8080/-forward-header=X-Request-ID/http://hop2:8080/-method=POST/https://api.example.com/users
```

## Testing

```console
# Run all tests
go test ./...

# Run specific package tests
go test -v ./options
go test -v ./parser
go test -v ./client
```

## License

See LICENSE file for details.
