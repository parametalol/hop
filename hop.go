package main

import (
    "context"
    "fmt"
    "io"
    "io/ioutil"
    "math/rand"
    "net"
    "net/http"
    "net/url"
    "os"
    "strconv"
    "strings"
    "time"
)

type hopHandler struct {}

var help = "-wait:[ms], -headers, -size:[bytes]"
var quit = make(chan int)

func callURL(url string, headers map[string]string, r []string) (*http.Response, error) {
    req, err := http.NewRequest("GET", url, nil)
    if err != nil || req == nil {
        return nil, err
    }
    for h, v := range headers {
        req.Header.Set(h, v)
    }
    client := &http.Client{ }
    return client.Do(req)
}

func (handler hopHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {

    var result [1]string

    hn, _ := os.Hostname()
    path := req.URL.Path
    if len(req.URL.RawPath) > 0 {
        path = req.URL.RawPath
    }
    result[0] = fmt.Sprintf("I am %s, will do %s", hn, path)
    r := result[:]

    split := strings.SplitN(path, "/", 3)
    next_cmd := path
    if len(split) > 1 {
        next_cmd = split[1]
    }
    path = ""
    if len(split) > 2 {
        path = split[2]
    }

    var headers = map[string]string {
        "Content-type": "text/plain",
    }
    var rheaders = map[string]string {
        "Content-type": "text/plain",
    }
    var fheaders []string

    showHeaders := false
    skip := false
    code := 0

    q := func (c int) {
        quit <- c
    }

    for strings.HasPrefix(next_cmd, "-") {
        cmd := strings.SplitN(next_cmd, ":", 2)

        split := strings.SplitN(path, "/", 2)
        if len(split) > 0 {
            next_cmd = split[0]
        } else {
            next_cmd = ""
        }
        if len(split) > 1 {
            path = split[1]
        } else {
            path = ""
        }

        if skip {
            r = append(r, fmt.Sprintf("Skipping %s", cmd[0]))
            skip = false
            continue
        }

        switch cmd[0] {
        case "-wait":
            if len(cmd) != 2 {
                r = append(r, fmt.Sprintf("Missing parameter for %s", cmd[0]))
                continue
            }
            d, err := strconv.Atoi(cmd[1])
            if err != nil {
                r = append(r, fmt.Sprintf("Cannot wait for %s ms", cmd[1]))
                continue
            }
            time.Sleep(time.Duration(d) * time.Millisecond)
            r = append(r, fmt.Sprintf("Waited for %d ms", d))
        case "-headers":
            showHeaders = true
            r = append(r, "Got headers:")
            for h, v := range req.Header {
                r = append(r, fmt.Sprintf(".\t%s: %s", h, v))
            }
        case "-header":
            if len(cmd) != 2 {
                r = append(r, fmt.Sprintf("Missing parameter for %s", cmd[0]))
                continue
            }
            hv := strings.SplitN(cmd[1], "=", 2)
            if len(hv) != 2 {
                r = append(r, fmt.Sprintf("Missing header value for %s", cmd[0]))
                continue
            }
            value, err := url.PathUnescape(hv[1])
            if err != nil {
                r = append(r, fmt.Sprintf("Bad value for header %s: %s", hv[0], hv[1]))
            } else {
                r = append(r, fmt.Sprintf("Will add header %s: %s", hv[0], value))
                headers[hv[0]] = value
            }
        case "-rheader":
            if len(cmd) != 2 {
                r = append(r, fmt.Sprintf("Missing parameter for %s", cmd[0]))
                continue
            }
            hv := strings.SplitN(cmd[1], "=", 2)
            if len(hv) != 2 {
                r = append(r, fmt.Sprintf("Missing header value for %s", cmd[0]))
                continue
            }
            value, err := url.PathUnescape(hv[1])
            if err != nil {
                r = append(r, fmt.Sprintf("Bad value for header %s: %s", hv[0], hv[1]))
            } else {
                r = append(r, fmt.Sprintf("Will return header %s: %s", hv[0], value))
                rheaders[hv[0]] = value
            }
        case "-fheader":
            if len(cmd) != 2 {
                r = append(r, fmt.Sprintf("Missing parameter for %s", cmd[0]))
                continue
            }
            r = append(r, fmt.Sprintf("Will forward header %s: %s", cmd[1], req.Header.Get(cmd[1])))
            headers[cmd[1]] = req.Header.Get(cmd[1])
            fheaders = append(fheaders, cmd[1])
        case "-code":
            if len(cmd) != 2 {
                r = append(r, fmt.Sprintf("Missing parameter for %s", cmd[0]))
                continue
            }
            c, err := strconv.Atoi(cmd[1])
            if err != nil {
                r = append(r, fmt.Sprintf("Cannot return code %s", cmd[1]))
                continue
            }
            code = c
            r = append(r, fmt.Sprintf("Returning code %d", code))
        case "-size":
            if len(cmd) != 2 {
                r = append(r, fmt.Sprintf("Missing parameter for %s", cmd[0]))
                continue
            }
            b, err := strconv.Atoi(cmd[1])
            if err != nil {
                r = append(r, fmt.Sprintf("Cannot create a byte array of %s bytes", cmd[1]))
                continue
            }
            r = append(r, fmt.Sprintf("Appending %d bytes", b))
            r = append(r, strings.Repeat("X", b))
            r = append(r, "\n")
        case "-rnd":
            if len(cmd) != 2 {
                r = append(r, fmt.Sprintf("Missing parameter for %s", cmd[0]))
                continue
            }
            p, err := strconv.Atoi(cmd[1])
            if err != nil {
                r = append(r, fmt.Sprintf("Cannot make a random of %s", cmd[1]))
                continue
            }
            if rand.Intn(100) < p {
                skip = true
                continue
            }
        case "-quit":
            r = append(r, "Quitting")
            defer q(1)
        case "-crash":
            defer q(2)
        }
    }

    if skip {
        r = append(r, fmt.Sprintf("Skipping call to %s", next_cmd))
    } else if len(next_cmd) > 0 {
        url := fmt.Sprintf("http://%s/%s", next_cmd, path)
        res, err := callURL(url, headers, r)
        if err != nil {
            r = append(r, fmt.Sprintf("Couldn't call %s. Got error: %s\n", url, err.Error()))
        } else if res == nil {
            r = append(r, fmt.Sprintf("Couldn't call %s by some reason\n", url))
        }
        if res != nil {
            r = append(r, fmt.Sprintf("Called %s with status %s", url, res.Status))
            if code == 0 {
                code = res.StatusCode
            }
            if res.Body != nil {
                data, err := ioutil.ReadAll(res.Body)
                res.Body.Close()
                if err != nil {
                    r = append(r, err.Error())
                    r = append(r, "\n")
                } else {
                    r = append(r, "With data:")
                    for _, line := range strings.Split(string(data), "\n") {
                        r = append(r, fmt.Sprintf(".\t%s", line))
                    }
                }
            }
            for _, h := range fheaders {
                v := res.Header.Get(h)
                r = append(r, fmt.Sprintf("Back forwarding header %s: %s", h, v))
                if len(v) > 0 {
                    rheaders[h] = v
                }
            }
            if showHeaders {
                r = append(r, "With headers:")
                for h, v := range res.Header {
                    r = append(r, fmt.Sprintf(".\t%s: %s", h, v))
                }
            }
        }
        if code == 0 && err != nil {
            code = 500
        }
    }

    for h, v := range rheaders {
        w.Header().Set(h, v)
    }
    if code == 0 {
        code = 200
    }
    w.WriteHeader(code)
    for _, line := range r {
        io.WriteString(w, "| ")
        io.WriteString(w, line)
        io.WriteString(w, "\n")
    }
}


func main() {
    rand.Seed(13)
    port := os.Getenv("PORT");
    if len(port) == 0 {
        port = "8000"
    }
    fmt.Println("Serving on", port)

    s := &http.Server {
        Addr: net.JoinHostPort("", port),
        Handler: hopHandler {},
        ReadTimeout: 10 * time.Second,
        WriteTimeout: 10 * time.Second,
        MaxHeaderBytes: 1 << 20,
    }

    go func() {
        fmt.Println(s.ListenAndServe())
        close(quit)
    }()

    switch <-quit {
    case 1:
        fmt.Println("Shutting down")
        err := s.Shutdown(context.Background());
        <-quit
        if err != nil {
            panic(err)
        }
    case 2:
        panic("Rabbits are coming!")
    }
    fmt.Println("Exiting normally")
}

