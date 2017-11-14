# hop

A stupid web service which can do stupid things told by the url.

# Usage

    * $ hop --help

    * $ PORT=8000 hop
      Serving on 8000

    * $ curl box1:8000/-wait:1000/box2:8000/-rheader:a=b

      | I am box, will do /-wait:1000/box2:8000/-rheader:a=b
      | Waited for 1000 ms
      | Called http://box2:8000/-rheader:a=b with status 200 OK
      | With data:
      | . | I am box2, will do /-rheader:a=b
      | . | Will return header a: b
      | . 

# Supported commands

    * $ curl hop/-help

* -info         - return some info about the request
* -rheader:H=V  - add header H: V to the reponse
* -code:N       - responde with HTTP code N
* -help         - return help message
* -if:H=V       - execute next command if header H contains substring V
* -on:H         - executes next command if the server host name contains substring H
* -quit         - stops the server with a nice response
* -size:B       - add B bytes of payload to the response
* -not          - reverts the effect of the next boolean command (if, on)
* -rnd:P        - execute next command with P% probability
* -wait:T       - wait for T ms before response
* -crash        - stops the server without a response
* -fheader:H    - forward incoming header H to the following request
* -header:H=V   - add header H: V to the following request
* -env:V        - return the value of an environment variable

# Examples:

Call hop1 which will show some details of the request

    curl -H "a: b" hop1/-info
    
Call hop1 which will call hop2 with forwarded header A

    curl -H "a: b" hop1/-fheader:a/hop2

Call hop1 which will call hop2 or hop3 (50%). hop2 would call hop3 and return error code 500

    curl hop1/-rnd:50/hop2/hop3/-on:hop2/-code:500

