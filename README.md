nginx-elastic-client
====================

To structure your elastic client command in your nginx proxy for multiple elasticsearch server.

Table of Contents
=================

* [Introduction](#introduction)
* [Usage](#usage)
* [Installation](#installation)
* [Sample Application Development](#sample-application-development)
* [Test](#test)
* [Support](#support)
* [Copyright & License](#copyright--license)

Introduction
============

nginx-elastic-client is a nginx module which allow to proxy to elastic server with given pre-defined/dynamic command.


Usage
=======
### 1. Setup your elastic upstream
```nginx
# nginx.conf
  upstream elastic_upstream {
     server 127.0.0.1:9200;
  }
```

### 2. Simple create index command, please noted that http method is defined inside command, it regardless what you called to nginx.
```nginx
# nginx.conf

server {
    ....
   location /test {
        elastic_pass http://elastic_upstream;
        elastic_send PUT /testindex/testdoc/100;
        elastic_query '{
            "testname": "mytest"            
        }';
    }
}
```

### 3. Create index based on your args, for example /test?new_id=Staff1232
```nginx
# nginx.conf

server {
    ....
   location /test {
        elastic_pass http://elastic_upstream;
        elastic_send PUT /testindex/testdoc/$arg_new_id;
        elastic_query '{
            "testname": "mytest-$arg_new_id"            
        }';
    }
}
```


### 4. search all
```nginx
# nginx.conf

server {
    ....
   location /test {
        elastic_pass http://elastic_upstream;
        elastic_send POST /testindex/testdoc/_search/;
        elastic_query '{"query":
           {
            "match_all": {}
           }
        }';
    }
}
```


### 5. search all but skipmeta data, keep index, type, and id.
```nginx
# nginx.conf

server {
    ....
     location /test {
        elastic_pass http://elastic_upstream;
        elastic_send POST /testindex/testdoc/_search skipmeta;
        
        elastic_query '{"query":
           {
            "match_all": {}
           }
        }';
    }
}
```


### 6. search all but source only data.
```nginx
# nginx.conf

server {
    ....
     location /test {
        elastic_pass http://elastic_upstream;
        elastic_send POST /testindex/testdoc/_search source;
        
        elastic_query '{"query":
           {
            "match_all": {}
           }
        }';
    }
}
```


### 7. search with dynamic input.
```nginx
# nginx.conf

server {
    ....
    location /test {
        elastic_pass http://elastic_upstream;
        elastic_send POST /testindex/testdoc/_search;
        elastic_query $request_body;
    }

    location /test2 {
        elastic_pass http://elastic_upstream;
        elastic_send POST /testindex/testdoc/_search;
        elastic_query '{"query": {"match" : {"$arg_field" : "$arg_value"}}}';
    }
}
```


### 7. Delete index.
```nginx
# nginx.conf

server {
    ....
    location /test {
        elastic_pass http://elastic_upstream;
        elastic_send DELETE /testindex/;
    }
}
```



Installation
============

```bash
wget 'http://nginx.org/download/nginx-1.13.7.tar.gz'
tar -xzvf nginx-1.13.7.tar.gz
cd nginx-1.13.7/

./configure --add-module=/path/to/nginx-elastic-client

make -j2
sudo make install
```

[Back to TOC](#table-of-contents)


Test
=====

It depends on nginx test suite libs, please refer [test-nginx](https://github.com/openresty/test-nginx) for installation.


```bash
cd /path/to/nginx-elastic-client
export PATH=/path/to/nginx-dirname:$PATH 
sudo TEST_NGINX_SLEEP=0.3 prove t
```

[Back to TOC](#table-of-contents)

Support
=======

Please do not hesitate to contact minikawoon2017@gmail.com for any queries or development improvement.


[Back to TOC](#table-of-contents)

Copyright & License
===================

Copyright (c) 2018, Taymindis <cloudleware2015@gmail.com>

This module is licensed under the terms of the BSD license.

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)
