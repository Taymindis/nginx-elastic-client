# vi:filetype=perl

use lib '/home/dispatch/testMap/c-lib/test-nginx/inc';
use lib '/home/dispatch/testMap/c-lib/test-nginx/lib';
use Test::Nginx::Socket 'no_plan';


$ENV{TEST_NGINX_ELASTIC_HOST} ||= '10.2.140.88';
$ENV{TEST_NGINX_ELASTIC_PORT} ||= 9200;

our $http_config = <<'_EOC_';
    upstream elastic_upstream {
        server     $TEST_NGINX_ELASTIC_HOST:$TEST_NGINX_ELASTIC_PORT;
        keepalive  1;
    }
_EOC_

no_shuffle();
run_tests();

#no_diff();

__DATA__



=== TEST 4: search all
--- http_config eval: $::http_config
--- config
    location /test {
        elastic_pass http://elastic_upstream;
        elastic_send POST /testindex/testdoc/_search/;
        elastic_query '{"query":
           {
            "match_all": {}
           }
        }';
    }
--- request
GET /test
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: application/json; charset=UTF-8
--- response_body_like eval chomp
qr/.*?\"_source\":.*/



=== TEST 5: search all but skipmeta data
--- http_config eval: $::http_config
--- config
    location /test {
        elastic_pass http://elastic_upstream;
        elastic_send POST /testindex/testdoc/_search skipmeta;
        
        elastic_query '{"query":
           {
            "match_all": {}
           }
        }';
    }
--- request
GET /test
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: application/json; charset=UTF-8
--- response_body_like eval chomp
qr/.*?\"_source\":.*/




=== TEST 6: search all but source only data
--- http_config eval: $::http_config
--- config
    location /test {
        elastic_pass http://elastic_upstream;
        elastic_send POST /testindex/testdoc/_search source;
        
        elastic_query '{"query":
           {
            "match_all": {}
           }
        }';
    }
--- request
GET /test
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: application/json; charset=UTF-8
--- response_body_like eval chomp
qr/.*?\"_source\":.*/



=== TEST 7: search with dynamic input
--- http_config eval: $::http_config
--- config
    location /test {
        elastic_pass http://elastic_upstream;
        elastic_send POST /testindex/testdoc/_search;
        elastic_query $request_body;
    }
--- request
POST /test
{"query":{"match_all": {}}}
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: application/json; charset=UTF-8
--- response_body_like eval chomp
qr/.*?\"_source\":.*/



=== TEST 8: search with dynamic input 2
--- http_config eval: $::http_config
--- config
    location /test {
        elastic_pass http://elastic_upstream;
        elastic_send POST /testindex/testdoc/_search;
        elastic_query '{"query": {"match" : {"$arg_field" : "$arg_value"}}}';
    }
--- request
GET /test?field=testname&value=mytest
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: application/json; charset=UTF-8
--- response_body_like eval chomp
qr/.*?\"_source\":.*/