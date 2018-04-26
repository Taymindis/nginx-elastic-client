# vi:filetype=perl

use lib 'inc';
use lib 'lib';
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


=== TEST 2: create index by id 100
--- http_config eval: $::http_config
--- config
    location /test {
        elastic_pass http://elastic_upstream;
        elastic_send PUT /testindex/testdoc/100;
        elastic_query '{
            "testname": "mytest"            
        }';
    }
--- request
GET /test
--- error_code: 201
--- timeout: 10
--- response_headers
Content-Type: application/json; charset=UTF-8



=== TEST 3: create index by arg id
--- http_config eval: $::http_config
--- config
    location /test {
        elastic_pass http://elastic_upstream;
        elastic_send PUT /testindex/testdoc/$arg_new_id;
        elastic_query '{
            "testname": "mytest-$arg_new_id"            
        }';
    }
--- request
GET /test?new_id=300
--- error_code: 201
--- timeout: 10
--- response_headers
Content-Type: application/json; charset=UTF-8