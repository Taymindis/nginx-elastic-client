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

=== TEST 1: test elastic connection
--- http_config eval: $::http_config
--- config
    location /test {
        elastic_pass http://elastic_upstream;
        elastic_send GET /;
    }
--- request
GET /test
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: application/json; charset=UTF-8