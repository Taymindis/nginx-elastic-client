/**
* @file   ngx_http_elastic_client_module.c
* @author taymindis <cloudleware2015@gmail.com>
* @date   Sun JAN 28 12:06:52 2018
*
* @brief  A nginx-elastic-client module for Nginx.
*
* @section LICENSE
*
* Copyright (c) 2018, Taymindis <cloudleware2015@gmail.com>
*
* This module is licensed under the terms of the BSD license.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice, this
*    list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*** this module depends on ngx_http_proxy_module ****/
extern ngx_module_t  ngx_http_proxy_module;

#define A_SKIP_METADATA "&filter_path=hits.total,hits.hits._index,hits.hits._type,hits.hits._source"
#define Q_SKIP_METADATA "?filter_path=hits.total,hits.hits._index,hits.hits._type,hits.hits._source"
#define SKIP_METADATA_LEN 74

#define A_SOURCE_ONLY "&filter_path=hits.total,hits.hits._source"
#define Q_SOURCE_ONLY "?filter_path=hits.total,hits.hits._source"
#define SOURCE_ONLY_LEN 41

#define A_INDEX_DOCLIST "&filter_path=hits.hits._index,hits.hits._source&sort=_index:asc"
#define Q_INDEX_DOCLIST "?filter_path=hits.hits._index,hits.hits._source&sort=_index:asc"
#define INDEX_DOCLIST_LEN 63

#define CLEAN_BUF(b)                    \
    cl->buf->pos = cl->buf->start;      \
    cl->buf->last = cl->buf->start;     \
    cl->buf->flush = 1;                 \
    cl->buf->temporary = 0;             \
    cl->buf->memory = 0;

#define CLEAR_BUF(b)                      \
    cl->buf->pos = cl->buf->last;

typedef struct {
    ngx_http_complex_value_t   *req_method;
    ngx_http_complex_value_t   *index_n_path;
    ngx_uint_t                  resp_opt;
} ngx_http_elastic_client_loc_conf_t;

typedef struct {
    ngx_chain_t             *free;
    ngx_chain_t             *busy;
    off_t                   length;
    ngx_buf_t               *saved_buf;
} ngx_http_elastic_client_ctx_t;

static ngx_int_t ngx_http_elastic_client_init(ngx_conf_t *cf);
static void *ngx_http_elastic_client_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_elastic_client_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_conf_elastic_client_set_path_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_elastic_client_set_query_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_elastic_client_set_enum_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, ngx_uint_t varargs);
static char *ngx_conf_elastic_client_proxy_pass_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_elastic_client_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_elastic_client_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_elastic_client_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

#define NGX_HTTP_ELASTIC_CLIENT_SKIPMETA_RESP 905
#define NGX_HTTP_ELASTIC_CLIENT_SOURCEONLY_RESP 906
#define NGX_HTTP_ELASTIC_CLIENT_INDEXDOCLIST_RESP 907
#define NGX_HTTP_ELASTIC_CLIENT_RESP_OPT_OFF 0

static ngx_flag_t index_docs_enabled = 0;
#define FIRST_INDEX "[{\"_index\":\""
#define SIZEOF_FIRSTINDEX 12
#define FOLLOW_INDEX ",{\"_index\":\""
#define SIZEOF_FOLLOWINDEX 12
#define _SOURCE ",\"_source\":"
#define SIZEOF_SOURCE 11

#define ARRAY_BRACKET_OPEN "["
#define ARRAY_BRACKET_CLOSED "]"
#define OBJ_BRACKET_OPEN "{"
#define OBJ_BRACKET_CLOSED "}"
#define COMMA ","
#define DOUBLE_QUOTE "\""
#define DOUBLE_QUOTE_COLON "\":"
#define COLON ":"


void *ngx_elasic_client_index_realloc(ngx_http_request_t *r,  void *ptr, size_t old_length, size_t new_length)
{
    void *ptrNew = ngx_palloc(r->pool, new_length);
    if (ptrNew) {
        memcpy(ptrNew, ptr, old_length);
        ngx_pfree(r->pool, ptr); // free with pool
    }
    return ptrNew;
}

#define is_index_existed(__index_buckets__, __index_size__, __index__, __index_len__) ({\
size_t z, existed=0;\
ngx_str_t *index_val = &__index_buckets__[0];\
for(z=0;z<__index_size__;z++,index_val++){\
if(index_val->len == __index_len__ && ngx_strncmp(__index__, index_val->data, __index_len__)==0){\
    existed=1; break;\
}}\
existed;})

static ngx_conf_enum_t ngx_http_elastic_client_resp_opt[] = {
    { ngx_string("skipmeta"), NGX_HTTP_ELASTIC_CLIENT_SKIPMETA_RESP },
    { ngx_string("source"), NGX_HTTP_ELASTIC_CLIENT_SOURCEONLY_RESP },
    { ngx_string("index_docs"), NGX_HTTP_ELASTIC_CLIENT_INDEXDOCLIST_RESP },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_elastic_client_commands[] = {

    {   ngx_string("elastic_pass"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
        ngx_conf_elastic_client_proxy_pass_command,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    {   ngx_string("elastic_send"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE23,
        ngx_conf_elastic_client_set_path_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_elastic_client_loc_conf_t, resp_opt),
        ngx_http_elastic_client_resp_opt
    },

    {   ngx_string("elastic_query"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
        ngx_conf_elastic_client_set_query_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_elastic_client_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_elastic_client_init,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_elastic_client_create_loc_conf,    /* create location configuration */
    ngx_http_elastic_client_merge_loc_conf      /* merge location configuration */
};

ngx_module_t  ngx_http_elastic_client_module = {
    NGX_MODULE_V1,
    &ngx_http_elastic_client_module_ctx,        /* module context */
    ngx_http_elastic_client_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_elastic_client_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_elastic_client_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_elastic_client_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->req_method = NGX_CONF_UNSET_PTR;
    conf->index_n_path = NGX_CONF_UNSET_PTR;
    conf->resp_opt = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_http_elastic_client_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_elastic_client_loc_conf_t *prev = parent;
    ngx_http_elastic_client_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->index_n_path, prev->index_n_path, NULL);
    ngx_conf_merge_ptr_value(conf->req_method, prev->req_method, NULL);
    ngx_conf_merge_uint_value(conf->resp_opt, prev->resp_opt, NGX_HTTP_ELASTIC_CLIENT_RESP_OPT_OFF);


    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_elastic_client_access_handler(ngx_http_request_t *r)
{
    ngx_http_elastic_client_loc_conf_t  *eclcf;
    ngx_str_t                           http_method;
    ngx_str_t                           index_path;
    u_char                              *p/*, *target_opt*/;
    size_t                              len/*, target_opt_len*/;


    eclcf = ngx_http_get_module_loc_conf(r, ngx_http_elastic_client_module);

    if (eclcf->index_n_path) {
        if (ngx_http_complex_value(r, eclcf->req_method, &http_method) != NGX_OK ||
                ngx_http_complex_value(r, eclcf->index_n_path, &index_path) != NGX_OK) {
            return NGX_ERROR;
        }

        // if (eclcf->resp_opt == NGX_HTTP_ELASTIC_CLIENT_SKIPMETA_RESP) {
        //     if (ngx_strchr(index_path.data, '?')) {
        //         len = index_path.len + SKIP_METADATA_LEN;
        //         p = r->unparsed_uri.data = ngx_palloc(r->pool, len);
        //         p = ngx_copy(p, index_path.data, index_path.len);
        //         p = ngx_copy(p, A_SKIP_METADATA, SKIP_METADATA_LEN);
        //         r->unparsed_uri.len = len;
        //     } else {
        //         len = index_path.len + SKIP_METADATA_LEN;
        //         p = r->unparsed_uri.data = ngx_palloc(r->pool, len);
        //         p = ngx_copy(p, index_path.data, index_path.len);
        //         p = ngx_copy(p, Q_SKIP_METADATA, SKIP_METADATA_LEN);
        //         r->unparsed_uri.len = len;
        //     }
        // } else if (eclcf->resp_opt == NGX_HTTP_ELASTIC_CLIENT_SOURCEONLY_RESP) {
        //     if (ngx_strchr(index_path.data, '?')) {
        //         len = index_path.len + SOURCE_ONLY_LEN;
        //         p = r->unparsed_uri.data = ngx_palloc(r->pool, len);
        //         p = ngx_copy(p, index_path.data, index_path.len);
        //         p = ngx_copy(p, A_SOURCE_ONLY, SOURCE_ONLY_LEN);
        //         r->unparsed_uri.len = len;
        //     } else {
        //         len = index_path.len + SOURCE_ONLY_LEN;
        //         p = r->unparsed_uri.data = ngx_palloc(r->pool, len);
        //         p = ngx_copy(p, index_path.data, index_path.len);
        //         p = ngx_copy(p, Q_SOURCE_ONLY, SOURCE_ONLY_LEN);
        //         r->unparsed_uri.len = len;
        //     }
        // } else {
        //     r->unparsed_uri = index_path;
        // }

        switch (eclcf->resp_opt) {
        case NGX_HTTP_ELASTIC_CLIENT_SKIPMETA_RESP:
            if (ngx_strchr(index_path.data, '?')) {
                len = index_path.len + SKIP_METADATA_LEN;
                p = r->unparsed_uri.data = ngx_palloc(r->pool, len);
                p = ngx_copy(p, index_path.data, index_path.len);
                p = ngx_copy(p, A_SKIP_METADATA, SKIP_METADATA_LEN);
                r->unparsed_uri.len = len;
            } else {
                len = index_path.len + SKIP_METADATA_LEN;
                p = r->unparsed_uri.data = ngx_palloc(r->pool, len);
                p = ngx_copy(p, index_path.data, index_path.len);
                p = ngx_copy(p, Q_SKIP_METADATA, SKIP_METADATA_LEN);
                r->unparsed_uri.len = len;
            }
            break;
        case NGX_HTTP_ELASTIC_CLIENT_SOURCEONLY_RESP:
            if (ngx_strchr(index_path.data, '?')) {
                len = index_path.len + SOURCE_ONLY_LEN;
                p = r->unparsed_uri.data = ngx_palloc(r->pool, len);
                p = ngx_copy(p, index_path.data, index_path.len);
                p = ngx_copy(p, A_SOURCE_ONLY, SOURCE_ONLY_LEN);
                r->unparsed_uri.len = len;
            } else {
                len = index_path.len + SOURCE_ONLY_LEN;
                p = r->unparsed_uri.data = ngx_palloc(r->pool, len);
                p = ngx_copy(p, index_path.data, index_path.len);
                p = ngx_copy(p, Q_SOURCE_ONLY, SOURCE_ONLY_LEN);
                r->unparsed_uri.len = len;
            }
            break;
        case NGX_HTTP_ELASTIC_CLIENT_INDEXDOCLIST_RESP:
            if (ngx_strchr(index_path.data, '?')) {
                len = index_path.len + INDEX_DOCLIST_LEN;
                p = r->unparsed_uri.data = ngx_palloc(r->pool, len);
                p = ngx_copy(p, index_path.data, index_path.len);
                p = ngx_copy(p, A_INDEX_DOCLIST, INDEX_DOCLIST_LEN);
                r->unparsed_uri.len = len;
            } else {
                len = index_path.len + INDEX_DOCLIST_LEN;
                p = r->unparsed_uri.data = ngx_palloc(r->pool, len);
                p = ngx_copy(p, index_path.data, index_path.len);
                p = ngx_copy(p, Q_INDEX_DOCLIST, INDEX_DOCLIST_LEN);
                r->unparsed_uri.len = len;
            }
            break;
        default:
            r->unparsed_uri = index_path;
        }
        r->method_name = http_method;

        // ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "uri is =%V ", &r->unparsed_uri);
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_elastic_client_init(ngx_conf_t *cf) {
    if (index_docs_enabled) {
        ngx_http_next_header_filter = ngx_http_top_header_filter;
        ngx_http_top_header_filter = ngx_http_elastic_client_header_filter;

        ngx_http_next_body_filter = ngx_http_top_body_filter;
        ngx_http_top_body_filter = ngx_http_elastic_client_body_filter;
    }

    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_elastic_client_access_handler;

    return NGX_OK;
}

static char *
ngx_conf_elastic_client_proxy_pass_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    u_char *p;
    ngx_str_t *upstream_name, *value = cf->args->elts;
    upstream_name = &value[1];

    if (upstream_name->len) {
        /*** check only allow domain name ***/
        if ((p = (u_char*)ngx_strstr(upstream_name->data, "//"))) {
            if (!(*(p += 2)))
                goto ELASTIC_ERROR_CONF;

            if ((p = (u_char*)ngx_strchr(p, '/'))) {
                upstream_name->len--;
                *p = '\0';
                p++;
                if (*p) {
                    goto ELASTIC_ERROR_CONF;
                }
            }
        } else
            goto ELASTIC_ERROR_CONF;

        ngx_command_t  *proxy_cmd = ngx_http_proxy_module.commands;
        if (proxy_cmd != NULL) {
            for ( /* void */ ; proxy_cmd->name.len; proxy_cmd++) {
                if ( ngx_strcmp(proxy_cmd->name.data, "proxy_pass"/*, (sizeof("proxy_pass") - 1)*/) == 0 ) {
                    // printf("upstream=%.*s\n", (int)upstream_name->len, upstream_name->data);
                    ngx_str_t *values = cf->args->elts;
                    cf->args->nelts = 2;
                    values[1].data = upstream_name->data;
                    values[1].len = upstream_name->len;
                    proxy_cmd->set(cf, proxy_cmd, ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_module) );
                }

                /* set request header content type application/json */
                if ( ngx_strcmp(proxy_cmd->name.data, "proxy_set_header") == 0 ) {
                    char  *conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_module);
                    ngx_array_t      **a;
                    ngx_keyval_t      *kv;

                    a = (ngx_array_t **) (conf + proxy_cmd->offset);

                    if (*a == NULL) {
                        *a = ngx_array_create(cf->pool, 4, sizeof(ngx_keyval_t));
                        if (*a == NULL) {
                            return NGX_CONF_ERROR;
                        }
                    }

                    kv = ngx_array_push(*a);
                    if (kv == NULL) {
                        return NGX_CONF_ERROR;
                    }

                    ngx_str_set(&kv->key, "Content-Type");
                    ngx_str_set(&kv->value, "application/json");
                }
            }
        }
    }

    return NGX_CONF_OK;
ELASTIC_ERROR_CONF:
    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "invalid upstream url while elastic pass");
    return NGX_CONF_ERROR;
} /* ngx_http_elastic_client_by_pass_post_command */


static char *
ngx_conf_elastic_client_set_path_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_elastic_client_loc_conf_t *eclcf = conf;

    ngx_str_t                         *value;
    ngx_http_complex_value_t          **cv;
    ngx_http_compile_complex_value_t   ccv;
    char                              *rv;

    cv = &eclcf->req_method;

    if (*cv != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    *cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (*cv == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    if ( cf->args->nelts == 4) {
        rv = ngx_conf_elastic_client_set_enum_slot(cf, cmd, conf, 3);

        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    if (value[1].len == 0 || value[2].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no method given, e.g. GET/PUT/POST? ");
        return NGX_CONF_ERROR;
    }

    // ngx_strlow(value[1].data, value[1].data, value[1].len);
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // index path complex value compilation
    cv = &eclcf->index_n_path;

    if (*cv != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    *cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (*cv == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = *cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_conf_elastic_client_set_query_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_command_t  *proxy_cmd = ngx_http_proxy_module.commands;
    if (proxy_cmd != NULL) {
        for ( /* void */ ; proxy_cmd->name.len; proxy_cmd++) {
            /* set elastic query to proxy_body */
            if ( ngx_strcmp(proxy_cmd->name.data, "proxy_set_body") == 0 ) {
                proxy_cmd->set(cf, proxy_cmd, ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_module) );
                break;
            }
        }
    }
    return NGX_CONF_OK;
}

static char *
ngx_conf_elastic_client_set_enum_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, ngx_uint_t varargs) {
    char  *p = conf;

    ngx_uint_t       *np, i;
    ngx_str_t        *value;
    ngx_conf_enum_t  *e;

    np = (ngx_uint_t *) (p + cmd->offset);

    if (*np != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    e = cmd->post;

    for (i = 0; e[i].name.len != 0; i++) {
        if (e[i].name.len != value[varargs].len
                || ngx_strcasecmp(e[i].name.data, value[varargs].data) != 0)
        {
            continue;
        }

        *np = e[i].value;

        if ( ngx_strcmp(value[varargs].data, "index_docs" ) == 0 ) {
            index_docs_enabled = 1;
        }

        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid value \"%s\", opts: index_docs, skipmeta, source", value[varargs].data);

    return NGX_CONF_ERROR;
}

static ngx_int_t
ngx_http_elastic_client_header_filter(ngx_http_request_t *r) {
    ngx_http_elastic_client_loc_conf_t *eclcf;
    ngx_http_elastic_client_ctx_t       *ctx;

    eclcf = ngx_http_get_module_loc_conf(r, ngx_http_elastic_client_module);

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED
            || r->headers_out.status == NGX_HTTP_NO_CONTENT
            || r->headers_out.status < NGX_HTTP_OK
            || r != r->main
            || r->method == NGX_HTTP_HEAD)
    {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "========  head response only =============");
    }

    if (eclcf->resp_opt != NGX_HTTP_ELASTIC_CLIENT_INDEXDOCLIST_RESP/*
            || r->headers_out.content_type.len != sizeof("application/json") - 1
            || ngx_strncmp(r->headers_out.content_type.data, "application/json",
                           r->headers_out.content_type.len) != 0*/) {
        goto SKIP_DOCLIST_FILTER;
    }

    // Response Json content type only
    // r->headers_out.content_type_len = sizeof("application/json") - 1;
    // ngx_str_set(&r->headers_out.content_type, "application/json");




    if (r->header_only) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_elastic_client_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->length = r->headers_out.content_length_n;
    if (!ctx->saved_buf) {
        ctx->saved_buf = ngx_calloc_buf(r->pool);
        ctx->saved_buf->pos = ngx_palloc(r->pool, ctx->length);
        ctx->saved_buf->start = ctx->saved_buf->last = ctx->saved_buf->pos;
        ctx->saved_buf->end = ctx->saved_buf->pos + ctx->length;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_elastic_client_module);

SKIP_DOCLIST_FILTER:
    r->filter_need_in_memory = 1;

    // if (r == r->main) {

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);
    // }


    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_index_docs_parser(ngx_http_request_t *r, ngx_buf_t *b, u_char *p, size_t buf_size ) {

    u_char *out;
    if (!b) {
        b = ngx_calloc_buf(r->pool);
    }
    b->start = b->pos = out = ngx_palloc(r->pool, buf_size);
    b->end = b->start + buf_size;
    ngx_str_t *index_str;
    u_char *_index;
    u_char *_source;
    size_t curr_size, index_len, i = 0, index_size = 10;

    ngx_str_t* index_buckets = ngx_pcalloc( r->pool, index_size * sizeof(ngx_str_t));

    out = ngx_copy(out, OBJ_BRACKET_OPEN, 1);

    if ((_index = (u_char*)ngx_strstr(p, FIRST_INDEX))) {
        _index = _index + SIZEOF_FIRSTINDEX;
        if ((_source = (u_char*)ngx_strstr(_index, _SOURCE))) {
            index_len = _source - _index - 1;
            out = ngx_copy(out, DOUBLE_QUOTE, 1);
            out = ngx_copy(out, _index, index_len);
            out = ngx_copy(out, DOUBLE_QUOTE_COLON, 2);
            out = ngx_copy(out, ARRAY_BRACKET_OPEN, 1);
            index_str = &index_buckets[i++];
            index_str->data = _index;
            index_str->len = index_len;
            _source = _source + SIZEOF_SOURCE;

            for (; (_index = (u_char*)ngx_strstr(_source, FOLLOW_INDEX)); i++ ) {
                out = ngx_copy(out, _source, _index - _source - 1);

                _index = _index + SIZEOF_FOLLOWINDEX;
                if (i >= index_size) {
                    curr_size = index_size * sizeof(ngx_str_t);
                    index_buckets = ngx_elasic_client_index_realloc(r, index_buckets, curr_size, curr_size * 2);
                    if (!index_buckets)
                        return NGX_ERROR;
                    index_size *= 2;
                }

                if ((_source = (u_char*)ngx_strstr(_index, _SOURCE))) {
                    index_len = _source - _index - 1;
                    if ( !(is_index_existed(index_buckets, i, _index, index_len)) ) {
                        /** new index **/
                        out = ngx_copy(out, ARRAY_BRACKET_CLOSED, 1);
                        out = ngx_copy(out, COMMA, 1);
                        out = ngx_copy(out, DOUBLE_QUOTE, 1);
                        out = ngx_copy(out, _index, index_len);
                        out = ngx_copy(out, DOUBLE_QUOTE_COLON, 2);
                        out = ngx_copy(out, ARRAY_BRACKET_OPEN, 1);
                    } else {
                        out = ngx_copy(out, COMMA, 1);
                    }
                    _source = _source + SIZEOF_SOURCE;
                }
                index_str = &index_buckets[i];
                index_str->data = _index;
                index_str->len = index_len;
            }

            // LAST Source
            int source_open_close = 0;
            size_t n = b->end - _source;
            register const u_char *__p = _source;
            for (; n != 0; n--) {
                if (*__p == '{')
                    source_open_close++;
                else if (*__p == '}')
                    source_open_close--;

                __p++;
                if (source_open_close == 0)
                    break;
            }
            out = ngx_copy(out, _source, __p - _source  );
            out = ngx_copy(out, ARRAY_BRACKET_CLOSED, 1);
        }
    }


    out = ngx_copy(out, OBJ_BRACKET_CLOSED, 1);
    b->last = out;

    return NGX_OK;
}

static ngx_int_t
ngx_http_elastic_client_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_elastic_client_loc_conf_t *eclcf;

    eclcf = ngx_http_get_module_loc_conf(r, ngx_http_elastic_client_module);

    if (eclcf->resp_opt != NGX_HTTP_ELASTIC_CLIENT_INDEXDOCLIST_RESP) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_int_t                   rc;
    ngx_buf_t                  *b;
    ngx_chain_t                *cl, *tl, *out, **ll;
    ngx_http_elastic_client_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_elastic_client_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    /* create a new chain "out" from "in" with all the changes */

    ll = &out;

    for (cl = in; cl; cl = cl->next) {

        ctx->saved_buf->last = ngx_copy(ctx->saved_buf->last, cl->buf->pos, ngx_buf_size(cl->buf));
        /* loop until last buf then we do the json parsing */
        if (cl->buf->last_buf) {

            tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            // *ctx->saved_buf->last = '\0'; // set NULL terminator
            b = tl->buf;

            ngx_index_docs_parser(r, b, ctx->saved_buf->pos, ctx->saved_buf->last - ctx->saved_buf->pos);

            b->tag = (ngx_buf_tag_t) &ngx_http_elastic_client_module;
            b->temporary = 1;
            b->last_buf = 1;
            // ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Buff= %O", b->last - b->pos );
            // ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "cxt->length= %O", ctx->length );


            *ll = tl;
            ll = &tl->next;
            CLEAR_BUF(cl->buf);
            goto out_result;
        }

        CLEAR_BUF(cl->buf); // clear current buffer

    }
out_result:
    *ll = NULL;

    /* send the new chain */

    rc = ngx_http_next_body_filter(r, out);

    /* update "busy" and "free" chains for reuse */

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_elastic_client_module);

    return rc;
}