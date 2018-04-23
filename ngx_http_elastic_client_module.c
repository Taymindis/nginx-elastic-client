/**
* @file   ngx_http_elastic_client_module.c
* @author taymindis <cloudleware2015@gmail.com>
* @date   Sun JAN 28 12:06:52 2018
*
* @brief  A ngx_c_function module for Nginx.
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
// static ngx_int_t ngx_http_elastic_client_header_filter(ngx_http_request_t *r);
// static ngx_int_t ngx_http_elastic_client_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

// static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
// static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

#define NGX_HTTP_ELASTIC_CLIENT_SKIPMETA_RESP 905
#define NGX_HTTP_ELASTIC_CLIENT_SOURCEONLY_RESP 906
#define NGX_HTTP_ELASTIC_CLIENT_RESP_OPT_OFF 0

static ngx_conf_enum_t ngx_http_elastic_client_resp_opt[] = {
    { ngx_string("skipmeta"), NGX_HTTP_ELASTIC_CLIENT_SKIPMETA_RESP },
    { ngx_string("source"), NGX_HTTP_ELASTIC_CLIENT_SOURCEONLY_RESP },
    //  { ngx_string("doctype_json"), NGX_HTTP_ELASTIC_CLIENT_DOCTYPEJSON_RESP },
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
    ngx_http_elastic_client_loc_conf_t  *hwlcf;
    ngx_str_t                           http_method;
    ngx_str_t                           index_path;
    u_char                              *p/*, *target_opt*/;
    size_t                              len/*, target_opt_len*/;


    hwlcf = ngx_http_get_module_loc_conf(r, ngx_http_elastic_client_module);

    if (hwlcf->index_n_path) {
        if (ngx_http_complex_value(r, hwlcf->req_method, &http_method) != NGX_OK ||
                ngx_http_complex_value(r, hwlcf->index_n_path, &index_path) != NGX_OK) {
            return NGX_ERROR;
        }

        if (hwlcf->resp_opt == NGX_HTTP_ELASTIC_CLIENT_SKIPMETA_RESP) {
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
        } else if (hwlcf->resp_opt == NGX_HTTP_ELASTIC_CLIENT_SOURCEONLY_RESP) {
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
        } else {
            r->unparsed_uri = index_path;
        }
        
        r->method_name = http_method;

        // ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "uri is =%V ", &r->unparsed_uri);
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_elastic_client_init(ngx_conf_t *cf) {
    // ngx_http_next_header_filter = ngx_http_top_header_filter;
    // ngx_http_top_header_filter = ngx_http_elastic_client_header_filter;

    // ngx_http_next_body_filter = ngx_http_top_body_filter;
    // ngx_http_top_body_filter = ngx_http_elastic_client_body_filter;

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
    ngx_http_elastic_client_loc_conf_t *hwlcf = conf;

    ngx_str_t                         *value;
    ngx_http_complex_value_t          **cv;
    ngx_http_compile_complex_value_t   ccv;
    char                              *rv;

    cv = &hwlcf->req_method;

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
    cv = &hwlcf->index_n_path;

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

        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid value \"%s\", opt: skipmeta, source", value[varargs].data);

    return NGX_CONF_ERROR;
}

// static ngx_int_t
// ngx_http_elastic_client_header_filter(ngx_http_request_t *r) {
//     ngx_http_elastic_client_loc_conf_t *hwlcf;
//     ngx_http_elastic_client_ctx_t       *ctx;

//     hwlcf = ngx_http_get_module_loc_conf(r, ngx_http_elastic_client_module);

//     if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED
//             || r->headers_out.status == NGX_HTTP_NO_CONTENT
//             || r->headers_out.status < NGX_HTTP_OK
//             || r != r->main
//             || r->method == NGX_HTTP_HEAD)
//     {
//         ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "========  head response only =============");
//     }

//     if (hwlcf->resp_opt != NGX_HTTP_ELASTIC_CLIENT_DOCTYPEJSON_RESP/*
//             || r->headers_out.content_type.len != sizeof("application/json") - 1
//             || ngx_strncmp(r->headers_out.content_type.data, "application/json",
//                            r->headers_out.content_type.len) != 0*/) {
//         return ngx_http_next_header_filter(r);
//     }

//     // Response Json content type only
//     // r->headers_out.content_type_len = sizeof("application/json") - 1;
//     // ngx_str_set(&r->headers_out.content_type, "application/json");




//     if (r->header_only) {
//         return ngx_http_next_header_filter(r);
//     }

//     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_elastic_client_ctx_t));
//     if (ctx == NULL) {
//         return NGX_ERROR;
//     }

//     ctx->length = r->headers_out.content_length_n;
//     if (!ctx->saved_buf) {
//         ctx->saved_buf = ngx_calloc_buf(r->pool);
//         ctx->saved_buf->pos = ngx_palloc(r->pool, ctx->length);
//         ctx->saved_buf->start = ctx->saved_buf->last = ctx->saved_buf->pos;
//         ctx->saved_buf->end = ctx->saved_buf->pos + ctx->length;
//     }

//     ngx_http_set_ctx(r, ctx, ngx_http_elastic_client_module);

//     r->filter_need_in_memory = 1;

//     // if (r == r->main) {

//     ngx_http_clear_content_length(r);
//     ngx_http_clear_accept_ranges(r);
//     ngx_http_weak_etag(r);
//     // }


//     return ngx_http_next_header_filter(r);
// }

// static void
// ngx_http_elastic_client_doctype_parser(ngx_http_request_t *r, ngx_buf_t *b, u_char *p, size_t buf_size ) {
//     u_char *l = NULL;
//     u_char *out;

//     b->start = b->pos = out = ngx_palloc(r->pool, buf_size);
//     b->end = b->start + buf_size;

//     if (out) {
//         out = ngx_copy(out, "{\"docs\":[", sizeof("{\"docs\":[") - 1);

//         l = p = (u_char*) ngx_strstr(p, "},{\"_source\"") + 14;

//         for (;;) {
//             l = (u_char*)ngx_strstr(l, "},{\"_source\"");
//             if (!l) {
//                 out = ngx_copy(out, "{", 1);
//                 out = ngx_copy(out, p, (u_char*)strrchr((const char *) p, ']') - 1 - p );
//                 out = ngx_copy(out, "]}", 2);
//                 break;
//             }
//             out = ngx_copy(out, "{", 1);
//             out = ngx_copy(out, p, l - p);
//             out = ngx_copy(out, ",", 1);
//             p = l = l + 14;
//         }
//     }
//     b->last = out;
// }

// static ngx_int_t
// ngx_http_elastic_client_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {

//     ngx_int_t                   rc;
//     ngx_buf_t                  *b;
//     ngx_chain_t                *cl, *tl, *out, **ll;
//     ngx_http_elastic_client_ctx_t  *ctx;

//     ctx = ngx_http_get_module_ctx(r, ngx_http_elastic_client_module);
//     if (ctx == NULL) {
//         ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_elastic_client_ctx_t));
//         if (ctx == NULL) {
//             return NGX_ERROR;
//         }

//         ngx_http_set_ctx(r, ctx, ngx_http_elastic_client_module);
//     }

//     /* create a new chain "out" from "in" with all the changes */

//     ll = &out;

//     for (cl = in; cl; cl = cl->next) {

//         ctx->saved_buf->last = ngx_copy(ctx->saved_buf->last, cl->buf->pos, ngx_buf_size(cl->buf));
//         /* loop until last buf then we do the json parsing */
//         if (cl->buf->last_buf) {
//             // ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Buff= %*s", ctx->saved_buf->last - ctx->saved_buf->pos , ctx->saved_buf->pos);

//             tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
//             if (tl == NULL) {
//                 return NGX_ERROR;
//             }

//             *ctx->saved_buf->last = '\0'; // set NULL terminator
//             b = tl->buf;

//             ngx_http_elastic_client_doctype_parser(r, b, ctx->saved_buf->pos, ctx->saved_buf->last - ctx->saved_buf->pos);

//             b->tag = (ngx_buf_tag_t) &ngx_http_elastic_client_module;
//             b->temporary = 1;

//             // b->pos = ctx->saved_buf->pos;
//             // b->last = ctx->saved_buf->last;
//             // b->start = ctx->saved_buf->start;
//             // b->end = ctx->saved_buf->end;
//             b->last_buf = 1;


//             *ll = tl;
//             ll = &tl->next;
//             CLEAR_BUF(cl->buf);
//             goto out_result;
//         }

//         CLEAR_BUF(cl->buf); // clear current buffer

//         /* append the next incoming buffer */

//         // tl = ngx_alloc_chain_link(r->pool);
//         // if (tl == NULL) {
//         //     return NGX_ERROR;
//         // }

//         // tl->buf = cl->buf;
//         // *ll = tl;
//         // ll = &tl->next;
//     }
// out_result:
//     *ll = NULL;

//     /* send the new chain */

//     rc = ngx_http_next_body_filter(r, out);

//     /* update "busy" and "free" chains for reuse */

//     ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
//                             (ngx_buf_tag_t) &ngx_http_elastic_client_module);

//     return rc;
// }