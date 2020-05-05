/*
 * Copyright (c) 2007 Mikael Magnusson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright owner nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/* Based on mod_spnego version 0.6 */
/*
 * Copyright (c) 2004 - 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <ei.h>
#include <unistd.h>
#include <gssapi/gssapi.h>
#include <malloc.h>
#include <memory.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>


#ifdef HAVE_KRB5
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>
#endif

#include "krb5_deleg.h"
#include "port_util.h"

#define AUTH_GSS_ERROR      -1
#define AUTH_GSS_COMPLETE    1
#define AUTH_GSS_CONTINUE    0

#define ENCODE_ERROR(err)                                \
    {                                                    \
        if (ei_x_encode_atom(&result, "error") ||        \
            ei_x_encode_atom(&result, err))              \
            return 17;                                   \
        write_cmd(&result);                              \
        ei_x_free(&result);                              \
        goto error;                                      \
    }

#define ENCODE_ERROR_NO(err, no)                        \
    {                                                   \
        if (ei_x_encode_atom(&result, "error") ||       \
            ei_x_encode_tuple_header(&result, 2) ||     \
            ei_x_encode_atom(&result, err) ||           \
            ei_x_encode_long(&result, no))              \
            return 18;                                  \
        write_cmd(&result);                             \
        ei_x_free(&result);                             \
        goto error;                                     \
    }

#define EI(err) \
{ \
    if (err) { \
        fprintf(stderr, "marshalling error at file:%s line:%d\r\n", \
                __FILE__, __LINE__); \
        return 1; \
    } \
}

typedef struct session_t {
    gss_ctx_id_t ctx;
    int next_free_session;
} session;

size_t g_session_size;
session *g_sessions;
int g_next_free_session;

typedef int (*port_func)(char *buf, int index, ei_x_buff *presult);

struct func_info {
    const char *name;
    port_func func;
};

void
gss_print_errors (int min_stat);

void
gss_err(int exitval, int status, const char *fmt, ...);

static int
decode_gssapi_binary(char *buf, int *index, gss_buffer_desc *bin);

static void
k5_save(const char *princ_name, gss_cred_id_t cred, char **pccname)
{
    store_gss_creds(princ_name, cred, pccname);
}

int sessions_expand()
{
    size_t session_size = 0;
    session *sessions= NULL;
    int idx;

    if (g_next_free_session >= 0 && g_next_free_session < g_session_size)
        return 1;

    /* Grow by factor of ~1.5 just like Java */
    session_size = (g_session_size * 3)/2 + 1;
    if ((sessions = realloc(g_sessions, session_size * sizeof(session))) == NULL)
        return 0;

    /* Initialise all new session entries */
    for (idx = g_session_size; idx < session_size; idx++) {
        sessions[idx].ctx = GSS_C_NO_CONTEXT;
        sessions[idx].next_free_session = idx+1;
    }

    g_next_free_session = g_session_size;
    g_session_size = session_size;
    g_sessions = sessions;

    return 1;
}

int session_create()
{
    int idx = -1;

    if (!sessions_expand())
        return idx;

    if (g_sessions[g_next_free_session].ctx != GSS_C_NO_CONTEXT)
        return idx;

    idx = g_next_free_session;
    g_next_free_session = g_sessions[idx].next_free_session;
    g_sessions[idx].ctx = GSS_C_NO_CONTEXT;
    g_sessions[idx].next_free_session = -1;

    return idx;
}

OM_uint32 session_destroy(OM_uint32 *min_stat, int idx)
{
    OM_uint32 maj_stat = GSS_S_COMPLETE;

    if (idx < 0 || idx >= g_session_size)
        return GSS_S_NO_CONTEXT;

    if (g_sessions[idx].ctx != GSS_C_NO_CONTEXT) {
        maj_stat = gss_delete_sec_context(min_stat, &g_sessions[idx].ctx,
                                          GSS_C_NO_BUFFER);
    }

    g_sessions[idx].ctx = GSS_C_NO_CONTEXT;
    g_sessions[idx].next_free_session = g_next_free_session;
    g_next_free_session = idx;

    return maj_stat;
}

struct mech_specific {
    char *oid;
    size_t oid_len;
    void (*save_cred)(const char *princ_name, gss_cred_id_t, char **pccname);
} mechs[] = {
    { "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02", 9, k5_save },
    { NULL }
};

static const struct mech_specific *
find_mech(gss_OID oid)
{
    int i;

    for (i = 0; mechs[i].oid != NULL; i++) {
        if (oid->length != mechs[i].oid_len)
            continue;
        if (memcmp(oid->elements, mechs[i].oid, mechs[i].oid_len) != 0)
            continue;
        return &mechs[i];
    }
    return NULL;
}

static int
accept_user(gss_ctx_id_t *ctx,
            gss_buffer_desc *input_token,
            gss_buffer_desc *output_token,
            gss_buffer_desc *name,
            char **pccname)
{
    OM_uint32 maj_stat, min_stat;
    gss_name_t src_name = GSS_C_NO_NAME;
    gss_OID oid = GSS_C_NO_OID;
    int ret = AUTH_GSS_CONTINUE;
    gss_cred_id_t delegated_cred_handle = GSS_C_NO_CREDENTIAL;

    *pccname = NULL;
    maj_stat = gss_accept_sec_context(&min_stat,
                                      ctx,
                                      GSS_C_NO_CREDENTIAL,
                                      input_token,
                                      GSS_C_NO_CHANNEL_BINDINGS,
                                      &src_name,
                                      &oid,
                                      output_token,
                                      NULL,
                                      NULL,
                                      &delegated_cred_handle);

    fprintf(stderr, "gss_accept_sec_context return: %X, %X\r\n", maj_stat, min_stat);

    if (GSS_ERROR(maj_stat) || (GSS_SUPPLEMENTARY_INFO(maj_stat) & ~GSS_S_CONTINUE_NEEDED)) {
        fprintf(stderr, "gss_accept_sec_context: %08x\r\n", maj_stat);
        gss_print_errors(min_stat);
        ret = AUTH_GSS_ERROR;
        goto out;
    }
    
    if (maj_stat & GSS_S_CONTINUE_NEEDED) {
        ret = AUTH_GSS_CONTINUE;
        goto out;
    }

    if (name) {
        /* Use display name */
        maj_stat = gss_display_name(&min_stat, src_name, name, NULL);
        fprintf(stderr, "gss_display_name return: %X, %X\r\n", maj_stat, min_stat);
        if (GSS_ERROR(maj_stat)) {
            ret = AUTH_GSS_ERROR;
            goto out;
        }
    }

    ret = OK;

    /* Do not save credential cache by default when nothing will ever destroy the file */
    /*
    if (delegated_cred_handle != GSS_C_NO_CREDENTIAL) {
        const struct mech_specific *m;
        m = find_mech(oid);
        if (m && m->save_cred)
            (*m->save_cred)(name->value, delegated_cred_handle, pccname);
    }
    */

out:
    if (src_name != GSS_C_NO_NAME)
        gss_release_name(&min_stat, &src_name);

    if (delegated_cred_handle != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min_stat, &delegated_cred_handle);

    return ret;
}

static int
init_user(gss_ctx_id_t *ctx,
          const char *service,
          const char *hostname,
          gss_buffer_desc *input_token,
          gss_buffer_desc *output_token)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc name_token = GSS_C_EMPTY_BUFFER;
    gss_name_t server;
    const gss_OID mech_oid = GSS_C_NO_OID;

    name_token.length = asprintf ((char **)&name_token.value,
                                  "%s@%s", service, hostname);

    maj_stat = gss_import_name (&min_stat,
                                &name_token,
                                GSS_C_NT_HOSTBASED_SERVICE,
                                &server);

    fprintf(stderr, "gss_import_name return: %X, %X\r\n", maj_stat, min_stat);
    if (GSS_ERROR(maj_stat))
        gss_err (1, min_stat,
                 "Error importing name `%s@%s':\r\n", service, hostname);

    maj_stat =
        gss_init_sec_context(&min_stat,
                             GSS_C_NO_CREDENTIAL,
                             ctx,
                             server,
                             mech_oid,
                             GSS_C_DELEG_FLAG,
                             0,
                             GSS_C_NO_CHANNEL_BINDINGS,
                             input_token,
                             NULL,
                             output_token,
                             NULL,
                             NULL);

    fprintf(stderr, "gss_init_sec_context return: %X, %X\r\n", maj_stat, min_stat);
    if (GSS_ERROR(maj_stat))
        gss_err (1, min_stat, "gss_init_sec_context\r\n");

    gss_release_buffer(&min_stat, &name_token);

    return maj_stat;
}

/* From Heimdal */

void
gss_print_errors (int min_stat)
{
    OM_uint32 new_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;
    OM_uint32 ret;

    do {
        ret = gss_display_status (&new_stat,
                                  min_stat,
                                  GSS_C_MECH_CODE,
                                  GSS_C_NO_OID,
                                  &msg_ctx,
                                  &status_string);

	fprintf(stderr, "gss_display_status return: %X, %X\r\n", ret, new_stat);

        fprintf (stderr, "%s\r\n", (char *)status_string.value);
        gss_release_buffer (&new_stat, &status_string);
    } while (!GSS_ERROR(ret) && msg_ctx != 0);
}

void
gss_verr(int exitval, int status, const char *fmt, va_list ap)
{
/*     vwarnx (fmt, ap); */
    gss_print_errors (status);
/*     exit (exitval); */
}

void
gss_err(int exitval, int status, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    gss_verr (exitval, status, fmt, args);
    va_end(args);
}


void test(int argc, char *argv[])
{
    const char *hostname;
    const char *service = "xmpp";
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    char *ccname = NULL;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t ctx_init = GSS_C_NO_CONTEXT;

    if (argc != 2)
        return;

    hostname = argv[1];

    int r1 = init_user(&ctx_init, service, hostname, NULL, &output_token);
    fprintf(stderr, "init_user return: %X\r\n", r1);
    if (r1 != OK) return;
    int r2 = accept_user(&ctx, &output_token, &input_token, &name, &ccname);
    fprintf(stderr, "accept_user return: %X\r\n", r2);
    if (r2 == OK) {
        fprintf(stderr, "User authenticated\r\n");
    }
}


/*
   Erlang port functions
*/

static int accept_sec_context(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;

    /*
      {accept_sec_context, {Idx, In}} ->
      {ok, {Idx, Name, CCName, Out}} |
      {needsmore, {Idx, Out}}
    */

    int arity;
    long idx = -1;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    int res;
    char *ccname = NULL;

    int session_created = 0;
    int success = 0;
    OM_uint32 min_stat;

    EI(ei_decode_tuple_header(buf, &index, &arity));

    EI(arity != 2);

    EI(ei_decode_long(buf, &index, &idx));

    EI(decode_gssapi_binary(buf, &index, &input_token));

    if (idx < 0) {
        idx = session_create();
        if (idx < 0) ENCODE_ERROR("no_mem");
        session_created = 1;
    } else {
        if (idx < 0 || idx >= g_session_size || g_sessions[idx].ctx == GSS_C_NO_CONTEXT)
            ENCODE_ERROR("bad_instance");
    }

    res = accept_user(&g_sessions[idx].ctx, &input_token, &output_token, &name, &ccname);
    if (!GSS_ERROR(res)) {
        if (res & GSS_S_CONTINUE_NEEDED) {
            EI(ei_x_encode_atom(&result, "needsmore") ||
               ei_x_encode_tuple_header(&result, 2) ||
               ei_x_encode_long(&result, idx) ||
               ei_x_encode_binary(&result, output_token.value, output_token.length)
            );
        } else {
            const char *ret_ccname = ccname;
            if (!ret_ccname)
                ret_ccname = "";

            EI(ei_x_encode_atom(&result, "ok") ||
               ei_x_encode_tuple_header(&result, 4) ||
               ei_x_encode_long(&result, idx) ||
               ei_x_encode_string_len(&result, name.value, name.length) ||
               ei_x_encode_string(&result, ret_ccname) ||
               ei_x_encode_binary(&result, output_token.value, output_token.length)
            );
        }
        success = 1;
    } else {
        EI(ei_x_encode_atom(&result, "error") || ei_x_encode_atom(&result, "unauthorized"));
    }

error:
    if (ccname)
        free(ccname);

    if (input_token.value)
        free(input_token.value);

    if (output_token.length)
        gss_release_buffer(&min_stat, &output_token);

    if (name.length)
        gss_release_buffer(&min_stat, &name);

    if (session_created && !success)
        session_destroy(&min_stat, idx);

    *presult = result;
    return 0;
}

static int init_sec_context(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;

    /*
      {init_sec_context, {Idx, Service, Host, Input}} ->
       {ok, {Idx, Data}} | {error, Error}
    */

    int arity;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    int res;
    char *service = NULL;
    char *hostname = NULL;
    long idx = -1;
    int session_created = 0;
    int success = 0;
    OM_uint32 min_stat;

    EI(ei_decode_tuple_header(buf, &index, &arity));

    EI(arity != 4);

    EI(ei_decode_long(buf, &index, &idx));

    DECODE_STRING(&service);
    DECODE_STRING(&hostname);

    EI(decode_gssapi_binary(buf, &index, &input_token));

    if (idx < 0) {
        idx = session_create();
        if (idx < 0) ENCODE_ERROR("no_mem");
        session_created = 1;
    } else {
        if (idx < 0 || idx >= g_session_size || g_sessions[idx].ctx == GSS_C_NO_CONTEXT)
            ENCODE_ERROR("bad_instance");
    }

    res = init_user(&g_sessions[idx].ctx, service, hostname, &input_token, &output_token);
    if (!GSS_ERROR(res)) {
        const char *status = (res & GSS_S_CONTINUE_NEEDED)?"needsmore":"ok";
        EI(ei_x_encode_atom(&result, status) ||
           ei_x_encode_tuple_header(&result, 2) ||
           ei_x_encode_long(&result, idx) ||
           ei_x_encode_binary(&result, output_token.value, output_token.length)
            );
        success = 1;
    } else {
        EI(ei_x_encode_atom(&result, "error") || ei_x_encode_long(&result, res));
    }

error:
    if (service)
        free(service);

    if (hostname)
        free(hostname);

    if (input_token.value)
        gss_release_buffer(&min_stat, &input_token);

    if (output_token.value)
        gss_release_buffer(&min_stat, &output_token);

    if (session_created && !success)
        session_destroy(&min_stat, idx);

    *presult = result;
    return 0;
}

static int delete_sec_context(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;

    /*
      {delete_sec_context, Idx} -> {ok, }
    */

    long idx = -1;
    OM_uint32 maj_stat, min_stat;

    EI(ei_decode_long(buf, &index, &idx));

    if (idx < 0 || idx >= g_session_size || g_sessions[idx].ctx == GSS_C_NO_CONTEXT)
        ENCODE_ERROR("bad_instance");

    maj_stat = session_destroy(&min_stat, idx);

    if (!GSS_ERROR(maj_stat)) {
        EI(ei_x_encode_atom(&result, "ok") ||
           ei_x_encode_atom(&result, "done")
            );
    } else {
        fprintf(stderr, "gss_delete_sec_context: %08x\r\n", maj_stat);
        gss_print_errors(min_stat);
        EI(ei_x_encode_atom(&result, "error") || ei_x_encode_long(&result, maj_stat));
    }

error:
    *presult = result;
    return 0;
}

static int wrap(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;

    /*
      {wrap, {Idx, Conf_req_flag, Input}} -> {ok, {Conf_state, Output}}
    */

    int arity;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    long idx;
    char conf_str[MAXATOMLEN];
    int conf_req;
    int conf_state;
    OM_uint32 maj_stat, min_stat;

    EI(ei_decode_tuple_header(buf, &index, &arity));

    EI(arity != 3);

    EI(ei_decode_long(buf, &index, &idx));

    EI(ei_decode_atom(buf, &index, conf_str));

    EI(decode_gssapi_binary(buf, &index, &input_token));

    if (idx < 0 || idx >= g_session_size || g_sessions[idx].ctx == GSS_C_NO_CONTEXT)
        ENCODE_ERROR("bad_instance");

    if (!strcmp(conf_str, "false")) {
        conf_req = 0;
    } else if (!strcmp(conf_str, "true")) {
        conf_req = 1;
    } else {
        ENCODE_ERROR("bad_parameter");
    }

    maj_stat = gss_wrap(&min_stat, g_sessions[idx].ctx,
                        conf_req, GSS_C_QOP_DEFAULT, &input_token,
                        &conf_state, &output_token);

    if (!GSS_ERROR(maj_stat)) {
        const char *conf_str = conf_state ? "true":"false";

        EI(ei_x_encode_atom(&result, "ok") ||
           ei_x_encode_tuple_header(&result, 2) ||
           ei_x_encode_atom(&result, conf_str) ||
           ei_x_encode_binary(&result, output_token.value, output_token.length)
            );

    } else {
        EI(ei_x_encode_atom(&result, "error") || ei_x_encode_long(&result, maj_stat));
    }

error:
    if (input_token.value)
        gss_release_buffer(&min_stat, &input_token);

    if (output_token.value)
        gss_release_buffer(&min_stat, &output_token);

    *presult = result;
    return 0;
}

static int unwrap(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;

    /*
      {unwrap, {Idx, Input}} -> {ok, {conf_state, Output}}
    */

    int arity;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    long idx;
    int conf_state;
    OM_uint32 maj_stat, min_stat;
    gss_qop_t qop;

    EI(ei_decode_tuple_header(buf, &index, &arity));

    EI(arity != 2);

    EI(ei_decode_long(buf, &index, &idx));

    EI(decode_gssapi_binary(buf, &index, &input_token));

    if (idx < 0 || idx >= g_session_size || g_sessions[idx].ctx == GSS_C_NO_CONTEXT)
        ENCODE_ERROR("bad_instance");

    maj_stat = gss_unwrap(&min_stat, g_sessions[idx].ctx,
                          &input_token, &output_token, &conf_state, &qop);

    if (!GSS_ERROR(maj_stat)) {
        const char *conf_str = conf_state ? "true":"false";

        EI(ei_x_encode_atom(&result, "ok") ||
           ei_x_encode_tuple_header(&result, 2) ||
           ei_x_encode_atom(&result, conf_str) ||
           ei_x_encode_binary(&result, output_token.value, output_token.length)
            );

    } else {
        EI(ei_x_encode_atom(&result, "error") || ei_x_encode_long(&result, maj_stat));
    }

error:
    if (input_token.value)
        gss_release_buffer(&min_stat, &input_token);

    if (output_token.value)
        gss_release_buffer(&min_stat, &output_token);

    *presult = result;
    return 0;
}

#define BUF_SIZE 128

struct func_info g_entries[] = {
    { "accept_sec_context", accept_sec_context },
    { "init_sec_context", init_sec_context },
    { "delete_sec_context", delete_sec_context },
    { "wrap", wrap },
    { "unwrap", unwrap }
};

port_func lookup_func(const char *name)
{
    int i;
    int size = sizeof(g_entries) / sizeof(g_entries[0]);

    for (i = 0; i < size; i++) {
        if (strcmp(name, g_entries[i].name) == 0) {
            return g_entries[i].func;
        }
    }

    return NULL;
}

/*-----------------------------------------------------------------
 * MAIN
 *----------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    byte *buf;
    int size = BUF_SIZE;
    char command[MAXATOMLEN];
    int index, version, arity;
    ei_x_buff result;
    port_func func;

    if (argc > 1) {
        test(argc, argv);
        return 0;
    }

    fprintf(stderr, "gssapi started\r\n");

    g_session_size = 0;
    g_sessions = NULL;
    g_next_free_session = -1;

    if ((buf = (byte *) malloc(size)) == NULL)
        return -1;

    while (read_cmd(&buf, &size) > 0) {
        index = 0;

        /* Ensure that we are receiving the binary term by reading and
         * stripping the version byte */
        EI(ei_decode_version(buf, &index, &version));

        /* Our marshalling spec is that we are expecting a tuple {Command, Arg1} */
        EI(ei_decode_tuple_header(buf, &index, &arity));

        EI(arity != 2);

        EI(ei_decode_atom(buf, &index, command));

        /* Prepare the output buffer that will hold {ok, Result} or {error, Reason} */
        EI(ei_x_new_with_version(&result) || ei_x_encode_tuple_header(&result, 2));

        func = lookup_func(command);
        if (func) {
            if (func(buf, index, &result) != 0)
                EI(ei_x_encode_atom(&result, "error") ||
                   ei_x_encode_atom(&result, "marshalling"));
        } else {
            EI(ei_x_encode_atom(&result, "error") || ei_x_encode_atom(&result, "unsupported_command"));
        }

        write_cmd(&result);

        ei_x_free(&result);
    }

    free(g_sessions);
    free(buf);

    fprintf(stderr, "No more command, gssapi exiting\r\n");

    return 0;
}

static int
decode_gssapi_binary(char *buf, int *index, gss_buffer_desc *bin)
{
    int type = 0;
    int len = 0;
    long llen;

    EI(ei_get_type(buf, index, &type, &len));

    EI(type != ERL_BINARY_EXT);

    bin->length = len;
    bin->value = malloc(len);

    llen = len;

    EI(ei_decode_binary(buf, index, bin->value, &llen));

    bin->length = llen;

    return 0;
}
