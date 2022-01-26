-- Copyright (C) by OpenResty Inc.


local base = require "resty.core.base"
local ffi = require "ffi"


local C = ffi.C
local ffi_str = ffi.string
local ffi_gc = ffi.gc
local FFI_ERROR = base.FFI_ERROR
local FFI_DONE = base.FFI_DONE
local FFI_OK = base.FFI_OK
local FFI_AGAIN = base.FFI_AGAIN
local FFI_NO_REQ_CTX = base.FFI_NO_REQ_CTX
local get_request = base.get_request
local error = error
local assert = assert
local type = type
local pcall = pcall
local select = select
local co_yield = coroutine._yield


ffi.cdef[[
typedef struct ngx_http_lua_socket_tcp_upstream_s
    ngx_http_lua_socket_tcp_upstream_t;

int ngx_http_lua_ffi_socket_tcp_sslhandshake(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, void *sess,
    int enable_session_reuse, ngx_str_t *server_name, int verify,
    int ocsp_status_req, void *chain, void *pkey, char **errmsg);

int ngx_http_lua_ffi_socket_tcp_get_sslhandshake_result(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, void **sess, char **errmsg,
    int *openssl_error_code);

void ngx_http_lua_ffi_ssl_free_session(void *sess);
]]


local SOCKET_CTX_INDEX = 1


local errmsg = base.get_errmsg_ptr()
local session_ptr = ffi.new("void *[1]")
local server_name_str = ffi.new("ngx_str_t[1]")
local openssl_error_code = ffi.new("int[1]")

local function setclientcert(self, cert, pkey)
    if not cert and not pkey then
        self.client_cert = nil
        self.client_pkey = nil
        return
    end

    if not cert or not pkey then
        error("client certificate must be supplied with corresponding " ..
              "private key", 2)
    end

    if type(cert) ~= "cdata" then
        error("bad client cert type", 2)
    end

    if type(pkey) ~= "cdata" then
        error("bad client pkey type", 2)
    end

    self.client_cert = cert
    self.client_pkey = pkey
end


local function sslhandshake(self, reused_session, server_name, ssl_verify,
    send_status_req, ...)

    local n = select("#", ...)
    if not self or n > 1 then
        error("ngx.socket sslhandshake: expecting 1 ~ 5 arguments " ..
              "(including the object), but seen " .. (self and 5 + n or 0))
    end

    local r = get_request()
    if not r then
        error("no request found", 2)
    end

    session_ptr[0] = type(reused_session) == "cdata" and reused_session or nil

    if server_name then
        server_name_str[0].data = server_name
        server_name_str[0].len = #server_name

    else
        server_name_str[0].data = nil
        server_name_str[0].len = 0
    end

    local u = self[SOCKET_CTX_INDEX]

    local rc = C.ngx_http_lua_ffi_socket_tcp_sslhandshake(r, u,
                   session_ptr[0],
                   reused_session ~= false,
                   server_name_str,
                   ssl_verify and 1 or 0,
                   send_status_req and 1 or 0,
                   self.client_cert, self.client_pkey, errmsg)

    if rc == FFI_NO_REQ_CTX then
        error("no request ctx found", 2)
    end

    while true do
        if rc == FFI_ERROR then
            if openssl_error_code[0] ~= 0 then
                return nil, openssl_error_code[0] .. ": " .. ffi_str(errmsg[0])
            end

            return nil, ffi_str(errmsg[0])
        end

        if rc == FFI_DONE then
            return reused_session
        end

        if rc == FFI_OK then
            if reused_session == false then
                return true
            end

            rc = C.ngx_http_lua_ffi_socket_tcp_get_sslhandshake_result(r, u,
                     session_ptr, errmsg, openssl_error_code)

            assert(rc == FFI_OK)

            if session_ptr[0] == nil then
                return nil
            end

            return ffi_gc(session_ptr[0], C.ngx_http_lua_ffi_ssl_free_session)
        end

        assert(rc == FFI_AGAIN)

        co_yield()

        rc = C.ngx_http_lua_ffi_socket_tcp_get_sslhandshake_result(r, u,
                 session_ptr, errmsg, openssl_error_code)
    end
end


do
    local old_socket_tcp = ngx.socket.tcp

    function ngx.socket.tcp()
        local ok, sock = pcall(old_socket_tcp)
        if not ok then
            error(sock, 2)
        end

        sock.setclientcert = setclientcert
        sock.sslhandshake  = sslhandshake

        return sock
    end
end


return {
    version = base.version
}
