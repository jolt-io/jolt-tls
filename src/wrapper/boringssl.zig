//! BoringSSL wrappers.
//! NOTE: Wrappers must be a thin layer, meaning they should not add costs what's already there.

const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.jolt_tls_boringssl);

const c = @cImport({
    @cInclude("openssl/ssl.h");
});

pub const SSL = c.SSL;
pub const SSL_CTX = c.SSL_CTX;
pub const SSL_METHOD = c.SSL_METHOD;
pub const BIO = c.BIO;
pub const BIO_METHOD = c.BIO_METHOD;

pub const SslError = error{
    // Same as SSL_ERROR_SSL, indicates the operation failed within the library.
    // The caller may inspect the error queue (see ERR_get_error) for more information.
    Internal,
    // Either read or write is requested in transport layer.
    IoPending,
    WantX509Lookup,
    Syscall,
    ZeroReturn,
    WantConnect,
    Unexpected,
    // TODO: Add more errors.
};

pub fn sslError(ssl: *c.SSL, e: c_int) SslError!void {
    return switch (c.SSL_get_error(ssl, e)) {
        c.SSL_ERROR_NONE => {}, // Not an error.
        c.SSL_ERROR_SSL => error.Internal, // SSL library encountered an internal error.
        c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => error.IoPending, // Transport layer needs some work to do.
        c.SSL_ERROR_WANT_X509_LOOKUP => error.WantX509Lookup,
        c.SSL_ERROR_SYSCALL => error.Syscall, // Not-so-likely to happen in our case.
        c.SSL_ERROR_ZERO_RETURN => error.ZeroReturn,
        c.SSL_ERROR_WANT_CONNECT => error.WantConnect,
        else => |errno| {
            log.warn("unexpected ssl error: {}\n", .{errno});
            return error.Unexpected;
        },
    };
}

pub fn sslDoHandshake(ssl: *c.SSL) SslError!void {
    const e = c.SSL_do_handshake(ssl);
    if (e == 1) {
        return;
    } else if (e <= 0) {
        return sslError(ssl, e);
    } else {
        unreachable;
    }
}

pub fn sslRead(ssl: *c.SSL, buffer: []u8) SslError!usize {
    const e = c.SSL_read(ssl, @ptrCast(buffer.ptr), @intCast(buffer.len));
    // Success.
    if (e > 0) {
        return @intCast(e);
    }

    try sslError(ssl, e);
    unreachable;
}

pub fn sslWrite(ssl: *c.SSL, buffer: []const u8) SslError!usize {
    const e = c.SSL_write(ssl, @ptrCast(buffer.ptr), @intCast(buffer.len));
    // Success.
    if (e > 0) {
        return @intCast(e);
    }

    try sslError(ssl, e);
    unreachable;
}

pub fn sslNew(ctx: *SSL_CTX) error{OutOfMemory}!*SSL {
    return c.SSL_new(ctx) orelse error.OutOfMemory;
}

pub inline fn sslFree(ssl: *SSL) void {
    return c.SSL_free(ssl);
}

pub inline fn sslSetTlsExtHostName(ssl: *c.SSL, host: []const u8) void {
    _ = c.SSL_set_tlsext_host_name(ssl, host.ptr);
}

pub inline fn sslSet0Rbio(ssl: *SSL, bio: *BIO) void {
    return c.SSL_set0_rbio(ssl, bio);
}

pub inline fn sslSet0Wbio(ssl: *SSL, bio: *BIO) void {
    return c.SSL_set0_wbio(ssl, bio);
}

pub const SslRenegotiateMode = struct {
    pub const once = c.ssl_renegotiate_once;
    pub const never = c.ssl_renegotiate_never;
    pub const explicit = c.ssl_renegotiate_explicit;
    pub const freely = c.ssl_renegotiate_freely;
    pub const ignore = c.ssl_renegotiate_ignore;
};

pub inline fn sslSetRenegotiateMode(ssl: *SSL, mode: c_int) void {
    return c.SSL_set_renegotiate_mode(ssl, mode);
}

pub inline fn sslSetPermuteExtensions(ssl: *SSL, enabled: bool) void {
    return c.SSL_set_permute_extensions(ssl, @as(c_int, @intFromBool(enabled)));
}

pub inline fn sslSetShedHandshakeConfig(ssl: *SSL, enabled: bool) void {
    return c.SSL_set_shed_handshake_config(ssl, @intFromBool(enabled));
}

pub inline fn sslSetConnectState(ssl: *SSL) void {
    return c.SSL_set_connect_state(ssl);
}

pub inline fn tlsMethod() *const SSL_METHOD {
    return c.TLS_method() orelse unreachable;
}

pub inline fn sslCtxNew(method: *const SSL_METHOD) error{OutOfMemory}!*SSL_CTX {
    return c.SSL_CTX_new(method) orelse error.OutOfMemory;
}

pub inline fn sslCtxFree(ctx: *SSL_CTX) void {
    return c.SSL_CTX_free(ctx);
}

pub const SslVersion = struct {
    pub const tls_1_2_version = c.TLS1_2_VERSION;
    pub const tls_1_3_version = c.TLS1_3_VERSION;
};

pub inline fn sslCtxSetMinProtoVersion(ctx: *SSL_CTX, version: u16) void {
    assert(c.SSL_CTX_set_min_proto_version(ctx, version) == 1);
}

pub inline fn sslCtxSetMaxProtoVersion(ctx: *SSL_CTX, version: u16) void {
    assert(c.SSL_CTX_set_max_proto_version(ctx, version) == 1);
}

pub const SslMode = struct {
    pub const enable_partial_write = c.SSL_MODE_ENABLE_PARTIAL_WRITE;
    pub const enable_false_start = c.SSL_MODE_ENABLE_FALSE_START;
    pub const accept_moving_write_buffer = c.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
    pub const no_auto_chain = c.SSL_MODE_NO_AUTO_CHAIN;
};

pub inline fn sslCtxSetMode(ctx: *SSL_CTX, mode: u32) void {
    _ = c.SSL_CTX_set_mode(ctx, mode);
}

pub fn bioNew(method: *BIO_METHOD) error{OutOfMemory}!*BIO {
    const bio = c.BIO_new(method);
    if (bio == null) return error.OutOfMemory;
    return @ptrCast(bio);
}

pub inline fn bioPending(bio: *BIO) usize {
    return c.BIO_pending(bio);
}

pub inline fn bioSetData(bio: *BIO, ptr: ?*anyopaque) void {
    return c.BIO_set_data(bio, ptr);
}

pub inline fn bioGetData(bio: *BIO) ?*anyopaque {
    return c.BIO_get_data(bio);
}

pub inline fn bioSetInit(bio: *BIO, enabled: bool) void {
    return c.BIO_set_init(bio, @as(c_int, @intFromBool(enabled)));
}

pub inline fn bioUpRef(bio: *BIO) void {
    assert(c.BIO_up_ref(bio) == 1);
}

pub inline fn bioClearRetryFlags(bio: *BIO) void {
    return c.BIO_clear_retry_flags(bio);
}

pub inline fn bioSetRetryRead(bio: *BIO) void {
    return c.BIO_set_retry_read(bio);
}

pub inline fn bioSetRetryWrite(bio: *BIO) void {
    return c.BIO_set_retry_write(bio);
}

pub fn bioMethNew() error{OutOfMemory}!*BIO_METHOD {
    return c.BIO_meth_new(0, null) orelse error.OutOfMemory;
}

pub const BIO_METH_READ_FUNC = *const fn (bio: ?*BIO, ptr: [*c]u8, len: c_int) callconv(.c) c_int;
pub const BIO_METH_WRITE_FUNC = *const fn (bio: ?*BIO, ptr: [*c]const u8, len: c_int) callconv(.c) c_int;
pub const BIO_METH_CTRL_FUNC = *const fn (bio: ?*BIO, cmd: c_int, larg: c_long, parg: ?*anyopaque) callconv(.c) c_long;

pub const BIO_CTRL = struct {
    pub const FLUSH = c.BIO_CTRL_FLUSH;
    pub const PENDING = c.BIO_CTRL_PENDING;
    pub const WPENDING = c.BIO_CTRL_WPENDING;
};

pub inline fn bioMethSetRead(meth: *BIO_METHOD, read_fn: BIO_METH_READ_FUNC) void {
    _ = c.BIO_meth_set_read(meth, read_fn);
}

pub inline fn bioMethSetWrite(meth: *BIO_METHOD, write_fn: BIO_METH_WRITE_FUNC) void {
    _ = c.BIO_meth_set_write(meth, write_fn);
}

pub inline fn bioMethSetCtrl(meth: *BIO_METHOD, ctrl_fn: BIO_METH_CTRL_FUNC) void {
    _ = c.BIO_meth_set_ctrl(meth, ctrl_fn);
}
