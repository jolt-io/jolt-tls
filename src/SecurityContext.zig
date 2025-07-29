//! SecurityContext defines security defaults.

const bssl = @import("wrapper/boringssl.zig");

const SecurityContext = @This();
ctx: *bssl.SSL_CTX,

pub fn init() error{OutOfMemory}!SecurityContext {
    const ctx = try bssl.sslCtxNew(bssl.tlsMethod());

    // Only allow TLS 1.2 to TLS 1.3.
    bssl.sslCtxSetMinProtoVersion(ctx, bssl.SslVersion.tls_1_2_version);
    bssl.sslCtxSetMaxProtoVersion(ctx, bssl.SslVersion.tls_1_3_version);

    bssl.sslCtxSetMode(ctx, bssl.SslMode.enable_partial_write | bssl.SslMode.enable_false_start | bssl.SslMode.accept_moving_write_buffer | bssl.SslMode.no_auto_chain);

    return .{ .ctx = ctx };
}

pub inline fn deinit(sec_ctx: SecurityContext) void {
    return bssl.sslCtxFree(sec_ctx.ctx);
}

pub inline fn get(sec_ctx: SecurityContext) *bssl.SSL_CTX {
    return sec_ctx.ctx;
}
