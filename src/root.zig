//! Jolt TLS.

const std = @import("std");
const os = std.os;
const posix = std.posix;
const linux = os.linux;
const assert = std.debug.assert;
const jolt = @import("jolt");
const Loop = jolt.Loop;
const Completion = Loop.Completion;
const Socket = Loop.Socket;
const bssl = @import("wrapper/boringssl.zig");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;

// Expose SecurityContext.
pub const SecurityContext = @import("SecurityContext.zig");

// On Windows, all file descriptors are pointers instead of i32.
// TODO: Move this to jolt/io instead.
const invalid_socket = if (is_windows) std.os.windows.ws2_32.INVALID_SOCKET else -1;
// Sizes of read and write buffers of TLS layer. Modifying this variables won't cause any issues.
// Note that too small buffers will likely increase network operations.
// https://github.com/chromium/chromium/blob/edc03b588da57ce59246a1cc5f2e0165a359dbc5/net/socket/ssl_client_socket_impl.cc#L82-L83
const default_openssl_buffer_size = 17 * 1024;
// Helps tracking the last network error.
// We're surely fucked if 65535 is used as error code in some systems.
const error_free: posix.E = @enumFromInt(std.math.maxInt(u16));

/// TLS client implementation backed by BoringSSL.
pub const Client = struct {
    /// Userdatum.
    userdata: ?*anyopaque = null,
    /// Event loop this client does it's I/O.
    loop: *Loop,
    /// Raw socket.
    /// NOTE: The socket is set here after `connect` completed.
    raw_socket: Socket = invalid_socket,
    /// NOTE: Never reuse SSL objects, always create a new one when resetting a `Client`.
    ssl: *bssl.SSL,
    /// TLS uses this for read operations.
    /// NOTE: Rather than pointing to full buffer, this is used as an offset to where readable region begin.
    read_start: [*]u8,
    /// Where readable region end.
    read_len: usize = 0,
    /// TLS uses this for write operations.
    /// NOTE: Unlike `read_start`, this always points to start of original region.
    write_start: [*]u8,
    /// Length of bytes in write region.
    write_len: usize = 0,
    /// Completion for read operations.
    read_comp: Completion = .{},
    /// Completion for write operations.
    write_comp: Completion = .{},
    /// Write completion given by user to write encrypted bytes.
    /// NOTE: Partial writes are always handled.
    /// NOTE: We only borrow this completion.
    user_write_transfer: ?*Transfer = null,
    /// Read completion given by user to receive decrypted bytes.
    /// NOTE: We only borrow this completion.
    user_read_transfer: ?*Transfer = null,
    /// Invoked when handshake made.
    on_handshake: ?HandshakeFn = null,
    /// Internal state management.
    state: State = .unconnected,
    /// Last error received from completions.
    /// Since operations happen in async, its better to keep this here for syncing.
    last_err: posix.E = error_free,

    /// Connection state tracking.
    pub const State = enum {
        /// Not connected yet.
        unconnected,
        /// Client is handshaking with server.
        negotiating,
        /// Stream has done handshake with server.
        /// We remain in this state while application data flows.
        negotiated,
        /// Stream is about to close.
        closing,
        /// Stream has closed.
        closed,
    };

    /// Write completions are turned into this; alignment and size is same as `jolt.Completion`.
    /// NOTE: Configure this to work with IOCP when building jolt/io IOCP.
    const Transfer = extern struct {
        /// Intrusively linked to next transfer.
        next: ?*Transfer = null,
        /// Type-erased userdata, use userdatum to give it a type.
        userdata: ?*anyopaque = null,
        /// Type-erased function pointer.
        callback: ?*const anyopaque = null,
        /// How much data transferred.
        transferred: usize = 0,
        /// This normally indicates operation type but here we use it to find out if we have errors.
        is_eof: bool = false,
        /// Whether or not the completion is in the works.
        active: bool = false,
        /// This'll be given by compiler anyway, reserved here for future usage.
        __pad: [6]u8 = undefined,
        data: extern union {
            rw: extern struct {
                base: [*]u8,
                len: usize,
            },
            /// Same as before, but const pointer for base field.
            rw_const: extern struct {
                base: [*]const u8,
                len: usize,
            },
        },
        /// Normally, this is used in `metadata` of `jolt.Completion` for string fd and flags.
        /// Here we use it store an additional userdata instead.
        userdata0: ?*anyopaque = null,

        /// # SAFETY: Returned slice must be considered constant if `rw_const` was active.
        inline fn sliceAt(transfer: *Transfer, offset: usize) []u8 {
            return (transfer.data.rw.base + offset)[0 .. transfer.data.rw.len - offset];
        }
    };

    pub const HandshakeFn = *const fn (client: *Client, result: anyerror!void) void;

    // Client + read buffer + write buffer.
    const chunk_size = @sizeOf(Client) + default_openssl_buffer_size * 2;

    /// Initializes a new `Client`.
    /// Clients are unmanaged, meaning they don't own an `allocator`. Instead, allocator is required when doing certain operations.
    /// Returns an error if there isn't enough memory.
    pub fn init(allocator: std.mem.Allocator, loop: *Loop, sec_ctx: SecurityContext) error{OutOfMemory}!*Client {
        // NOTE: Alignment of Client must be same as []u8.
        assert(@alignOf(Client) == @alignOf([]u8) and default_openssl_buffer_size > 0);

        // Allocate everything in one go.
        const chunk = try allocator.alignedAlloc(u8, @alignOf(Client), chunk_size);
        errdefer allocator.free(chunk);

        // Interpret first `@sizeOf(Client)` bytes as `Client`.
        const client: *Client = @ptrCast(chunk[0..@sizeOf(Client)]);

        // Init SSL and read/write BIO, we use the same BIO for all ops.
        const rwbio = try bssl.bioNew(try Client.tlsMethod());
        // TODO: errdefer bssl.bioFree?.
        bssl.bioSetData(rwbio, @ptrCast(client)); // Attach Client to BIO.
        bssl.bioSetInit(rwbio, true); // Unless this is provided, BIO won't be initialized.

        // Create SSL.
        const ssl = try bssl.sslNew(sec_ctx.get());
        errdefer bssl.sslFree(ssl);
        // Read BIO.
        bssl.bioUpRef(rwbio); // SSL_set0_rbio takes ownership.
        bssl.sslSet0Rbio(ssl, rwbio);
        // Write BIO.
        bssl.bioUpRef(rwbio); // SSL_set0_wbio takes ownership.
        bssl.sslSet0Wbio(ssl, rwbio);

        // NOTE: might support SSL_set_early_data_enabled.

        // We're the client.
        bssl.sslSetConnectState(ssl);
        // Disable renegotiation, has security flaws.
        bssl.sslSetRenegotiateMode(ssl, bssl.SslRenegotiateMode.never);
        // Configures whether sockets on SSL should permute extensions.
        // For now, this is only implemented for the ClientHello.
        bssl.sslSetPermuteExtensions(ssl, true);
        // Frees some unnecessary data after handshake completed.
        // https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_set_shed_handshake_config
        bssl.sslSetShedHandshakeConfig(ssl, true);

        // Slices of buffers.
        const read_slice = (chunk.ptr + @sizeOf(Client))[0..default_openssl_buffer_size];
        const write_slice = (chunk.ptr + @sizeOf(Client) + default_openssl_buffer_size)[0..default_openssl_buffer_size];

        // Finally init client.
        client.* = .{
            .loop = loop,
            .ssl = ssl,
            .read_start = read_slice.ptr,
            .write_start = write_slice.ptr,
        };

        return client;
    }

    pub fn deinit(client: *Client, allocator: std.mem.Allocator) void {
        bssl.sslFree(client.ssl);

        const chunk = @as([*]u8, @ptrCast(client))[0..chunk_size];
        allocator.free(chunk);
    }

    /// Runs the state machine once.
    fn step(client: *Client) void {
        sw: switch (client.state) {
            // step cannot be called in unconnected and closed state.
            .unconnected, .closing, .closed => unreachable,
            .negotiating => {
                bssl.sslDoHandshake(client.ssl) catch |err| switch (err) {
                    error.IoPending => return, // Retry later.
                    else => unreachable, // TODO
                };

                // If we got here, handshake completed successfully.
                client.state = .negotiated;
                client.on_handshake.?(client, {});

                continue :sw client.state;
            },
            // This is where implicit negotiations and application data transfers happen.
            .negotiated => {
                // Handle write if requested.
                write_blk: {
                    if (client.user_write_transfer) |transfer| {
                        while (transfer.transferred < transfer.data.rw_const.len) {
                            const written = bssl.sslWrite(client.ssl, transfer.sliceAt(transfer.transferred)) catch |err| switch (err) {
                                error.IoPending => break :write_blk, // Retry later.
                                // Indicates TLs layer error, handled as EndOfStream currently.
                                error.Internal => blk: {
                                    client.last_err = @enumFromInt(0); // EOF
                                    break :blk 0;
                                },
                                error.Syscall => 0, // Indicates transport layer error, handled in Completion.Callback.
                                // Other errors are unknown to be reachable; if we found a case where some of them possible
                                // to get, we should also handle them.
                                else => unreachable,
                            };

                            // Advance.
                            transfer.transferred += written;
                        }

                        // Invoke it on loop's completion queue, we do this for;
                        // * predictable stack usage,
                        // * consistency when completions completed.
                        //
                        // NOTE: If we don't see a benefit of it, we can just invoke the callback here.
                        client.sendTransferToLoop(transfer);
                    }
                }

                // Handle read if requested.
                if (client.user_read_transfer) |transfer| {
                    const transferred = bssl.sslRead(client.ssl, transfer.sliceAt(0)) catch |err| switch (err) {
                        error.IoPending => return, // Retry later.
                        // Indicates TLS layer error, handled as EndOfStream currently.
                        error.Internal => blk: {
                            client.last_err = @enumFromInt(0);
                            break :blk 0;
                        },
                        error.Syscall => 0, // Indicates transport layer error, handled in Completion.Callback.
                        else => unreachable,
                    };

                    // No need to sum.
                    transfer.transferred = transferred;

                    // Invoke read callback.
                    const completion: *Completion = @ptrCast(transfer);
                    @call(.auto, @as(Completion.Callback, @ptrCast(completion.callback)), .{ client.loop, completion });
                }
            },
        }
    }

    /// Activates tls_ext_hostname.
    pub inline fn setHostName(client: *const Client, hostname: []const u8) void {
        bssl.sslSetTlsExtHostName(client.ssl, hostname);
    }

    /// Sets the socket for this client.
    pub inline fn setSocket(client: *Client, socket: Socket) void {
        client.raw_socket = socket;
    }

    /// Initiates TLS handshake.
    pub fn handshake(client: *Client, on_done: HandshakeFn) void {
        assert(client.raw_socket != invalid_socket);

        // We don't use step here since we do a lot different things than a step.
        sw: switch (client.state) {
            .negotiated, .closing, .closed => unreachable, // TODO
            .unconnected => {
                // Setup client for the handshake.
                client.on_handshake = on_done;

                client.state = .negotiating;
                continue :sw client.state;
            },
            .negotiating => {
                bssl.sslDoHandshake(client.ssl) catch |err| switch (err) {
                    // Retry later, that's what we expect.
                    error.IoPending => {
                        @branchHint(.likely);
                        return;
                    },
                    else => unreachable, // TODO
                };

                // We should never get here since read buffer must be empty when this called.
                unreachable;
            },
        }

        unreachable;
    }

    /// Write to a TLS client, operation will be inlined if possible. Hence the reason this function can return results.
    /// NOTE: Only a single write completion can be active at a time.
    pub fn write(
        client: *Client,
        completion: *Completion,
        comptime T: type,
        userdata: *T,
        buffer: []const u8,
        comptime on_done: *const fn (
            userdata: *T,
            completion: *Completion,
            client: *Client,
            buffer: []const u8,
            result: error{EndOfStream}!usize,
        ) void,
    ) !usize {
        // Reinterpret as Transfer.
        const transfer: *Transfer = @ptrCast(completion);

        transfer.* = .{
            .next = null,
            .userdata = userdata,
            .callback = @ptrCast(&(struct {
                // This has to take *Loop as argument since this completion will be sent to event loop's
                // completion queue. Event loop invokes each completion's callback with only these two arguments.
                fn wrap(_: *Loop, _completion: *Completion) void {
                    // Completion is free.
                    _completion.active = false;
                    // Transform to transfer.
                    const _transfer: *Transfer = @ptrCast(_completion);
                    // *Client is stored at userdata0.
                    const _client: *Client = @ptrCast(@alignCast(_transfer.userdata0));

                    const result: error{EndOfStream}!usize = blk: {
                        if (_client.hasError()) break :blk error.EndOfStream;

                        break :blk _transfer.transferred;
                    };

                    @call(.always_inline, on_done, .{
                        _completion.userdatum(T),
                        _completion,
                        _client,
                        _transfer.sliceAt(0),
                        result,
                    });
                }
            }).wrap),
            .transferred = 0,
            .active = true,
            .data = .{
                .rw_const = .{
                    .base = buffer.ptr,
                    .len = buffer.len,
                },
            },
            // Client stored here.
            .userdata0 = client,
        };

        // Try inlining.
        while (transfer.transferred < buffer.len) {
            const written = bssl.sslWrite(client.ssl, transfer.sliceAt(transfer.transferred)) catch |err| switch (err) {
                error.IoPending => {
                    // Either cannot be inlined or we have a partial write.
                    // Operation will be completed in the future.
                    client.user_write_transfer = transfer;
                    return err;
                },
                error.Internal => {
                    client.last_err = @enumFromInt(0); // EOF.
                    return error.EndOfStream;
                },
                error.Syscall => return error.EndOfStream,
                else => unreachable,
            };

            // Advance transferred.
            transfer.transferred += written;
        }

        // Not active since operation inlined.
        transfer.active = false;
        return transfer.transferred;
    }

    /// Queues a read operation. Only a single read completion can be active at a time.
    pub fn read(
        client: *Client,
        completion: *Completion,
        comptime T: type,
        userdata: *T,
        slice: []u8,
        comptime on_done: *const fn (
            userdata: *T,
            completion: *Completion,
            client: *Client,
            slice: []u8,
            result: error{EndOfStream}!usize,
        ) void,
    ) void {
        assert(client.user_read_transfer == null);

        const transfer: *Transfer = @ptrCast(completion);

        transfer.* = .{
            .next = null,
            .userdata = userdata,
            .callback = @ptrCast(&(struct {
                fn wrap(_: *Loop, _completion: *Completion) void {
                    // Completion is free.
                    _completion.active = false;
                    // Transform to transfer.
                    const _transfer: *Transfer = @ptrCast(_completion);
                    // *Client is stored at userdata0.
                    const _client: *Client = @ptrCast(@alignCast(_transfer.userdata0));
                    _client.user_read_transfer = null;

                    // Check if we've any errors.
                    // NOTE: Add more errors.
                    const result: error{EndOfStream}!usize = blk: {
                        if (_client.hasError()) {
                            break :blk error.EndOfStream;
                        }

                        break :blk _transfer.transferred;
                    };

                    @call(.always_inline, on_done, .{
                        _completion.userdatum(T),
                        _completion,
                        _client,
                        _transfer.sliceAt(0),
                        result,
                    });
                }
            }).wrap),
            .transferred = 0,
            .active = true,
            .data = .{
                .rw = .{
                    .base = slice.ptr,
                    .len = slice.len,
                },
            },
            .userdata0 = client,
        };

        client.user_read_transfer = transfer;

        // Try inlining.
        const transferred = bssl.sslRead(client.ssl, slice) catch |err| switch (err) {
            error.IoPending => return, // Retry later.
            // Indicates TLS layer error, handled as EndOfStream currently.
            error.Internal => blk: {
                client.last_err = @enumFromInt(0); // EOF
                break :blk 0;
            },
            error.Syscall => 0, // Indicates transport layer error, handled in Completion.Callback.
            else => unreachable,
        };

        // NOTE: No need to sum, we do a single SSL_read call and partial reads are not handled.
        transfer.transferred = transferred;
        // Operation completed inline.
        @call(.auto, @as(Completion.Callback, @ptrCast(completion.callback)), .{ client.loop, completion });
    }

    /// Internal.
    inline fn getReadCompletion(client: *Client) *Completion {
        return &client.read_comp;
    }

    /// Internal.
    inline fn getWriteCompletion(client: *Client) *Completion {
        return &client.write_comp;
    }

    /// Internal.
    inline fn hasError(client: *const Client) bool {
        return client.last_err != error_free;
    }

    /// Internal, sends a `*Transfer` to `jolt.Loop`.
    fn sendTransferToLoop(client: *Client, transfer: *Transfer) void {
        // TODO: Have a proper API in jolt/io to do this.
        client.loop.completed.push(@ptrCast(transfer));
    }

    /// Internal, resets the position of `read_start`.
    inline fn resetReadOffset(client: *Client) void {
        // Read buffer begins right after where `Client` end.
        const read_region = @as([*]u8, @ptrCast(client)) + @sizeOf(Client);
        client.read_start = read_region;
        //client.read_len = 0;
    }

    /// Internal, puts the write buffer to wire if there isn't ongoing send operation.
    inline fn drainWriteBuffer(client: *Client) void {
        // There's nothing to write.
        if (client.write_len == 0) {
            @branchHint(.unlikely);
            return;
        }

        const completion = client.getWriteCompletion();
        // If the completion is already in the works, do nothing.
        if (completion.isPending()) return;

        client.sendAll();
    }

    // NOTE: Modify this to be only given when backed by io_uring.
    const send_flags = if (is_linux) std.os.linux.MSG.WAITALL else 0;

    /// Internal, tries to send the whole buffer that's provided.
    fn sendAll(client: *Client) void {
        client.loop.send(
            client.getWriteCompletion(),
            Client,
            client,
            client.raw_socket,
            client.write_start[0..client.write_len],
            send_flags,
            struct {
                fn on_done(
                    _client: *Client,
                    loop: *Loop,
                    completion: *Completion,
                    _: Socket,
                    _: []const u8,
                    result: Loop.SendError!usize,
                ) void {
                    blk: {
                        // Don't handle the error here, it will be taken care of in bio_write.
                        if (completion.result <= 0) {
                            _client.last_err = @enumFromInt(-completion.result);
                            break :blk;
                        }

                        // Safe, error is handled above.
                        const written = result catch unreachable;
                        // Decrease as much as written.
                        _client.write_len -= written;

                        // Move remaining bytes to beginning.
                        const beginning = _client.write_start[0.._client.write_len];
                        const remaining = (_client.write_start + written)[0.._client.write_len];
                        // NOTE: Slices have a chance to overlap so we cannot use memcpy here.
                        // There are alternative ways to make this fifo without copying, might want to investigate.
                        std.mem.copyForwards(u8, beginning, remaining);

                        // If there are bytes still, keep writing.
                        if (beginning.len > 0) {
                            loop.send(completion, Client, _client, _client.raw_socket, beginning, send_flags, on_done);
                        }
                    }

                    // Continue state machine.
                    @call(.always_inline, step, .{_client});
                }
            }.on_done,
        );
    }

    /// Invoked when transport layer completed a recv operation.
    fn on_recv(
        client: *Client,
        _: *Loop,
        completion: *Completion,
        _: Socket,
        _: []u8,
        result: Loop.RecvError!usize,
    ) void {
        blk: {
            // Don't handle the error here, it will be taken care of in bio_read.
            if (completion.result <= 0) {
                client.last_err = @enumFromInt(-completion.result);
                break :blk;
            }

            // Safe, error is caught above.
            const transferred = result catch unreachable;
            // Advance the read_len.
            client.read_len += transferred;
        }

        // Continue state machine.
        @call(.always_inline, step, .{client});
    }

    /// Called internally by SSL.
    fn bio_read(_bio: ?*bssl.BIO, ptr: [*c]u8, len: c_int) callconv(.c) c_int {
        if (len < 0) unreachable;
        const bio = _bio.?;

        bssl.bioClearRetryFlags(bio);
        const client = clientFromBio(bio);

        // Check if any last op failed.
        //
        // BIO_read attempts to read len bytes into data.
        // It returns the number of bytes read, zero on EOF,
        // or a negative number on error.
        if (client.hasError()) {
            return -1;
        }

        // If there's nothing in the read buffer, queue a read operation.
        if (client.read_len == 0) {
            const completion = client.getReadCompletion();

            // Early return, recv is already pending.
            if (completion.isPending()) {
                bssl.bioSetRetryRead(bio);
                return -1;
            }

            // This puts `read_start` back to start of read region.
            // NOTE: Only moving `read_start` around helps avoiding memcpy for reordering incoming data.
            client.resetReadOffset();

            // NOTE: The idea is only queueing a recv when the read buffer has fully consumed after the last BIO_read.
            // We also try to reduce network syscalls, that's the reason we put whole buffer for the transfer.
            const slice = client.read_start[0..default_openssl_buffer_size];

            // Tell transport layer to do recv.
            client.loop.recv(completion, Client, client, client.raw_socket, slice, on_recv);

            // Tell caller to retry later.
            bssl.bioSetRetryRead(bio);
            return -1;
        }

        // Find how much we can read today.
        const final_len = @min(client.read_len, @as(usize, @intCast(len)));
        // Copy.
        @memcpy(ptr[0..final_len], client.read_start[0..final_len]);
        // Increment `read_start` offset as much as read.
        client.read_start += final_len;
        // Decrement `read_len` as much as consumed.
        client.read_len -= final_len;

        // Success.
        return @intCast(final_len);
    }

    /// Called internally by SSL.
    fn bio_write(_bio: ?*bssl.BIO, ptr: [*c]const u8, len: c_int) callconv(.c) c_int {
        if (len < 0) unreachable;
        const bio = _bio.?;

        bssl.bioClearRetryFlags(bio);
        const client = clientFromBio(bio);

        // Check if any last op failed.
        //
        // BIO_write writes len bytes from data to bio.
        // It returns the number of bytes written or a negative number on error.
        if (client.hasError()) {
            return -1;
        }

        const available_space = default_openssl_buffer_size - client.write_len;

        // If the write buffer is full, queue a send operation.
        // NOTE: This function can only queue send if the write buffer is full, otherwise `bio_flush` do queueing.
        if (available_space == 0) {
            client.drainWriteBuffer();
            // Retry later.
            bssl.bioSetRetryWrite(bio);
            return -1;
        }

        // Find how much we can write atm.
        const final_len = @min(available_space, @as(usize, @intCast(len)));
        // Writable region.
        const portion = (client.write_start + client.write_len)[0..final_len];
        // Copy bytes to internal buffer.
        @memcpy(portion, ptr[0..final_len]);
        client.write_len += final_len;

        // We don't queue a write here since BIO_flush will cause bytes to be transported.
        return @intCast(final_len);
    }

    // Called internally by SSL.
    fn bio_ctrl(_bio: ?*bssl.BIO, cmd: c_int, _: c_long, _: ?*anyopaque) callconv(.c) c_long {
        const bio = _bio.?;
        const client = clientFromBio(bio);

        switch (cmd) {
            bssl.BIO_CTRL.FLUSH => {
                // Initiate data flow if it has stopped or not started yet.
                client.drainWriteBuffer();
                return 1;
            },
            else => {
                // SSL doesn't require us to implement others.
                @panic("attempt to call unimplemented BIO_CTRL");
            },
        }

        unreachable;
    }

    /// Returns a `*Client` from `*bssl.BIO`.
    fn clientFromBio(bio: *bssl.BIO) *Client {
        return @ptrCast(@alignCast(bssl.bioGetData(bio)));
    }

    /// Internal BIO method.
    fn tlsMethod() error{OutOfMemory}!*bssl.BIO_METHOD {
        const meth = try bssl.bioMethNew();
        bssl.bioMethSetRead(meth, bio_read);
        bssl.bioMethSetWrite(meth, bio_write);
        bssl.bioMethSetCtrl(meth, bio_ctrl);

        return meth;
    }
};

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}

test "Simple request, write a proper test" {
    const allocator = std.testing.allocator;

    const Callbacks = struct {
        fn on_socket_create(
            client: *Client,
            loop: *Loop,
            completion: *Completion,
            result: Loop.SocketError!Loop.Socket,
        ) void {
            const socket = result catch unreachable;
            client.setSocket(socket);

            const addr = std.net.Address.initIp4(.{ 142, 250, 184, 142 }, 443);
            loop.connect(completion, Client, client, socket, addr, on_connect);
        }

        fn on_connect(
            client: *Client,
            _: *Loop,
            completion: *Completion,
            _: Loop.Socket,
            _: std.net.Address,
            result: Loop.ConnectError!void,
        ) void {
            result catch unreachable;
            _ = completion;

            client.handshake(on_handshake);
        }

        fn on_handshake(client: *Client, result: anyerror!void) void {
            result catch unreachable;

            var c = Completion{};
            const slice = allocator.dupe(u8, "GET / HTTP/1.1\r\n\r\n") catch unreachable;
            defer allocator.free(slice);

            const transferred = client.write(
                &c,
                Client,
                client,
                slice,
                on_write,
            ) catch unreachable;

            std.debug.print("written {} bytes\n", .{transferred});
        }

        fn on_write(
            _: *Client,
            completion: *Completion,
            client: *Client,
            slice: []const u8,
            result: anyerror!usize,
        ) void {
            defer allocator.free(slice);
            _ = result catch unreachable;
            _ = completion;
            _ = client;

            //const buffer = allocator.alloc(u8, 2048) catch unreachable;
            //client.read(completion, Client, client, buffer, on_read);
        }

        fn on_read(
            _: *Client,
            _: *Completion,
            _: *Client,
            slice: []u8,
            result: error{EndOfStream}!usize,
        ) void {
            defer allocator.free(slice);
            const len = result catch unreachable;

            std.debug.print("{s}\n", .{slice[0..len]});

            //std.debug.print("{s}\n", .{slice[0..len]});
            //_ = stdout.writer().writeAll(slice[0..len]) catch unreachable;
        }
    };

    const sec_ctx = try SecurityContext.init();

    var loop = try Loop.init();
    defer loop.deinit();

    const client = try Client.init(allocator, &loop, sec_ctx);
    defer client.deinit(allocator);

    var completion = Completion{};

    loop.openSocket(
        &completion,
        Client,
        client,
        std.posix.AF.INET,
        std.posix.SOCK.STREAM,
        0,
        0,
        Callbacks.on_socket_create,
    );

    // TODO
    // An atomically reference counted, mutex-locked TLS client.
    // Can be shared across threads and submit operations in parallel.
    // Note that completion callbacks will still be emitted in the loop (main) thread.
    // tls.Client(.shared)
    //
    // Non-atomic TLS client.
    // Cannot be shared across threads, only a single thread can submit operations.
    // tls.Client(.unshared)

    try loop.run();
}
