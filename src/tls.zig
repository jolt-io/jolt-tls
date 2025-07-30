const std = @import("std");
const os = std.os;
const posix = std.posix;
const assert = std.debug.assert;
const jolt = @import("jolt");
const Loop = jolt.Loop;
const Completion = Loop.Completion;
const Socket = Loop.Socket;
const bssl = @import("wrapper/boringssl.zig");
const SecurityContext = @import("SecurityContext.zig");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;

// On Windows, all file descriptors are pointers instead of i32.
// TODO: Move this to jolt/io instead.
const invalid_socket = if (is_windows) std.os.windows.ws2_32.INVALID_SOCKET else -1;
// Sizes of read and write buffers of TLS layer. Modifying this variables won't cause any issues.
// Note that too small buffers will likely increase network operations.
// https://github.com/chromium/chromium/blob/edc03b588da57ce59246a1cc5f2e0165a359dbc5/net/socket/ssl_client_socket_impl.cc#L82-L83
const default_openssl_buffer_size = 17 * 1024;

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
    /// Write completions but in order.
    /// NOTE: Partial writes are always handled.
    /// NOTE: We don't take ownership of Transfers here, only borrowed.
    write_queue: jolt.Queue(Transfer) = .{},
    /// Read completion given by user to receive decrypted bytes.
    /// NOTE: We don't take ownership of this completion.
    user_read_transfer: ?*Transfer = null,
    /// Invoked when handshake made.
    on_handshake: ?HandshakeFn = null,
    /// Internal state management.
    state: State = .unconnected,

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

        /// Type of type-erased `callback`.
        const Callback = *const fn (*Client, *Completion) void;

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
        assert(@alignOf(Client) == @alignOf([]u8));
        // Allocate everything in one go.
        const chunk = try allocator.alignedAlloc(u8, @alignOf(Client), chunk_size);
        errdefer allocator.free(chunk);

        // Interpret first `@sizeOf(Client)` bytes as `Client`.
        const client: *Client = @ptrCast(chunk[0..@sizeOf(Client)]);

        // Init SSL and read/write BIO.
        // BIO we use for all TLS I/O.
        const rwbio = try bssl.bioNew(try Client.tlsMethod());
        // TODO: errdefer bssl.bioFree.
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
            .unconnected, .closed => unreachable,
            .negotiating => {
                bssl.sslDoHandshake(client.ssl) catch |err| switch (err) {
                    error.IoPending => return, // Retry later.
                    error.ZeroReturn, error.Syscall => {
                        client.state = .closing;
                        client.on_handshake.?(client, error.Closed);
                    },
                    else => unreachable,
                };

                // If we got here, handshake completed successfully.
                client.state = .negotiated;
                client.on_handshake.?(client, {});

                continue :sw client.state;
            },
            // This is where implicit negotiations and application data transfers happen.
            .negotiated => {
                // We try to drain everything in the wq.
                var _node = client.write_queue.head;
                write_loop: while (_node) |node| : (_node = client.write_queue.head) {
                    while (node.transferred < node.data.rw_const.len) {
                        const written = bssl.sslWrite(client.ssl, node.sliceAt(node.transferred)) catch |err| switch (err) {
                            // Retry later.
                            error.IoPending => break :write_loop,
                            else => {
                                // This indicates write layer encountered an unrecoverable error.
                                // Move on to closing state.
                                client.state = .closing;
                                continue :sw client.state;
                            },
                        };

                        // Increment as much as written.
                        node.transferred += written;
                    }

                    _ = client.write_queue.pop();

                    // Invoke it on loop's completion queue, we want to have a predictable stack usage.
                    client.sendTransferToLoop(node);
                }

                // Handle read if requested.
                if (client.user_read_transfer) |transfer| {
                    const transferred = bssl.sslRead(client.ssl, transfer.sliceAt(0)) catch |err| switch (err) {
                        error.IoPending => return, // Retry later.
                        else => 0, // Handled in Transfer.callback.
                    };

                    // No need to sum.
                    transfer.transferred = transferred;

                    const completion: *Completion = @ptrCast(transfer);
                    @call(.auto, @as(Completion.Callback, @ptrCast(completion.callback)), .{ client.loop, completion });
                }
            },
            .closing => {
                // Empty write queue.
                while (client.write_queue.pop()) |node| {
                    node.is_eof = true;
                    const completion: *Completion = @ptrCast(node);
                    @call(.auto, @as(Completion.Callback, @ptrCast(completion.callback)), .{ client.loop, completion });
                }

                // TODO: If there's a read, fail it also.

                // Move to closed state.
                client.state = .closed;
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
                    error.ZeroReturn, error.Syscall => {
                        client.state = .closing;
                        continue :sw client.state;
                    },
                    else => unreachable,
                };

                // We should never get here since read buffer must be empty when this called.
                unreachable;
            },
            .negotiated => client.on_handshake.?(client, error.AlreadyNegotiated),
            .closing, .closed => client.on_handshake.?(client, error.Closed),
        }
    }

    /// Write to a TLS client, operation can be inlined if write queue is empty.
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
    ) void {
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

                    @call(.always_inline, on_done, .{
                        _completion.userdatum(T),
                        _completion,
                        _client,
                        _transfer.sliceAt(0),
                        if (_transfer.is_eof) error.EndOfStream else _transfer.transferred,
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

        // perf: If this is the only node in wq, try to inline the operation.
        // NOTE: Its possible to do it in `negotiating` phase too thanks to FALSE_START.
        sw: switch (client.state) {
            .unconnected => break :sw, // Can't inline here since raw_socket is not set.
            .negotiating, .negotiated => {
                // Can't inline.
                if (!client.write_queue.isEmpty()) break :sw;

                // Try to write everything.
                while (transfer.transferred < transfer.data.rw_const.len) {
                    const written = bssl.sslWrite(client.ssl, transfer.sliceAt(transfer.transferred)) catch |err| switch (err) {
                        // Inlining failed or we got partial write, continue in queue.
                        error.IoPending => break :sw,
                        else => @panic("TODO"),
                    };

                    transfer.transferred += written;
                }

                // Operation finished.
                return client.sendTransferToLoop(transfer);
            },
            .closing, .closed => unreachable,
        }

        // Can't inline, put in write queue instead.
        client.write_queue.push(transfer);
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

                    // Check if last read cause any errors.
                    const res: error{EndOfStream}!usize = blk: {
                        if (_client.read_comp.result < 0) break :blk error.EndOfStream;
                        break :blk _transfer.transferred;
                    };

                    @call(.always_inline, on_done, .{
                        _completion.userdatum(T),
                        _completion,
                        _client,
                        _transfer.sliceAt(0),
                        res,
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
            else => 0, // Any other error is handled in Transfer.callback.
        };

        // NOTE: This is the first time SSL_read called so no need to sum.
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
                        const written = result catch break :blk;
                        // EOF, we never provide zero-length buffers.
                        if (written == 0) break :blk;

                        // Decrease as much as written.
                        _client.write_len -= written;

                        // Move unwritten bytes to beginning.
                        // NOTE: These two slices must not overlap.
                        const beginning = _client.write_start[0.._client.write_len];
                        @memcpy(beginning, (_client.write_start + written)[0.._client.write_len]);

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
        _: *Completion,
        _: Socket,
        _: []u8,
        result: Loop.RecvError!usize,
    ) void {
        // Don't handle the error here, it will be taken care of in bio_read.
        const transferred = result catch @as(usize, 0);
        // Advance the read_len.
        client.read_len += transferred;

        // Continue state machine.
        @call(.always_inline, step, .{client});
    }

    /// Called internally by SSL.
    fn bio_read(_bio: ?*bssl.BIO, ptr: [*c]u8, len: c_int) callconv(.c) c_int {
        if (len < 0) unreachable;
        const bio = _bio.?;

        bssl.bioClearRetryFlags(bio);
        const client = clientFromBio(bio);

        // Check if the last recv completion failed.
        //
        // BIO_read attempts to read len bytes into data.
        // It returns the number of bytes read, zero on EOF,
        // or a negative number on error.
        const completion = client.getReadCompletion();
        // NOTE: connect and close calls handle the errors in their respective callbacks.
        // This one only cares errors that happened after successful negotiation.
        //
        // NOTE: We NEVER provide zero-sized buffers so result == 0 is just EOF.
        if (completion.result <= 0 and completion.isPending() == false and client.state == .negotiated) {
            return completion.result;
        }

        // If there's nothing in the read buffer, queue a read operation.
        if (client.read_len == 0) {
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

        // Handle previous send error if there was.
        const completion = client.getWriteCompletion();
        // NOTE: Make sure we never queue a zero-sized buffer.
        if (completion.result <= 0 and completion.isPending() == false and client.state == .negotiated) {
            return completion.result;
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
