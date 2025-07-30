const std = @import("std");
const jolt = @import("jolt");
const Loop = jolt.Loop;
const Completion = jolt.Loop.Completion;
const SecureContext = @import("SecurityContext.zig");
const bssl = @import("wrapper/boringssl.zig");

const tls = @import("tls.zig");

const allocator = std.heap.page_allocator;

threadlocal var stdout = std.io.bufferedWriter(std.io.getStdOut().writer());

const Callbacks = struct {
    fn on_socket_create(
        client: *tls.Client,
        loop: *Loop,
        completion: *Completion,
        result: Loop.SocketError!Loop.Socket,
    ) void {
        const socket = result catch unreachable;
        client.setSocket(socket);

        const addr = std.net.Address.initIp4(.{ 142, 250, 184, 142 }, 443);
        loop.connect(completion, tls.Client, client, socket, addr, on_connect);
    }

    fn on_connect(
        client: *tls.Client,
        _: *Loop,
        completion: *Completion,
        _: Loop.Socket,
        _: std.net.Address,
        result: Loop.ConnectError!void,
    ) void {
        result catch unreachable;

        client.handshake(on_handshake);
        client.write(
            completion,
            tls.Client,
            client,
            allocator.dupe(u8, "GET / HTTP/1.1\r\n\r\n") catch unreachable,
            on_write,
        );
    }

    fn on_handshake(client: *tls.Client, result: anyerror!void) void {
        _ = client;
        result catch unreachable;
    }

    fn on_write(
        _: *tls.Client,
        completion: *Completion,
        client: *tls.Client,
        _: []const u8,
        result: anyerror!usize,
    ) void {
        _ = result catch unreachable;
        allocator.free(completion.metadata.rw_const.base[0..completion.metadata.rw_const.len]);

        const buffer = allocator.alloc(u8, 2048) catch unreachable;
        client.read(completion, tls.Client, client, buffer, on_read);
    }

    fn on_read(
        _: *tls.Client,
        completion: *Completion,
        client: *tls.Client,
        slice: []u8,
        result: error{EndOfStream}!usize,
    ) void {
        const len = result catch unreachable;

        //std.debug.print("{s}\n", .{slice[0..len]});
        //_ = stdout.writer().writeAll(slice[0..len]) catch unreachable;

        if (len == 5) {
            std.posix.exit(0);
        }

        client.read(completion, tls.Client, client, slice, on_read);
    }
};

pub fn main() !void {
    const sec_ctx = try SecureContext.init();

    var loop = try Loop.init();
    defer loop.deinit();

    const client = try tls.Client.init(allocator, &loop, sec_ctx);
    defer client.deinit(allocator);

    var completion = Completion{};

    loop.openSocket(
        &completion,
        tls.Client,
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
