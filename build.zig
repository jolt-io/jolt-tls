const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const jolt_tls_mod = b.addModule("jolt-tls", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/root.zig"),
    });

    // TODO: Module specific configuration.
    // TODO: Custom allocators.
    // https://github.com/oven-sh/bun/blob/main/src/boringssl.zig#L46-L82

    const dep_opts = .{ .target = target, .optimize = optimize };

    // Get jolt module.
    const jolt_mod = b.dependency("jolt", dep_opts).module("jolt");
    jolt_tls_mod.addImport("jolt", jolt_mod);

    // Get boringssl-zig module.
    const @"boringssl-zig" = b.lazyDependency("boringssl-zig", .{
        .target = target,
        .optimize = optimize,
        .force_pic = false,
    });

    if (@"boringssl-zig") |dep| {
        const ssl = dep.artifact("ssl");
        const crypto = dep.artifact("crypto");
        ssl.bundle_ubsan_rt = true;
        crypto.bundle_ubsan_rt = true;

        // Link ssl and crypto.
        jolt_tls_mod.linkLibrary(ssl);
        jolt_tls_mod.linkLibrary(crypto);
    }

    const unit_tests = b.addTest(.{
        .root_module = jolt_tls_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
