const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module (exposed for consumers via zig package manager)
    const uuid_mod = b.addModule("uuid", .{
        .root_source_file = b.path("src/uuid.zig"),
        .target = target,
        .optimize = optimize,
    });

    // CLI executable
    const exe = b.addExecutable(.{
        .name = "uuid",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "uuid", .module = uuid_mod },
            },
        }),
    });
    b.installArtifact(exe);

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the UUID CLI");
    run_step.dependOn(&run_cmd.step);

    // Tests for the library module
    const lib_tests = b.addTest(.{
        .root_module = uuid_mod,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    // Tests for the CLI module
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
