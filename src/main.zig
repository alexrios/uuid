const std = @import("std");
const Uuid = @import("uuid").Uuid;

const usage =
    \\Usage: uuid <command> [options]
    \\
    \\Commands:
    \\  generate <version>  Generate a UUID (v1, v3, v4, v5, v6, v7, v8)
    \\  parse <uuid>        Parse and display UUID info
    \\
    \\Generate options:
    \\  --namespace <ns>    Namespace for v3/v5: dns, url, oid, x500, or a UUID string
    \\  --name <string>     Name for v3/v5
    \\
;

pub fn main() !void {
    var buf: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writerStreaming(&buf);
    const w = &stdout.interface;

    var args = std.process.args();
    const has_prog_name = args.skip();
    std.debug.assert(has_prog_name); // argv[0] must always exist

    const command = args.next() orelse {
        try w.writeAll(usage);
        try w.flush();
        return;
    };

    if (std.mem.eql(u8, command, "generate")) {
        try cmdGenerate(&args, w);
    } else if (std.mem.eql(u8, command, "parse")) {
        try cmdParse(&args, w);
    } else {
        try w.writeAll("Unknown command: ");
        try w.writeAll(command);
        try w.writeAll("\n");
        try w.writeAll(usage);
    }
    try w.flush();
}

fn cmdGenerate(args: *std.process.ArgIterator, w: *std.Io.Writer) !void {
    const version_str = args.next() orelse {
        try w.writeAll("Error: missing version argument\n");
        return;
    };

    // Collect optional flags for v3/v5
    var namespace: ?Uuid = null;
    var name: ?[]const u8 = null;

    // Bounded: max 16 CLI arguments (well above any realistic use)
    for (0..16) |_| {
        const arg = args.next() orelse break;
        if (std.mem.eql(u8, arg, "--namespace")) {
            const ns_str = args.next() orelse {
                try w.writeAll("Error: --namespace requires a value\n");
                return;
            };
            namespace = resolveNamespace(ns_str);
            if (namespace == null) {
                try w.writeAll("Error: invalid namespace '");
                try w.writeAll(ns_str);
                try w.writeAll("'\n");
                return;
            }
        } else if (std.mem.eql(u8, arg, "--name")) {
            name = args.next() orelse {
                try w.writeAll("Error: --name requires a value\n");
                return;
            };
        }
    }

    const uuid = generateUuid(version_str, namespace, name) catch |err| {
        switch (err) {
            error.UnknownVersion => {
                try w.writeAll("Error: unknown version '");
                try w.writeAll(version_str);
                try w.writeAll("'. Use: v1, v3, v4, v5, v6, v7, v8\n");
            },
            error.MissingNamespace => try w.writeAll("Error: v3/v5 require --namespace\n"),
            error.MissingName => try w.writeAll("Error: v3/v5 require --name\n"),
            error.ClockStall => try w.writeAll("Error: system clock stalled, could not generate v7 UUID\n"),
        }
        return;
    };

    const str = uuid.toStr();
    try w.writeAll(&str);
    try w.writeAll("\n");
}

const GenerateError = error{ UnknownVersion, MissingNamespace, MissingName, ClockStall };

fn generateUuid(version_str: []const u8, namespace: ?Uuid, name: ?[]const u8) GenerateError!Uuid {
    if (std.mem.eql(u8, version_str, "v1")) return try Uuid.v1(null);
    if (std.mem.eql(u8, version_str, "v3")) {
        const ns = namespace orelse return error.MissingNamespace;
        const n = name orelse return error.MissingName;
        return Uuid.v3(ns, n);
    }
    if (std.mem.eql(u8, version_str, "v4")) return Uuid.v4();
    if (std.mem.eql(u8, version_str, "v5")) {
        const ns = namespace orelse return error.MissingNamespace;
        const n = name orelse return error.MissingName;
        return Uuid.v5(ns, n);
    }
    if (std.mem.eql(u8, version_str, "v6")) return try Uuid.v6(null);
    if (std.mem.eql(u8, version_str, "v7")) return try Uuid.v7();
    if (std.mem.eql(u8, version_str, "v8")) return Uuid.v8(0, 0, 0);
    return error.UnknownVersion;
}

fn resolveNamespace(ns_str: []const u8) ?Uuid {
    if (std.mem.eql(u8, ns_str, "dns")) return Uuid.namespace_dns;
    if (std.mem.eql(u8, ns_str, "url")) return Uuid.namespace_url;
    if (std.mem.eql(u8, ns_str, "oid")) return Uuid.namespace_oid;
    if (std.mem.eql(u8, ns_str, "x500")) return Uuid.namespace_x500;
    return Uuid.parse(ns_str) catch null;
}

fn cmdParse(args: *std.process.ArgIterator, w: *std.Io.Writer) !void {
    const uuid_str = args.next() orelse {
        try w.writeAll("Error: missing UUID argument\n");
        return;
    };

    const uuid = Uuid.parse(uuid_str) catch {
        try w.writeAll("Error: invalid UUID '");
        try w.writeAll(uuid_str);
        try w.writeAll("'\n");
        return;
    };

    const canonical = uuid.toStr();
    try w.writeAll("UUID:    ");
    try w.writeAll(&canonical);
    try w.writeAll("\n");

    try w.writeAll("Version: ");
    if (uuid.getVersion()) |ver| {
        try w.writeAll(switch (ver) {
            .time_based => "1 (Gregorian time-based)",
            .name_based_md5 => "3 (Name-based MD5)",
            .random => "4 (Random)",
            .name_based_sha1 => "5 (Name-based SHA-1)",
            .time_based_reordered => "6 (Reordered Gregorian time-based)",
            .time_based_unix => "7 (Unix epoch time-based)",
            .custom => "8 (Custom)",
        });
    } else {
        try w.writeAll("Unknown");
    }
    try w.writeAll("\n");

    try w.writeAll("Variant: ");
    try w.writeAll(switch (uuid.getVariant()) {
        .rfc9562 => "RFC 9562",
        .reserved_ncs => "Reserved (NCS)",
        .reserved_microsoft => "Reserved (Microsoft)",
        .reserved_future => "Reserved (Future)",
    });
    try w.writeAll("\n");

    // Show if nil or max
    if (uuid.eql(Uuid.nil)) {
        try w.writeAll("Special: Nil UUID\n");
    } else if (uuid.eql(Uuid.max)) {
        try w.writeAll("Special: Max UUID\n");
    }
}

// ===================================================================
// Tests for pure CLI functions
// ===================================================================

const testing = std.testing;

test "generateUuid: all valid versions produce correct version" {
    const cases = [_]struct { ver: []const u8, expected: Uuid.Version }{
        .{ .ver = "v4", .expected = .random },
        .{ .ver = "v8", .expected = .custom },
    };
    for (cases) |c| {
        const uuid = try generateUuid(c.ver, null, null);
        try testing.expectEqual(c.expected, uuid.getVersion().?);
    }
}

test "generateUuid: v3 requires namespace and name" {
    try testing.expectError(error.MissingNamespace, generateUuid("v3", null, "foo"));
    try testing.expectError(error.MissingName, generateUuid("v3", Uuid.namespace_dns, null));
}

test "generateUuid: v5 requires namespace and name" {
    try testing.expectError(error.MissingNamespace, generateUuid("v5", null, "foo"));
    try testing.expectError(error.MissingName, generateUuid("v5", Uuid.namespace_dns, null));
}

test "generateUuid: v3 with namespace and name succeeds" {
    const uuid = try generateUuid("v3", Uuid.namespace_dns, "example.com");
    try testing.expectEqual(Uuid.Version.name_based_md5, uuid.getVersion().?);
}

test "generateUuid: v5 with namespace and name succeeds" {
    const uuid = try generateUuid("v5", Uuid.namespace_dns, "example.com");
    try testing.expectEqual(Uuid.Version.name_based_sha1, uuid.getVersion().?);
}

test "generateUuid: unknown version returns error" {
    try testing.expectError(error.UnknownVersion, generateUuid("v9", null, null));
    try testing.expectError(error.UnknownVersion, generateUuid("", null, null));
    try testing.expectError(error.UnknownVersion, generateUuid("v2", null, null));
}

test "resolveNamespace: named namespaces" {
    try testing.expect(resolveNamespace("dns").?.eql(Uuid.namespace_dns));
    try testing.expect(resolveNamespace("url").?.eql(Uuid.namespace_url));
    try testing.expect(resolveNamespace("oid").?.eql(Uuid.namespace_oid));
    try testing.expect(resolveNamespace("x500").?.eql(Uuid.namespace_x500));
}

test "resolveNamespace: UUID string" {
    const ns = resolveNamespace("6ba7b810-9dad-11d1-80b4-00c04fd430c8").?;
    try testing.expect(ns.eql(Uuid.namespace_dns));
}

test "resolveNamespace: invalid string returns null" {
    try testing.expectEqual(@as(?Uuid, null), resolveNamespace("garbage"));
    try testing.expectEqual(@as(?Uuid, null), resolveNamespace(""));
}
