# uuid

RFC 9562 UUIDs in Zig. Library and CLI.

I wanted a UUID implementation that doesn't allocate, doesn't panic on clock weirdness, and follows the actual spec instead of whatever half-baked subset most libraries ship. So I wrote one.

## install

```sh
brew install alexrios/tap/uuid
```

Or as a Zig dependency:

```sh
zig fetch --save git+https://github.com/alexrios/uuid
```

Then in your `build.zig`:

```zig
const uuid_dep = b.dependency("uuid", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("uuid", uuid_dep.module("uuid"));
```

## quick start

```zig
const std = @import("std");
const Uuid = @import("uuid").Uuid;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;

    const id = Uuid.v4(io);                                      // random
    const id7 = try Uuid.v7(io);                                 // time-sorted
    const id5 = Uuid.v5(Uuid.namespace_dns, "example.com");      // deterministic
    const parsed = try Uuid.parse("550e8400-e29b-41d4-a716-446655440000");

    for ([_][36]u8{ id.toStr(), id7.toStr(), id5.toStr(), parsed.toStr() }) |s| {
        try w.writeAll(&s);
        try w.writeAll("\n");
    }
    try w.flush();
}
```

There's also a CLI:

```sh
uuid generate v4
uuid generate v7
uuid generate v5 --namespace dns --name "example.com"
uuid parse "2ed6657d-e927-568b-95e1-2665a8aea6a2"
```

## what's in the box

- All UUID versions from RFC 9562: v1, v3, v4, v5, v6, v7, v8
- Nil and max UUIDs, namespace constants (DNS, URL, OID, X.500)
- Parse (case-insensitive) and format (canonical 8-4-4-4-12)
- Lexicographic byte-order comparison
- Zero heap allocations, single Zig file

## things you should know

**ClockStall.** v1, v6, and v7 can return `error.ClockStall`. This fires when you generate too many UUIDs too fast (>4096/ms for v7, >16384 per 100ns tick for v1/v6) or when the system clock misbehaves (VM migration, NTP step, CPU throttling). Don't `catch unreachable` it.

**Per-thread monotonicity.** Each thread has its own counter. UUIDs from different threads don't sort relative to each other.

**Distributed clocks.** v7 sort order depends on clock sync. If your machines disagree on the time, the UUIDs will sort wrong during the skew window.

## development

Requires [mise](https://mise.jdx.dev/).

```sh
mise install        # zig 0.16.0 + goreleaser
mise run test       # run tests
mise run build      # build
mise run fmt        # format
```
