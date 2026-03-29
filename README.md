# uuid

RFC 9562 UUIDs in Zig. Library and CLI.

I wanted a UUID implementation that doesn't allocate, doesn't panic on clock weirdness, and follows the actual spec instead of whatever half-baked subset most libraries ship. So I wrote one.

The whole thing follows [NASA/JPL's Power of 10](https://en.wikipedia.org/wiki/The_Power_of_10:_Rules_for_Developing_Safety-Critical_Code) rules and [TigerBeetle's paired assertion pattern](https://tigerbeetle.com/blog/2023-12-27-it-takes-two-to-contract/). No recursion, all loops bounded, every generator asserts its own output through an independent code path. 109 tests.

## what's in the box

All UUID versions from RFC 9562 (v1, v3, v4, v5, v6, v7, v8), plus nil/max, namespace constants (DNS, URL, OID, X.500), parsing, formatting, and comparison. Zero heap allocations. The whole thing is a single Zig file.

## install

Homebrew:

```sh
brew install alexrios/tap/uuid
```

As a Zig package (requires public repo access, or use a local path dep):

```zig
// build.zig.zon
.uuid = .{
    .url = "https://github.com/alexrios/uuid/archive/refs/tags/v0.2.0.tar.gz",
    .hash = "...",
},
```

```zig
// build.zig
const uuid_dep = b.dependency("uuid", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("uuid", uuid_dep.module("uuid"));
```

## CLI

```sh
uuid generate v4
uuid generate v7
uuid generate v5 --namespace dns --name "example.com"

uuid parse "2ed6657d-e927-568b-95e1-2665a8aea6a2"
# UUID:    2ed6657d-e927-568b-95e1-2665a8aea6a2
# Version: 5 (Name-based SHA-1)
# Variant: RFC 9562
```

## library

```zig
const Uuid = @import("uuid").Uuid;

const id = Uuid.v4();
const id7 = try Uuid.v7();
const id5 = Uuid.v5(Uuid.namespace_dns, "example.com");

const parsed = try Uuid.parse("550e8400-e29b-41d4-a716-446655440000");
const str = parsed.toStr(); // [36]u8

const ord = Uuid.order(a, b); // std.math.Order
```

## things you should know

v1, v6, and v7 can return `error.ClockStall`. This happens when the internal counter overflows and the system clock doesn't advance in time. In practice: more than 4096 v7 UUIDs in a single millisecond, or more than 16384 v1/v6 UUIDs in a single 100ns tick. Also happens if your clock is having a bad day (VM live migration, aggressive NTP step, CPU throttling).

Don't write `catch unreachable`. Handle the error.

Monotonicity is per-thread. Each OS thread has its own counter and timestamp state. UUIDs from different threads are not ordered relative to each other. If you need global ordering across threads, that's your problem to solve (and it's a hard one).

If you're using v7 across multiple machines and expecting sort order to mean something, your clocks need to agree. Clock skew between machines means the UUIDs will sort wrong during the skew window. NTP is your friend here.

## development

Requires [mise](https://mise.jdx.dev/).

```sh
mise install        # zig 0.15.2 + goreleaser
mise run test       # 109 tests
mise run build      # build
mise run fmt        # format
```
