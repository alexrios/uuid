# uuid

RFC 9562 UUID library and CLI for Zig 0.15.2.

## Features

- All UUID versions: v1, v3, v4, v5, v6, v7, v8
- Nil and Max UUIDs
- Predefined namespace UUIDs (DNS, URL, OID, X.500)
- Parse (case-insensitive) and format (canonical lowercase 8-4-4-4-12)
- Lexicographic byte-order comparison
- Zero heap allocations
- Safety-critical: follows NASA/JPL Power of 10 rules with paired assertions

## Install (Homebrew)

```sh
brew install alexrios/tap/uuid
```

## Install (Zig package)

Add to your `build.zig.zon` dependencies:

```zig
.uuid = .{
    .url = "https://github.com/alexrios/uuid/archive/refs/tags/v0.1.0.tar.gz",
    .hash = "...",
},
```

Then in `build.zig`:

```zig
const uuid_dep = b.dependency("uuid", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("uuid", uuid_dep.module("uuid"));
```

## CLI Usage

```sh
# Generate UUIDs
uuid generate v4
uuid generate v7
uuid generate v5 --namespace dns --name "example.com"

# Parse and inspect
uuid parse "2ed6657d-e927-568b-95e1-2665a8aea6a2"
# UUID:    2ed6657d-e927-568b-95e1-2665a8aea6a2
# Version: 5 (Name-based SHA-1)
# Variant: RFC 9562
```

## Library Usage

```zig
const Uuid = @import("uuid").Uuid;

// Generate
const id = Uuid.v4();
const id7 = try Uuid.v7();

// Name-based (deterministic)
const id5 = Uuid.v5(Uuid.namespace_dns, "example.com");

// Parse and format
const parsed = try Uuid.parse("550e8400-e29b-41d4-a716-446655440000");
const str = parsed.toStr(); // [36]u8

// Compare
const ord = Uuid.order(a, b); // std.math.Order
const eq = a.eql(b);
```

## Development

Requires [mise](https://mise.jdx.dev/) for tool management.

```sh
mise install        # Install zig 0.15.2 + goreleaser
mise run test       # Run tests
mise run build      # Build
mise run fmt        # Format
mise run fmt-check  # Check formatting
```
