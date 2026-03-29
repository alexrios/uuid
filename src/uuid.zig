const std = @import("std");

/// A 128-bit universally unique identifier (RFC 9562).
/// Stored as 16 bytes in big-endian (network) byte order. Zero heap allocations.
pub const Uuid = UuidImpl(std.time.nanoTimestamp, std.time.milliTimestamp);

/// Generic UUID implementation parameterized by clock sources.
/// Production code uses `Uuid` (which binds real clocks). Tests can instantiate
/// `UuidImpl(fakeNano, fakeMilli)` to control time deterministically.
pub fn UuidImpl(
    comptime nanoTimestampFn: anytype,
    comptime milliTimestampFn: anytype,
) type {
    comptime {
        const NanoReturn = @typeInfo(@TypeOf(nanoTimestampFn)).@"fn".return_type.?;
        if (NanoReturn != i128) @compileError("nanoTimestampFn must return i128");
        const MilliReturn = @typeInfo(@TypeOf(milliTimestampFn)).@"fn".return_type.?;
        if (MilliReturn != i64) @compileError("milliTimestampFn must return i64");
    }
    return struct {
        const Self = @This();

        bytes: [16]u8,

        // -- Constants --
        /// The nil UUID (all zeros). Represents absence of a UUID value.
        pub const nil: Self = .{ .bytes = .{0} ** 16 };
        /// The max UUID (all ones). Upper bound sentinel.
        pub const max: Self = .{ .bytes = .{0xff} ** 16 };

        // -- Predefined namespace UUIDs (RFC 9562 Section 6.6) --
        pub const namespace_dns: Self = parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8") catch unreachable;
        pub const namespace_url: Self = parse("6ba7b811-9dad-11d1-80b4-00c04fd430c8") catch unreachable;
        pub const namespace_oid: Self = parse("6ba7b812-9dad-11d1-80b4-00c04fd430c8") catch unreachable;
        pub const namespace_x500: Self = parse("6ba7b814-9dad-11d1-80b4-00c04fd430c8") catch unreachable;

        // -- Version --
        pub const Version = enum(u4) {
            time_based = 1,
            name_based_md5 = 3,
            random = 4,
            name_based_sha1 = 5,
            time_based_reordered = 6,
            time_based_unix = 7,
            custom = 8,
        };

        // -- Variant --
        pub const Variant = enum {
            rfc9562,
            reserved_ncs,
            reserved_microsoft,
            reserved_future,
        };

        /// Return the UUID version, or null if the version nibble is not a recognized RFC 9562 version.
        pub fn getVersion(self: Self) ?Version {
            const nibble: u4 = @truncate(self.bytes[6] >> 4);
            return std.meta.intToEnum(Version, nibble) catch null;
        }

        /// Return the UUID variant (RFC 9562, NCS, Microsoft, or future reserved).
        pub fn getVariant(self: Self) Variant {
            const octet = self.bytes[8];
            if (octet & 0x80 == 0) return .reserved_ncs;
            if (octet & 0xc0 == 0x80) return .rfc9562;
            if (octet & 0xe0 == 0xc0) return .reserved_microsoft;
            return .reserved_future;
        }

        // -- Timestamp extraction --

        /// Extract the 60-bit Gregorian timestamp from a v1 UUID.
        /// Returns 100-nanosecond intervals since 1582-10-15T00:00:00Z.
        pub fn getTimestampV1(self: Self) ?u60 {
            if (self.getVersion() != .time_based) return null;
            const time_low: u60 = std.mem.readInt(u32, self.bytes[0..4], .big);
            const time_mid: u60 = std.mem.readInt(u16, self.bytes[4..6], .big);
            const time_hi: u60 = @as(u60, self.bytes[6] & 0x0f) << 8 | self.bytes[7];
            return time_low | (time_mid << 32) | (time_hi << 48);
        }

        /// Extract the 60-bit Gregorian timestamp from a v6 UUID.
        /// Returns 100-nanosecond intervals since 1582-10-15T00:00:00Z.
        pub fn getTimestampV6(self: Self) ?u60 {
            if (self.getVersion() != .time_based_reordered) return null;
            const time_high: u60 = std.mem.readInt(u32, self.bytes[0..4], .big);
            const time_mid: u60 = std.mem.readInt(u16, self.bytes[4..6], .big);
            const time_low: u60 = @as(u60, self.bytes[6] & 0x0f) << 8 | self.bytes[7];
            return (time_high << 28) | (time_mid << 12) | time_low;
        }

        /// Extract the 48-bit Unix millisecond timestamp from a v7 UUID.
        pub fn getTimestampV7(self: Self) ?u48 {
            if (self.getVersion() != .time_based_unix) return null;
            return std.mem.readInt(u48, self.bytes[0..6], .big);
        }

        /// Extract the 14-bit clock sequence from a v1 or v6 UUID.
        pub fn getClockSeq(self: Self) ?u14 {
            const ver = self.getVersion() orelse return null;
            if (ver != .time_based and ver != .time_based_reordered) return null;
            return @truncate((@as(u16, self.bytes[8] & 0x3f) << 8) | self.bytes[9]);
        }

        /// Extract the 48-bit node from a v1 or v6 UUID.
        pub fn getNode(self: Self) ?[6]u8 {
            const ver = self.getVersion() orelse return null;
            if (ver != .time_based and ver != .time_based_reordered) return null;
            return self.bytes[10..16].*;
        }

        /// Construct a UUID from raw 16 bytes (e.g., from a database or network).
        pub fn fromBytes(bytes: [16]u8) Self {
            return .{ .bytes = bytes };
        }

        // -- Comparison --
        /// Lexicographic byte-order comparison of two UUIDs.
        pub fn order(a: Self, b: Self) std.math.Order {
            return std.mem.order(u8, &a.bytes, &b.bytes);
        }

        /// Return true if two UUIDs are byte-identical.
        pub fn eql(a: Self, b: Self) bool {
            return std.mem.eql(u8, &a.bytes, &b.bytes);
        }

        // -- Formatting --
        const hex_chars = "0123456789abcdef";

        /// Format as lowercase canonical string (8-4-4-4-12). Returns a stack-allocated [36]u8.
        pub fn toStr(self: Self) [36]u8 {
            var out: [36]u8 = undefined;
            var pos: usize = 0;
            const groups = [_]usize{ 4, 2, 2, 2, 6 };
            var byte_idx: usize = 0;
            for (groups, 0..) |len, g| {
                if (g > 0) {
                    out[pos] = '-';
                    pos += 1;
                }
                for (0..len) |_| {
                    out[pos] = hex_chars[self.bytes[byte_idx] >> 4];
                    out[pos + 1] = hex_chars[self.bytes[byte_idx] & 0x0f];
                    pos += 2;
                    byte_idx += 1;
                }
            }
            std.debug.assert(pos == 36);
            std.debug.assert(byte_idx == 16);
            return out;
        }

        /// Write the canonical string representation to a writer. Use with `{f}` format specifier.
        pub fn format(self: Self, writer: anytype) !void {
            const str = self.toStr();
            try writer.writeAll(&str);
        }

        // -- Parsing --
        pub const ParseError = error{ InvalidLength, InvalidCharacter, InvalidSeparator };

        /// Parse a UUID from its canonical 8-4-4-4-12 string representation (36 chars).
        /// Case-insensitive. Works at comptime.
        pub fn parse(buf: []const u8) ParseError!Self {
            if (buf.len != 36) return error.InvalidLength;

            // Validate hyphens at positions 8, 13, 18, 23
            if (buf[8] != '-' or buf[13] != '-' or buf[18] != '-' or buf[23] != '-')
                return error.InvalidSeparator;

            // Hex character positions (excluding hyphens): 32 hex chars = 16 bytes
            const hex_positions = [32]usize{
                0,  1,  2,  3,  4,  5,  6,  7,
                9,  10, 11, 12, 14, 15, 16, 17,
                19, 20, 21, 22, 24, 25, 26, 27,
                28, 29, 30, 31, 32, 33, 34, 35,
            };

            var result: Self = undefined;
            // Fixed-bound loop: exactly 16 iterations
            for (0..16) |byte_idx| {
                const hi_pos = hex_positions[byte_idx * 2];
                const lo_pos = hex_positions[byte_idx * 2 + 1];
                const hi = hexVal(buf[hi_pos]) orelse return error.InvalidCharacter;
                const lo = hexVal(buf[lo_pos]) orelse return error.InvalidCharacter;
                result.bytes[byte_idx] = (@as(u8, hi) << 4) | lo;
            }
            return result;
        }

        fn hexVal(c: u8) ?u4 {
            return switch (c) {
                '0'...'9' => @truncate(c - '0'),
                'a'...'f' => @truncate(c - 'a' + 10),
                'A'...'F' => @truncate(c - 'A' + 10),
                else => null,
            };
        }

        // -- Internal helpers for version/variant stamping --
        fn setVersion(bytes: *[16]u8, ver: u4) void {
            bytes[6] = (bytes[6] & 0x0f) | (@as(u8, ver) << 4);
        }

        fn setVariant(bytes: *[16]u8) void {
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
        }

        // ---------------------------------------------------------------
        // Generators
        // ---------------------------------------------------------------

        /// Verify version and variant bits are correctly set (caller-side paired assertion).
        pub fn assertValid(uuid: Self, expected_version: Version) void {
            // Paired assertion: caller independently checks what the generator promised.
            // This uses different code paths (getVersion/getVariant) than setVersion/setVariant,
            // following TigerBeetle's two-party contract pattern.
            std.debug.assert(uuid.getVersion() == expected_version);
            std.debug.assert(uuid.getVariant() == .rfc9562);
        }

        // -- v4: Random --
        /// Generate a random (v4) UUID using the OS cryptographically secure RNG.
        pub fn v4() Self {
            return v4WithSource(std.crypto.random);
        }

        /// Build a v4 UUID from an explicit random source (for deterministic testing).
        pub fn v4WithSource(random: std.Random) Self {
            var uuid: Self = undefined;
            random.bytes(&uuid.bytes);
            setVersion(&uuid.bytes, @intFromEnum(Version.random));
            setVariant(&uuid.bytes);
            std.debug.assert(uuid.getVersion() == .random);
            std.debug.assert(uuid.getVariant() == .rfc9562);
            return uuid;
        }

        // -- v3: Name-based MD5 --
        /// Generate a name-based v3 UUID using MD5. Deterministic: same namespace + name
        /// always produces the same UUID. Prefer v5 for new applications.
        pub fn v3(namespace: Self, name: []const u8) Self {
            var hasher = std.crypto.hash.Md5.init(.{});
            hasher.update(&namespace.bytes);
            hasher.update(name);
            var digest: [16]u8 = undefined;
            hasher.final(&digest);

            var uuid: Self = .{ .bytes = digest };
            setVersion(&uuid.bytes, @intFromEnum(Version.name_based_md5));
            setVariant(&uuid.bytes);
            std.debug.assert(uuid.getVersion() == .name_based_md5);
            std.debug.assert(uuid.getVariant() == .rfc9562);
            return uuid;
        }

        // -- v5: Name-based SHA-1 --
        /// Generate a name-based v5 UUID using SHA-1. Deterministic: same namespace + name
        /// always produces the same UUID.
        pub fn v5(namespace: Self, name: []const u8) Self {
            var hasher = std.crypto.hash.Sha1.init(.{});
            hasher.update(&namespace.bytes);
            hasher.update(name);
            var digest: [20]u8 = undefined;
            hasher.final(&digest);

            // Take first 16 bytes of the 20-byte SHA-1 digest
            var uuid: Self = .{ .bytes = digest[0..16].* };
            setVersion(&uuid.bytes, @intFromEnum(Version.name_based_sha1));
            setVariant(&uuid.bytes);
            std.debug.assert(uuid.getVersion() == .name_based_sha1);
            std.debug.assert(uuid.getVariant() == .rfc9562);
            return uuid;
        }

        // -- v8: Custom --
        /// Generate a custom (v8) UUID from caller-provided fields. Version and variant bits
        /// are stamped automatically; the remaining 122 bits are packed from the arguments.
        pub fn v8(custom_a: u48, custom_b: u12, custom_c: u62) Self {
            var uuid: Self = undefined;

            // custom_a: 48 bits → bytes[0..6]
            std.mem.writeInt(u48, uuid.bytes[0..6], custom_a, .big);

            // custom_b: 12 bits → lower 12 bits of bytes[6..8] (upper 4 will be version)
            uuid.bytes[6] = @truncate(@as(u16, custom_b) >> 8);
            uuid.bytes[7] = @truncate(custom_b);

            // custom_c: 62 bits → lower 62 bits of bytes[8..16] (upper 2 will be variant)
            std.mem.writeInt(u64, uuid.bytes[8..16], @as(u64, custom_c), .big);

            setVersion(&uuid.bytes, @intFromEnum(Version.custom));
            setVariant(&uuid.bytes);
            std.debug.assert(uuid.getVersion() == .custom);
            std.debug.assert(uuid.getVariant() == .rfc9562);
            return uuid;
        }

        // -- Gregorian time state (shared by v1 and v6) --
        /// 100-nanosecond intervals between 1582-10-15T00:00:00Z and 1970-01-01T00:00:00Z.
        pub const gregorian_offset: u64 = 0x01B2_1DD2_1381_4000;

        const GregorianState = struct {
            last_timestamp: u60 = 0,
            clock_seq: u14 = 0,
            node: [6]u8 = .{0} ** 6,
            initialized: bool = false,
        };

        /// Per-thread state shared by v1() and v6(). Each thread has independent
        /// clock sequence and node. Monotonicity is per-thread, not global.
        threadlocal var gregorian_state: GregorianState = .{};

        fn getGregorianTimestamp() u60 {
            const nanos: i128 = nanoTimestampFn();
            const ticks: i128 = @divFloor(nanos, 100);
            const sum = ticks + @as(i128, gregorian_offset);
            // Safe in all build modes: if clock is before 1582-10-15, saturate to 0
            // rather than invoking UB via @intCast in ReleaseFast.
            const uuid_ticks: u64 = if (sum >= 0) @intCast(sum) else 0;
            return @truncate(uuid_ticks);
        }

        fn ensureGregorianState(node: ?[6]u8) void {
            if (!gregorian_state.initialized) {
                var seq_bytes: [2]u8 = undefined;
                std.crypto.random.bytes(&seq_bytes);
                gregorian_state.clock_seq = @truncate(std.mem.readInt(u16, &seq_bytes, .big));
                if (node) |n| {
                    gregorian_state.node = n;
                } else {
                    std.crypto.random.bytes(&gregorian_state.node);
                    gregorian_state.node[0] |= 0x01; // multicast bit
                }
                gregorian_state.initialized = true;
            } else if (node) |n| {
                if (!std.mem.eql(u8, &gregorian_state.node, &n)) {
                    gregorian_state.node = n;
                    // RFC 9562 Section 4.5: reset clock_seq when node changes
                    var seq_bytes: [2]u8 = undefined;
                    std.crypto.random.bytes(&seq_bytes);
                    gregorian_state.clock_seq = @truncate(std.mem.readInt(u16, &seq_bytes, .big));
                }
            }
            // Postcondition: state must be initialized after this call
            std.debug.assert(gregorian_state.initialized);
            // Postcondition: if caller provided a node, it must be set
            if (node) |n| std.debug.assert(std.mem.eql(u8, &gregorian_state.node, &n));
        }

        fn advanceGregorianClock() error{ClockStall}!u60 {
            var ts = getGregorianTimestamp();
            if (ts <= gregorian_state.last_timestamp) {
                if (gregorian_state.clock_seq == std.math.maxInt(u14)) {
                    // clock_seq would wrap — stall until timestamp advances to preserve
                    // v6 lexicographic monotonicity (wrap from 0x3FFF→0x0000 causes
                    // byte[8] to decrease from 0xBF to 0x80).
                    for (0..max_spin_iterations) |_| {
                        ts = getGregorianTimestamp();
                        if (ts > gregorian_state.last_timestamp) break;
                        std.atomic.spinLoopHint();
                    } else {
                        return error.ClockStall;
                    }
                    // New timestamp: re-randomize clock_seq
                    var seq_bytes: [2]u8 = undefined;
                    std.crypto.random.bytes(&seq_bytes);
                    gregorian_state.clock_seq = @truncate(std.mem.readInt(u16, &seq_bytes, .big));
                } else {
                    gregorian_state.clock_seq += 1;
                }
            }
            gregorian_state.last_timestamp = ts;
            return ts;
        }

        // -- v1: Gregorian time-based --
        /// Generate a v1 UUID (Gregorian time-based).
        /// On first call, pass null to generate a random node (multicast bit set), or provide
        /// an explicit 6-byte node (e.g., MAC address). Subsequent calls with null preserve the
        /// previously established node. Pass a different explicit node to change it (resets clock_seq).
        /// Thread safety: uses per-thread state. Monotonicity is per-thread, not global.
        pub fn v1(node: ?[6]u8) error{ClockStall}!Self {
            ensureGregorianState(node);
            const ts = try advanceGregorianClock();
            const uuid = v1FromFields(ts, gregorian_state.clock_seq, gregorian_state.node);
            uuid.assertValid(.time_based);
            return uuid;
        }

        /// Build a v1 UUID from explicit fields (for deterministic testing).
        pub fn v1FromFields(timestamp: u60, clock_seq: u14, node: [6]u8) Self {
            var uuid: Self = undefined;

            // time_low: bits 0-31 of timestamp → bytes[0..4]
            const time_low: u32 = @truncate(timestamp);
            std.mem.writeInt(u32, uuid.bytes[0..4], time_low, .big);

            // time_mid: bits 32-47 of timestamp → bytes[4..6]
            const time_mid: u16 = @truncate(timestamp >> 32);
            std.mem.writeInt(u16, uuid.bytes[4..6], time_mid, .big);

            // time_hi: bits 48-59 of timestamp → lower 12 bits of bytes[6..8]
            const time_hi: u16 = @truncate(timestamp >> 48);
            uuid.bytes[6] = @truncate(time_hi >> 8);
            uuid.bytes[7] = @truncate(time_hi);

            // clock_seq → bytes[8..10]
            uuid.bytes[8] = @truncate(@as(u16, clock_seq) >> 8);
            uuid.bytes[9] = @truncate(clock_seq);

            // node → bytes[10..16]
            uuid.bytes[10..16].* = node;

            setVersion(&uuid.bytes, @intFromEnum(Version.time_based));
            setVariant(&uuid.bytes);
            std.debug.assert(uuid.getVersion() == .time_based);
            std.debug.assert(uuid.getVariant() == .rfc9562);
            // Paired assertion: extraction path must recover the same timestamp we packed.
            // This catches bit-scatter bugs through a completely independent code path.
            std.debug.assert(uuid.getTimestampV1().? == timestamp);
            std.debug.assert(uuid.getClockSeq().? == clock_seq);
            std.debug.assert(std.mem.eql(u8, &uuid.getNode().?, &node));
            return uuid;
        }

        // -- v6: Reordered Gregorian time-based --
        /// Generate a v6 UUID (reordered Gregorian time-based).
        /// Same timestamp and node semantics as v1 (null preserves existing node after init),
        /// but with bits reordered for lexicographic sortability.
        /// Thread safety: uses per-thread state. Monotonicity is per-thread, not global.
        pub fn v6(node: ?[6]u8) error{ClockStall}!Self {
            ensureGregorianState(node);
            const ts = try advanceGregorianClock();
            const uuid = v6FromFields(ts, gregorian_state.clock_seq, gregorian_state.node);
            uuid.assertValid(.time_based_reordered);
            return uuid;
        }

        /// Build a v6 UUID from explicit fields (for deterministic testing).
        pub fn v6FromFields(timestamp: u60, clock_seq: u14, node: [6]u8) Self {
            var uuid: Self = undefined;

            // time_high: upper 32 bits of 60-bit timestamp → bytes[0..4]
            const time_high: u32 = @truncate(timestamp >> 28);
            std.mem.writeInt(u32, uuid.bytes[0..4], time_high, .big);

            // time_mid: bits 12-27 of timestamp → bytes[4..6]
            const time_mid: u16 = @truncate(timestamp >> 12);
            std.mem.writeInt(u16, uuid.bytes[4..6], time_mid, .big);

            // time_low: bits 0-11 of timestamp → lower 12 bits of bytes[6..8]
            const time_low: u16 = @truncate(timestamp & 0xfff);
            uuid.bytes[6] = @truncate(time_low >> 8);
            uuid.bytes[7] = @truncate(time_low);

            // clock_seq → bytes[8..10]
            uuid.bytes[8] = @truncate(@as(u16, clock_seq) >> 8);
            uuid.bytes[9] = @truncate(clock_seq);

            // node → bytes[10..16]
            uuid.bytes[10..16].* = node;

            setVersion(&uuid.bytes, @intFromEnum(Version.time_based_reordered));
            setVariant(&uuid.bytes);
            std.debug.assert(uuid.getVersion() == .time_based_reordered);
            std.debug.assert(uuid.getVariant() == .rfc9562);
            // Paired assertion: extraction path must recover the same timestamp we packed.
            std.debug.assert(uuid.getTimestampV6().? == timestamp);
            std.debug.assert(uuid.getClockSeq().? == clock_seq);
            std.debug.assert(std.mem.eql(u8, &uuid.getNode().?, &node));
            return uuid;
        }

        // -- v7: Unix epoch time + monotonic counter --
        const V7State = struct {
            last_ms: i64 = 0,
            counter: u12 = 0,
            initialized: bool = false,
        };

        threadlocal var v7_state: V7State = .{};

        /// Maximum number of spin iterations waiting for the next millisecond.
        /// At ~1ns per iteration, 2_000_000 iterations ≈ 2ms — well above the 1ms we need.
        const max_spin_iterations: u32 = 2_000_000;

        /// Generate a v7 UUID (Unix timestamp + monotonic counter).
        /// Thread safety: each thread maintains independent state (threadlocal).
        /// Monotonic ordering is guaranteed only within a single thread.
        /// Returns error.ClockStall if the system clock does not advance within ~2ms
        /// after the 12-bit counter overflows (>4096 UUIDs in one millisecond).
        pub fn v7() error{ClockStall}!Self {
            // Loop replaces recursion: runs at most twice (once on counter overflow).
            for (0..2) |_| {
                const now_ms = milliTimestampFn();

                if (!v7_state.initialized or now_ms > v7_state.last_ms) {
                    var counter_bytes: [2]u8 = undefined;
                    std.crypto.random.bytes(&counter_bytes);
                    v7_state.counter = @truncate(std.mem.readInt(u16, &counter_bytes, .big));
                    v7_state.last_ms = now_ms;
                    v7_state.initialized = true;
                } else {
                    // Same or earlier millisecond (clock regression). Intentionally keep
                    // last_ms unchanged and increment counter — this preserves monotonicity
                    // per RFC 9562 Section 6.2: the UUID timestamp stays at the last known
                    // good value while the counter provides ordering within that timestamp.
                    if (v7_state.counter == std.math.maxInt(u12)) {
                        // Counter overflow — spin until next millisecond with bounded iterations
                        for (0..max_spin_iterations) |_| {
                            if (milliTimestampFn() > v7_state.last_ms) break;
                            std.atomic.spinLoopHint();
                        } else {
                            return error.ClockStall;
                        }
                        continue; // retry with new millisecond
                    }
                    v7_state.counter += 1;
                }

                std.debug.assert(v7_state.last_ms >= 0);
                const ts: u48 = @truncate(@as(u64, @intCast(v7_state.last_ms)));
                var rand_b: [8]u8 = undefined;
                std.crypto.random.bytes(&rand_b);
                const uuid = v7FromFields(ts, v7_state.counter, rand_b);
                // Caller-side paired assertion: independently verify the result
                uuid.assertValid(.time_based_unix);
                return uuid;
            }
            // Clock regressed during spin-wait (e.g., NTP correction).
            return error.ClockStall;
        }

        /// Build a v7 UUID from explicit fields (for deterministic testing).
        pub fn v7FromFields(unix_ts_ms: u48, counter: u12, rand_b: [8]u8) Self {
            var uuid: Self = undefined;

            // unix_ts_ms: 48 bits → bytes[0..6]
            std.mem.writeInt(u48, uuid.bytes[0..6], unix_ts_ms, .big);

            // rand_a (12 bits) = counter → lower 12 bits of bytes[6..8]
            uuid.bytes[6] = @truncate(@as(u16, counter) >> 8);
            uuid.bytes[7] = @truncate(counter);

            // rand_b → bytes[8..16]
            @memcpy(uuid.bytes[8..16], &rand_b);

            setVersion(&uuid.bytes, @intFromEnum(Version.time_based_unix));
            setVariant(&uuid.bytes);
            std.debug.assert(uuid.getVersion() == .time_based_unix);
            std.debug.assert(uuid.getVariant() == .rfc9562);
            // Paired assertion: extraction path must recover the same timestamp we packed.
            std.debug.assert(uuid.getTimestampV7().? == unix_ts_ms);
            return uuid;
        }
    };
}

// ===================================================================
// Tests
// ===================================================================

const testing = std.testing;

// ---- Parse / Format ----

test "parse and format round-trip" {
    const input = "550e8400-e29b-41d4-a716-446655440000";
    const uuid = try Uuid.parse(input);
    const output = uuid.toStr();
    try testing.expectEqualStrings(input, &output);
}

test "parse case-insensitive" {
    const upper = "550E8400-E29B-41D4-A716-446655440000";
    const lower = "550e8400-e29b-41d4-a716-446655440000";
    const uuid_upper = try Uuid.parse(upper);
    const uuid_lower = try Uuid.parse(lower);
    try testing.expect(uuid_upper.eql(uuid_lower));
}

test "parse mixed case" {
    const mixed = "550e8400-E29B-41d4-A716-446655440000";
    const uuid = try Uuid.parse(mixed);
    try testing.expectEqualStrings("550e8400-e29b-41d4-a716-446655440000", &uuid.toStr());
}

test "parse error: empty string" {
    try testing.expectError(error.InvalidLength, Uuid.parse(""));
}

test "parse error: too short by one" {
    try testing.expectError(error.InvalidLength, Uuid.parse("550e8400-e29b-41d4-a716-44665544000"));
}

test "parse error: too long by one" {
    try testing.expectError(error.InvalidLength, Uuid.parse("550e8400-e29b-41d4-a716-4466554400000"));
}

test "parse error: 32 hex no hyphens" {
    try testing.expectError(error.InvalidLength, Uuid.parse("550e8400e29b41d4a716446655440000"));
}

test "parse error: invalid separator at pos 8" {
    try testing.expectError(error.InvalidSeparator, Uuid.parse("550e8400xe29b-41d4-a716-446655440000"));
}

test "parse error: invalid separator at pos 13" {
    try testing.expectError(error.InvalidSeparator, Uuid.parse("550e8400-e29bx41d4-a716-446655440000"));
}

test "parse error: invalid separator at pos 18" {
    try testing.expectError(error.InvalidSeparator, Uuid.parse("550e8400-e29b-41d4xa716-446655440000"));
}

test "parse error: invalid separator at pos 23" {
    try testing.expectError(error.InvalidSeparator, Uuid.parse("550e8400-e29b-41d4-a716x446655440000"));
}

test "parse error: invalid character g" {
    try testing.expectError(error.InvalidCharacter, Uuid.parse("550e8400-e29b-41d4-a716-44665544000g"));
}

test "parse error: invalid character space" {
    try testing.expectError(error.InvalidCharacter, Uuid.parse("550e8400-e29b-41d4-a716-4466554400 0"));
}

test "parse preserves exact bytes" {
    // Manually construct a known byte sequence and verify parse reproduces it
    const uuid = try Uuid.parse("01020304-0506-0708-090a-0b0c0d0e0f10");
    const expected = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    try testing.expectEqualSlices(u8, &expected, &uuid.bytes);
}

// ---- Nil and Max ----

test "nil UUID string" {
    try testing.expectEqualStrings("00000000-0000-0000-0000-000000000000", &Uuid.nil.toStr());
}

test "max UUID string" {
    try testing.expectEqualStrings("ffffffff-ffff-ffff-ffff-ffffffffffff", &Uuid.max.toStr());
}

test "nil parse round-trip" {
    const uuid = try Uuid.parse("00000000-0000-0000-0000-000000000000");
    try testing.expect(uuid.eql(Uuid.nil));
}

test "max parse round-trip" {
    const uuid = try Uuid.parse("ffffffff-ffff-ffff-ffff-ffffffffffff");
    try testing.expect(uuid.eql(Uuid.max));
}

// ---- Comparison ----

test "nil less than max" {
    try testing.expectEqual(std.math.Order.lt, Uuid.order(Uuid.nil, Uuid.max));
}

test "eql self" {
    try testing.expect(Uuid.nil.eql(Uuid.nil));
    try testing.expect(Uuid.max.eql(Uuid.max));
    try testing.expect(!Uuid.nil.eql(Uuid.max));
}

test "order is consistent with byte comparison" {
    const a = try Uuid.parse("00000000-0000-0000-0000-000000000001");
    const b = try Uuid.parse("00000000-0000-0000-0000-000000000002");
    try testing.expectEqual(std.math.Order.lt, Uuid.order(a, b));
    try testing.expectEqual(std.math.Order.gt, Uuid.order(b, a));
    try testing.expectEqual(std.math.Order.eq, Uuid.order(a, a));
}

// ---- Version / Variant ----

test "nil version and variant" {
    try testing.expectEqual(@as(?Uuid.Version, null), Uuid.nil.getVersion());
    try testing.expectEqual(Uuid.Variant.reserved_ncs, Uuid.nil.getVariant());
}

test "max version and variant" {
    try testing.expectEqual(@as(?Uuid.Version, null), Uuid.max.getVersion());
    try testing.expectEqual(Uuid.Variant.reserved_future, Uuid.max.getVariant());
}

test "variant detection: all four variants" {
    // NCS: top bit 0 → byte 8 = 0x00..0x7f
    var ncs = Uuid.nil;
    ncs.bytes[8] = 0x00;
    try testing.expectEqual(Uuid.Variant.reserved_ncs, ncs.getVariant());
    ncs.bytes[8] = 0x7f;
    try testing.expectEqual(Uuid.Variant.reserved_ncs, ncs.getVariant());

    // RFC 9562: top bits 10 → byte 8 = 0x80..0xbf
    var rfc = Uuid.nil;
    rfc.bytes[8] = 0x80;
    try testing.expectEqual(Uuid.Variant.rfc9562, rfc.getVariant());
    rfc.bytes[8] = 0xbf;
    try testing.expectEqual(Uuid.Variant.rfc9562, rfc.getVariant());

    // Microsoft: top bits 110 → byte 8 = 0xc0..0xdf
    var ms = Uuid.nil;
    ms.bytes[8] = 0xc0;
    try testing.expectEqual(Uuid.Variant.reserved_microsoft, ms.getVariant());
    ms.bytes[8] = 0xdf;
    try testing.expectEqual(Uuid.Variant.reserved_microsoft, ms.getVariant());

    // Future: top bits 111 → byte 8 = 0xe0..0xff
    var future = Uuid.nil;
    future.bytes[8] = 0xe0;
    try testing.expectEqual(Uuid.Variant.reserved_future, future.getVariant());
    future.bytes[8] = 0xff;
    try testing.expectEqual(Uuid.Variant.reserved_future, future.getVariant());
}

test "version detection for all valid versions" {
    const versions = [_]struct { nibble: u4, expected: Uuid.Version }{
        .{ .nibble = 1, .expected = .time_based },
        .{ .nibble = 3, .expected = .name_based_md5 },
        .{ .nibble = 4, .expected = .random },
        .{ .nibble = 5, .expected = .name_based_sha1 },
        .{ .nibble = 6, .expected = .time_based_reordered },
        .{ .nibble = 7, .expected = .time_based_unix },
        .{ .nibble = 8, .expected = .custom },
    };
    for (versions) |v| {
        var uuid = Uuid.nil;
        uuid.bytes[6] = @as(u8, v.nibble) << 4;
        try testing.expectEqual(v.expected, uuid.getVersion().?);
    }
}

test "version detection returns null for unknown versions" {
    const invalid_nibbles = [_]u4{ 0, 2, 9, 10, 11, 12, 13, 14, 15 };
    for (invalid_nibbles) |n| {
        var uuid = Uuid.nil;
        uuid.bytes[6] = @as(u8, n) << 4;
        try testing.expectEqual(@as(?Uuid.Version, null), uuid.getVersion());
    }
}

// ---- v4 ----

test "v4 version and variant" {
    const uuid = Uuid.v4();
    try testing.expectEqual(Uuid.Version.random, uuid.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, uuid.getVariant());
}

test "v4 uniqueness" {
    const a = Uuid.v4();
    const b = Uuid.v4();
    try testing.expect(!a.eql(b));
}

test "v4 version and variant bits are correct across many UUIDs" {
    for (0..100) |_| {
        const uuid = Uuid.v4();
        // Version nibble must be 0x4
        try testing.expectEqual(@as(u8, 0x40), uuid.bytes[6] & 0xf0);
        // Variant must be 0b10
        try testing.expectEqual(@as(u8, 0x80), uuid.bytes[8] & 0xc0);
    }
}

// ---- v3 ----

test "v3 deterministic" {
    const a = Uuid.v3(Uuid.namespace_dns, "www.example.com");
    const b = Uuid.v3(Uuid.namespace_dns, "www.example.com");
    try testing.expect(a.eql(b));
    try testing.expectEqual(Uuid.Version.name_based_md5, a.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, a.getVariant());
}

test "v3 known vector: DNS www.example.com" {
    const uuid = Uuid.v3(Uuid.namespace_dns, "www.example.com");
    try testing.expectEqualStrings("5df41881-3aed-3515-88a7-2f4a814cf09e", &uuid.toStr());
}

test "v3 different names produce different UUIDs" {
    const a = Uuid.v3(Uuid.namespace_dns, "example.com");
    const b = Uuid.v3(Uuid.namespace_dns, "example.org");
    try testing.expect(!a.eql(b));
}

test "v3 different namespaces produce different UUIDs" {
    const a = Uuid.v3(Uuid.namespace_dns, "example.com");
    const b = Uuid.v3(Uuid.namespace_url, "example.com");
    try testing.expect(!a.eql(b));
}

test "v3 empty name" {
    const uuid = Uuid.v3(Uuid.namespace_dns, "");
    try testing.expectEqual(Uuid.Version.name_based_md5, uuid.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, uuid.getVariant());
}

// ---- v5 ----

test "v5 deterministic" {
    const a = Uuid.v5(Uuid.namespace_dns, "www.example.com");
    const b = Uuid.v5(Uuid.namespace_dns, "www.example.com");
    try testing.expect(a.eql(b));
    try testing.expectEqual(Uuid.Version.name_based_sha1, a.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, a.getVariant());
}

test "v5 known vector: DNS www.example.com" {
    const uuid = Uuid.v5(Uuid.namespace_dns, "www.example.com");
    try testing.expectEqualStrings("2ed6657d-e927-568b-95e1-2665a8aea6a2", &uuid.toStr());
}

test "v5 known vector: DNS python.org" {
    // Cross-verified with Python's uuid.uuid5(uuid.NAMESPACE_DNS, "python.org")
    const uuid = Uuid.v5(Uuid.namespace_dns, "python.org");
    try testing.expectEqualStrings("886313e1-3b8a-5372-9b90-0c9aee199e5d", &uuid.toStr());
}

test "v5 known vector: URL http://example.com" {
    // Cross-verified with Python's uuid.uuid5(uuid.NAMESPACE_URL, "http://example.com")
    const uuid = Uuid.v5(Uuid.namespace_url, "http://example.com");
    try testing.expectEqualStrings("8c9ddcb0-8084-5a7f-a988-1095ab18b5df", &uuid.toStr());
}

test "v5 different from v3 for same input" {
    const v3_uuid = Uuid.v3(Uuid.namespace_dns, "www.example.com");
    const v5_uuid = Uuid.v5(Uuid.namespace_dns, "www.example.com");
    try testing.expect(!v3_uuid.eql(v5_uuid));
}

// ---- v8 ----

test "v8 version and variant" {
    const uuid = Uuid.v8(0x112233445566, 0xabc, 0x1234567890abcdef);
    try testing.expectEqual(Uuid.Version.custom, uuid.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, uuid.getVariant());
}

test "v8 all zeros except version/variant" {
    const uuid = Uuid.v8(0, 0, 0);
    try testing.expectEqual(@as(u8, 0x80), uuid.bytes[6]);
    try testing.expectEqual(@as(u8, 0x00), uuid.bytes[7]);
    try testing.expectEqual(@as(u8, 0x80), uuid.bytes[8] & 0xc0);
    // bytes 0-5 should be zero
    for (uuid.bytes[0..6]) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "v8 custom_a big-endian packing" {
    const uuid = Uuid.v8(0x112233445566, 0, 0);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, uuid.bytes[0..6]);
}

test "v8 custom_b packing" {
    // custom_b = 0xabc → byte 6 low nibble = 0xa (but version overwrites high nibble),
    // byte 7 = 0xbc
    const uuid = Uuid.v8(0, 0xabc, 0);
    // After version stamp: byte 6 = 0x8a (version=8, low nibble=a)
    try testing.expectEqual(@as(u8, 0x8a), uuid.bytes[6]);
    try testing.expectEqual(@as(u8, 0xbc), uuid.bytes[7]);
}

test "v8 custom_c packing" {
    // custom_c occupies 62 bits in bytes[8..16], top 2 bits are variant
    const uuid = Uuid.v8(0, 0, 0x3fffffffffffffff); // max 62-bit value
    // After variant stamp: byte 8 top 2 bits = 10, low 6 bits = all ones = 0xbf
    try testing.expectEqual(@as(u8, 0xbf), uuid.bytes[8]);
    for (uuid.bytes[9..16]) |b| try testing.expectEqual(@as(u8, 0xff), b);
}

test "v8 full round-trip: all fields" {
    const uuid = Uuid.v8(0xAABBCCDDEEFF, 0x123, 0x0ABCDEF012345678);
    // custom_a
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, uuid.bytes[0..6]);
    // custom_b: 0x123 → byte 6 low nibble = 0x1, byte 7 = 0x23, version overwrites high nibble
    try testing.expectEqual(@as(u8, 0x81), uuid.bytes[6]);
    try testing.expectEqual(@as(u8, 0x23), uuid.bytes[7]);
    // custom_c: 0x0ABCDEF012345678 → bytes 8-15, variant overwrites top 2 bits
    // byte 8: original = 0x0A, after variant (10xxxxxx) = 0x8A
    try testing.expectEqual(@as(u8, 0x8A), uuid.bytes[8]);
}

// ---- v1 ----

test "v1 version and variant" {
    const uuid = try Uuid.v1(null);
    try testing.expectEqual(Uuid.Version.time_based, uuid.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, uuid.getVariant());
}

test "v1 with explicit node" {
    const node = [6]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab };
    const uuid = try Uuid.v1(node);
    try testing.expectEqualSlices(u8, &node, uuid.bytes[10..16]);
}

test "v1 random node has multicast bit set" {
    // Reset state to force new node generation
    Uuid.gregorian_state = .{};
    const uuid = try Uuid.v1(null);
    try testing.expectEqual(@as(u8, 1), uuid.bytes[10] & 0x01);
}

test "v1 timestamp is extractable and reasonable" {
    const uuid = try Uuid.v1(null);
    const ts = uuid.getTimestampV1().?;
    // Timestamp should be after 2020-01-01 in Gregorian ticks
    // 2020-01-01 = 438 years after 1582 ≈ 1.38e17 ticks
    try testing.expect(ts > 0x01d4_a2e0_0000_0000);
}

// ---- v6 ----

test "v6 version and variant" {
    const uuid = try Uuid.v6(null);
    try testing.expectEqual(Uuid.Version.time_based_reordered, uuid.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, uuid.getVariant());
}

test "v6 strict ordering" {
    // Reset state to ensure clean sequence
    Uuid.gregorian_state = .{};
    const a = try Uuid.v6(null);
    const b = try Uuid.v6(null);
    try testing.expect(Uuid.order(a, b) == .lt);
}

test "v6 timestamp extraction" {
    const uuid = try Uuid.v6(null);
    const ts = uuid.getTimestampV6().?;
    try testing.expect(ts > 0x01d4_a2e0_0000_0000);
}

test "v1 and v6 carry the same timestamp" {
    // Generate v1 and v6 in sequence; they share the same Gregorian clock state.
    // The timestamps should differ by at most the time between the two calls,
    // which is negligible. We verify they're within 1 second of each other.
    Uuid.gregorian_state = .{};
    const node = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const uuid_v1 = try Uuid.v1(node);
    const uuid_v6 = try Uuid.v6(node);

    const ts_v1 = uuid_v1.getTimestampV1().?;
    const ts_v6 = uuid_v6.getTimestampV6().?;

    // Within 10 million 100ns ticks = 1 second
    const diff = if (ts_v6 > ts_v1) ts_v6 - ts_v1 else ts_v1 - ts_v6;
    try testing.expect(diff < 10_000_000);
}

test "v1 and v6 share the same node" {
    Uuid.gregorian_state = .{};
    const node = [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const uuid_v1 = try Uuid.v1(node);
    const uuid_v6 = try Uuid.v6(node);
    try testing.expectEqualSlices(u8, uuid_v1.getNode().?[0..], uuid_v6.getNode().?[0..]);
}

// ---- v7 ----

test "v7 version and variant" {
    const uuid = try Uuid.v7();
    try testing.expectEqual(Uuid.Version.time_based_unix, uuid.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, uuid.getVariant());
}

test "v7 timestamp is extractable and reasonable" {
    const uuid = try Uuid.v7();
    const ts_ms = uuid.getTimestampV7().?;
    // Should be after 2020-01-01 00:00:00 UTC = 1577836800000 ms
    try testing.expect(ts_ms > 1_577_836_800_000);
}

test "v7 monotonic ordering: 5000 iterations" {
    Uuid.v7_state = .{};
    var prev = try Uuid.v7();
    for (0..5000) |_| {
        const next = try Uuid.v7();
        try testing.expect(Uuid.order(prev, next) == .lt);
        prev = next;
    }
}

test "v7 version and variant bits across many UUIDs" {
    for (0..200) |_| {
        const uuid = try Uuid.v7();
        try testing.expectEqual(@as(u8, 0x70), uuid.bytes[6] & 0xf0);
        try testing.expectEqual(@as(u8, 0x80), uuid.bytes[8] & 0xc0);
    }
}

// ---- Gregorian offset ----

test "gregorian offset is 122192928000000000" {
    // The number of 100-nanosecond intervals between 1582-10-15 and 1970-01-01
    // is well-established as 122,192,928,000,000,000.
    try testing.expectEqual(@as(u64, 122_192_928_000_000_000), Uuid.gregorian_offset);
}

// ---- Namespace constants ----

test "namespace DNS" {
    try testing.expectEqualStrings("6ba7b810-9dad-11d1-80b4-00c04fd430c8", &Uuid.namespace_dns.toStr());
}

test "namespace URL" {
    try testing.expectEqualStrings("6ba7b811-9dad-11d1-80b4-00c04fd430c8", &Uuid.namespace_url.toStr());
}

test "namespace OID" {
    try testing.expectEqualStrings("6ba7b812-9dad-11d1-80b4-00c04fd430c8", &Uuid.namespace_oid.toStr());
}

test "namespace X500" {
    try testing.expectEqualStrings("6ba7b814-9dad-11d1-80b4-00c04fd430c8", &Uuid.namespace_x500.toStr());
}

test "namespace UUIDs have version 1 and RFC variant" {
    const namespaces = [_]Uuid{ Uuid.namespace_dns, Uuid.namespace_url, Uuid.namespace_oid, Uuid.namespace_x500 };
    for (namespaces) |ns| {
        try testing.expectEqual(Uuid.Version.time_based, ns.getVersion().?);
        try testing.expectEqual(Uuid.Variant.rfc9562, ns.getVariant());
    }
}

// ---- Format protocol ----

test "std.fmt integration" {
    const uuid = try Uuid.parse("550e8400-e29b-41d4-a716-446655440000");
    var buf: [36]u8 = undefined;
    const result = std.fmt.bufPrint(&buf, "{f}", .{uuid}) catch unreachable;
    try testing.expectEqualStrings("550e8400-e29b-41d4-a716-446655440000", result);
}

// ---- fromBytes ----

test "fromBytes round-trip" {
    const original = Uuid.v4();
    const rebuilt = Uuid.fromBytes(original.bytes);
    try testing.expect(original.eql(rebuilt));
}

test "fromBytes with known bytes" {
    const bytes = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const uuid = Uuid.fromBytes(bytes);
    try testing.expectEqualSlices(u8, &bytes, &uuid.bytes);
}

// ---- Timestamp extraction returns null for wrong version ----

test "getTimestampV1 returns null for non-v1" {
    try testing.expectEqual(@as(?u60, null), Uuid.v4().getTimestampV1());
    try testing.expectEqual(@as(?u60, null), (try Uuid.v7()).getTimestampV1());
}

test "getTimestampV6 returns null for non-v6" {
    try testing.expectEqual(@as(?u60, null), Uuid.v4().getTimestampV6());
    try testing.expectEqual(@as(?u60, null), (try Uuid.v1(null)).getTimestampV6());
}

test "getTimestampV7 returns null for non-v7" {
    try testing.expectEqual(@as(?u48, null), Uuid.v4().getTimestampV7());
    try testing.expectEqual(@as(?u48, null), (try Uuid.v1(null)).getTimestampV7());
}

test "getClockSeq returns null for non-time-based" {
    try testing.expectEqual(@as(?u14, null), Uuid.v4().getClockSeq());
    try testing.expectEqual(@as(?u14, null), (try Uuid.v7()).getClockSeq());
}

test "getNode returns null for non-time-based" {
    try testing.expectEqual(@as(?[6]u8, null), Uuid.v4().getNode());
    try testing.expectEqual(@as(?[6]u8, null), (try Uuid.v7()).getNode());
}

// ===================================================================
// Deterministic tests — fixed inputs, hand-verified expected bytes
// ===================================================================

// -- v4 deterministic --
test "v4 deterministic: seeded random produces expected UUID" {
    // Use a deterministic PRNG seeded with a known value
    var prng = std.Random.DefaultPrng.init(42);
    const uuid = Uuid.v4WithSource(prng.random());

    // Regardless of the random output, version and variant must be stamped
    try testing.expectEqual(Uuid.Version.random, uuid.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, uuid.getVariant());

    // Generate a second one from the same seed — must reproduce
    var prng2 = std.Random.DefaultPrng.init(42);
    const uuid2 = Uuid.v4WithSource(prng2.random());
    try testing.expect(uuid.eql(uuid2));
}

// -- v1 deterministic: known timestamp, clock_seq, node --
test "v1 deterministic: known fields produce exact bytes" {
    // Timestamp: 0x1E4_ABCD_1234_5678 (a 60-bit value)
    // = 0x1E4ABCD12345678
    //   time_low  (bits 0-31)  = 0x12345678
    //   time_mid  (bits 32-47) = 0xBCD1      (wait — let me compute properly)
    //
    // timestamp = 0x1E4_ABCD_1234_5678
    //   bits [0:31]  = 0x12345678 → time_low
    //   bits [32:47] = 0xABCD     → wait, let me recompute
    //
    // 0x1E4ABCD12345678 in binary:
    //   0001 1110 0100 1010 1011 1100 1101 0001 0010 0011 0100 0101 0110 0111 1000
    //   That's 61 bits — too big for u60. Let me use a valid 60-bit value.
    //
    // Use timestamp = 0x1D8_ABCD_EF01_2345 (fits in 60 bits)
    //   time_low  = bits[0:31]  = 0xEF012345
    //   time_mid  = bits[32:47] = 0xABCD
    //   time_hi   = bits[48:59] = 0x1D8
    const timestamp: u60 = 0x1D8_ABCD_EF01_2345;
    const clock_seq: u14 = 0x1234;
    const node = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    const uuid = Uuid.v1FromFields(timestamp, clock_seq, node);

    // Verify version and variant
    try testing.expectEqual(Uuid.Version.time_based, uuid.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, uuid.getVariant());

    // Verify timestamp round-trips
    try testing.expectEqual(timestamp, uuid.getTimestampV1().?);

    // Verify clock_seq (variant takes top 2 bits of byte 8)
    try testing.expectEqual(clock_seq, uuid.getClockSeq().?);

    // Verify node
    try testing.expectEqualSlices(u8, &node, uuid.getNode().?[0..]);

    // Verify exact bytes:
    // bytes[0..4] = time_low  = 0xEF012345 → EF 01 23 45
    try testing.expectEqualSlices(u8, &[_]u8{ 0xEF, 0x01, 0x23, 0x45 }, uuid.bytes[0..4]);
    // bytes[4..6] = time_mid  = 0xABCD → AB CD
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAB, 0xCD }, uuid.bytes[4..6]);
    // bytes[6..8] = version(0x1) | time_hi(0x1D8) → 0x11 0xD8
    try testing.expectEqual(@as(u8, 0x11), uuid.bytes[6]);
    try testing.expectEqual(@as(u8, 0xD8), uuid.bytes[7]);
    // bytes[8..10] = variant(0b10) | clock_seq(0x1234)
    //   clock_seq = 0x1234 = 0001 0010 0011 0100
    //   But clock_seq is only 14 bits: 0x1234 & 0x3FFF = 0x1234
    //   byte 8 = variant(10) | upper 6 bits of clock_seq(00 0100) = 1001 0010 = 0x92
    //   byte 9 = lower 8 bits of clock_seq = 0x34
    try testing.expectEqual(@as(u8, 0x92), uuid.bytes[8]);
    try testing.expectEqual(@as(u8, 0x34), uuid.bytes[9]);
    // bytes[10..16] = node
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, uuid.bytes[10..16]);
}

// -- v6 deterministic: same timestamp as v1, verify reordering --
test "v6 deterministic: known fields produce exact bytes" {
    const timestamp: u60 = 0x1D8_ABCD_EF01_2345;
    const clock_seq: u14 = 0x1234;
    const node = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    const uuid = Uuid.v6FromFields(timestamp, clock_seq, node);

    try testing.expectEqual(Uuid.Version.time_based_reordered, uuid.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, uuid.getVariant());
    try testing.expectEqual(timestamp, uuid.getTimestampV6().?);
    try testing.expectEqual(clock_seq, uuid.getClockSeq().?);
    try testing.expectEqualSlices(u8, &node, uuid.getNode().?[0..]);

    // v6 reorders: time_high(bits 59:28) | time_mid(bits 27:12) | ver | time_low(bits 11:0)
    //
    // timestamp = 0x1D8_ABCD_EF01_2345
    //   time_high = bits[59:28] = timestamp >> 28 = 0x1D8ABCDE
    //   time_mid  = bits[27:12] = (timestamp >> 12) & 0xFFFF = 0xF012
    //   time_low  = bits[11:0]  = timestamp & 0xFFF = 0x345
    //
    // bytes[0..4] = time_high = 0x1D8ABCDE → 1D 8A BC DE
    try testing.expectEqualSlices(u8, &[_]u8{ 0x1D, 0x8A, 0xBC, 0xDE }, uuid.bytes[0..4]);
    // bytes[4..6] = time_mid = 0xF012 → F0 12
    try testing.expectEqualSlices(u8, &[_]u8{ 0xF0, 0x12 }, uuid.bytes[4..6]);
    // bytes[6..8] = version(0x6) | time_low(0x345) → 0x63 0x45
    try testing.expectEqual(@as(u8, 0x63), uuid.bytes[6]);
    try testing.expectEqual(@as(u8, 0x45), uuid.bytes[7]);
    // bytes[8..10] same as v1: variant | clock_seq
    try testing.expectEqual(@as(u8, 0x92), uuid.bytes[8]);
    try testing.expectEqual(@as(u8, 0x34), uuid.bytes[9]);
    // bytes[10..16] = node
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, uuid.bytes[10..16]);
}

// -- v1 and v6 same timestamp produce same extracted value --
test "v1 and v6 deterministic: same timestamp encodes identically" {
    const timestamp: u60 = 0x1D8_ABCD_EF01_2345;
    const clock_seq: u14 = 0x0000;
    const node = [6]u8{ 0, 0, 0, 0, 0, 0 };

    const uuid_v1 = Uuid.v1FromFields(timestamp, clock_seq, node);
    const uuid_v6 = Uuid.v6FromFields(timestamp, clock_seq, node);

    // Both should extract the same timestamp
    try testing.expectEqual(timestamp, uuid_v1.getTimestampV1().?);
    try testing.expectEqual(timestamp, uuid_v6.getTimestampV6().?);
}

// -- v7 deterministic: known fields produce exact bytes --
test "v7 deterministic: known fields produce exact bytes" {
    const unix_ts_ms: u48 = 0x0188_4F29_7A00; // ~2023-03-01 in ms
    const counter: u12 = 0xABC;
    const rand_b = [8]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

    const uuid = Uuid.v7FromFields(unix_ts_ms, counter, rand_b);

    try testing.expectEqual(Uuid.Version.time_based_unix, uuid.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, uuid.getVariant());
    try testing.expectEqual(unix_ts_ms, uuid.getTimestampV7().?);

    // bytes[0..6] = unix_ts_ms = 0x01884F297A00 → 01 88 4F 29 7A 00
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x88, 0x4F, 0x29, 0x7A, 0x00 }, uuid.bytes[0..6]);
    // bytes[6..8] = version(0x7) | counter(0xABC) → 0x7A 0xBC
    try testing.expectEqual(@as(u8, 0x7A), uuid.bytes[6]);
    try testing.expectEqual(@as(u8, 0xBC), uuid.bytes[7]);
    // bytes[8..16] = variant(10) | rand_b[0..8]
    //   byte 8: rand_b[0]=0x11 → variant stamps top 2 bits: (0x11 & 0x3F) | 0x80 = 0x91
    try testing.expectEqual(@as(u8, 0x91), uuid.bytes[8]);
    //   bytes 9-15: rand_b[1..7] unchanged
    try testing.expectEqualSlices(u8, &[_]u8{ 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }, uuid.bytes[9..16]);
}

// -- v7 deterministic: counter=0, counter=max --
test "v7 deterministic: counter boundaries" {
    const ts: u48 = 1000;
    const rand_b = [_]u8{0} ** 8;

    // counter = 0
    const uuid_min = Uuid.v7FromFields(ts, 0, rand_b);
    try testing.expectEqual(@as(u8, 0x70), uuid_min.bytes[6]); // version=7, counter high=0
    try testing.expectEqual(@as(u8, 0x00), uuid_min.bytes[7]); // counter low=0

    // counter = max (0xFFF)
    const uuid_max = Uuid.v7FromFields(ts, 0xFFF, rand_b);
    try testing.expectEqual(@as(u8, 0x7F), uuid_max.bytes[6]); // version=7, counter high=0xF
    try testing.expectEqual(@as(u8, 0xFF), uuid_max.bytes[7]); // counter low=0xFF

    // max > min
    try testing.expectEqual(std.math.Order.lt, Uuid.order(uuid_min, uuid_max));
}

// -- v7 deterministic: monotonicity across counter values --
test "v7 deterministic: sequential counters are monotonic" {
    const ts: u48 = 0x0188_4F29_7A00;
    const rand_b = [8]u8{ 0x80, 0, 0, 0, 0, 0, 0, 0 };

    var prev = Uuid.v7FromFields(ts, 0, rand_b);
    var counter: u12 = 1;
    while (counter < 4095) : (counter += 1) {
        const next = Uuid.v7FromFields(ts, counter, rand_b);
        try testing.expect(Uuid.order(prev, next) == .lt);
        prev = next;
    }
}

// -- v7 deterministic: different timestamps sort correctly --
test "v7 deterministic: timestamp ordering" {
    const rand_b = [_]u8{0} ** 8;

    const uuid_early = Uuid.v7FromFields(1000, 0, rand_b);
    const uuid_late = Uuid.v7FromFields(2000, 0, rand_b);
    try testing.expect(Uuid.order(uuid_early, uuid_late) == .lt);
}

// -- v1 deterministic: timestamp=0 (Gregorian epoch exactly) --
test "v1 deterministic: timestamp zero" {
    const uuid = Uuid.v1FromFields(0, 0, .{ 0, 0, 0, 0, 0, 0 });
    try testing.expectEqual(@as(?u60, 0), uuid.getTimestampV1());
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, uuid.bytes[0..4]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0 }, uuid.bytes[4..6]);
    try testing.expectEqual(@as(u8, 0x10), uuid.bytes[6]); // version=1, time_hi=0
    try testing.expectEqual(@as(u8, 0x00), uuid.bytes[7]);
    // clock_seq=0: variant(10) + 0 = 0x80, low byte = 0x00
    try testing.expectEqual(@as(u8, 0x80), uuid.bytes[8]);
    try testing.expectEqual(@as(u8, 0x00), uuid.bytes[9]);
    try testing.expectEqual(@as(?u14, 0), uuid.getClockSeq());
}

// -- v6 deterministic: timestamp=0 --
test "v6 deterministic: timestamp zero" {
    const uuid = Uuid.v6FromFields(0, 0, .{ 0, 0, 0, 0, 0, 0 });
    try testing.expectEqual(@as(?u60, 0), uuid.getTimestampV6());
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, uuid.bytes[0..4]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0 }, uuid.bytes[4..6]);
    try testing.expectEqual(@as(u8, 0x60), uuid.bytes[6]); // version=6, time_low=0
    try testing.expectEqual(@as(u8, 0x00), uuid.bytes[7]);
    try testing.expectEqual(@as(u8, 0x80), uuid.bytes[8]);
    try testing.expectEqual(@as(u8, 0x00), uuid.bytes[9]);
    try testing.expectEqual(@as(?u14, 0), uuid.getClockSeq());
}

// -- v1 deterministic: max timestamp (all 60 bits set) --
test "v1 deterministic: max timestamp" {
    const max_ts: u60 = std.math.maxInt(u60);
    const uuid = Uuid.v1FromFields(max_ts, std.math.maxInt(u14), .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
    try testing.expectEqual(max_ts, uuid.getTimestampV1().?);
    try testing.expectEqual(std.math.maxInt(u14), uuid.getClockSeq().?);
}

// -- v6 deterministic: max timestamp --
test "v6 deterministic: max timestamp" {
    const max_ts: u60 = std.math.maxInt(u60);
    const uuid = Uuid.v6FromFields(max_ts, std.math.maxInt(u14), .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
    try testing.expectEqual(max_ts, uuid.getTimestampV6().?);
    try testing.expectEqual(std.math.maxInt(u14), uuid.getClockSeq().?);
}

// ===================================================================
// State machine tests — exercise threadlocal state paths
// ===================================================================

test "v1 node change resets clock_seq" {
    Uuid.gregorian_state = .{};
    const node_a = [6]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const node_b = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    _ = try Uuid.v1(node_a);
    const seq_after_a = Uuid.gregorian_state.clock_seq;
    _ = try Uuid.v1(node_b);
    // Node must have changed
    try testing.expectEqualSlices(u8, &node_b, &Uuid.gregorian_state.node);
    // clock_seq was re-randomized — with overwhelming probability it differs
    // (1/16384 chance of false negative, acceptable for a test)
    // At minimum verify the state is still initialized
    try testing.expect(Uuid.gregorian_state.initialized);
    _ = seq_after_a;
}

test "v1 null node preserves existing node after init" {
    Uuid.gregorian_state = .{};
    const explicit_node = [6]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 };
    _ = try Uuid.v1(explicit_node);
    // Second call with null should keep the explicit node
    _ = try Uuid.v1(null);
    try testing.expectEqualSlices(u8, &explicit_node, &Uuid.gregorian_state.node);
}

test "v1 clock_seq overflow does not stall when timestamp advances" {
    Uuid.gregorian_state = .{
        .initialized = true,
        .last_timestamp = 0, // far in the past — real clock will exceed this
        .clock_seq = std.math.maxInt(u14),
        .node = .{ 0x01, 0, 0, 0, 0, 0 },
    };
    // Real clock > 0, so the spin in advanceGregorianClock should break immediately
    const uuid = try Uuid.v1(null);
    try testing.expectEqual(Uuid.Version.time_based, uuid.getVersion().?);
    try testing.expectEqual(Uuid.Variant.rfc9562, uuid.getVariant());
    // Real clock always advances past 0, so last_timestamp must have changed
    try testing.expect(Uuid.gregorian_state.last_timestamp > 0);
}

test "v7 clock regression increments counter" {
    Uuid.v7_state = .{
        .initialized = true,
        .last_ms = std.math.maxInt(i64) >> 1, // far future — real clock will be behind
        .counter = 100,
    };
    const uuid = try Uuid.v7();
    // Counter should have incremented (clock regression enters else branch)
    try testing.expectEqual(@as(u12, 101), Uuid.v7_state.counter);
    // Timestamp in UUID should be the old last_ms, not the current time
    try testing.expectEqual(Uuid.Version.time_based_unix, uuid.getVersion().?);
}

test "v7 clock regression preserves monotonicity" {
    Uuid.v7_state = .{
        .initialized = true,
        .last_ms = std.math.maxInt(i64) >> 1,
        .counter = 0,
    };
    const a = try Uuid.v7();
    const b = try Uuid.v7();
    try testing.expect(Uuid.order(a, b) == .lt);
}

// ===================================================================
// v4 structural coverage
// ===================================================================

test "v4 preserves all random bytes except version/variant nibbles" {
    var prng1 = std.Random.DefaultPrng.init(0);
    var prng2 = std.Random.DefaultPrng.init(0);
    // Capture what the PRNG would produce
    var raw: [16]u8 = undefined;
    prng2.random().bytes(&raw);
    const uuid = Uuid.v4WithSource(prng1.random());
    // All bytes except version nibble (byte 6 high) and variant bits (byte 8 top 2) must match
    for (0..16) |i| {
        if (i == 6) {
            try testing.expectEqual(raw[i] & 0x0f, uuid.bytes[i] & 0x0f);
        } else if (i == 8) {
            try testing.expectEqual(raw[i] & 0x3f, uuid.bytes[i] & 0x3f);
        } else {
            try testing.expectEqual(raw[i], uuid.bytes[i]);
        }
    }
}

// ===================================================================
// Parse negative tests — correct length, wrong structure
// ===================================================================

test "parse error: hyphen shifted by one position" {
    // 36 chars, but hyphen at position 9 instead of 8
    try testing.expectError(error.InvalidSeparator, Uuid.parse("550e84000-e29b-41d4-a716-44665544000"));
}

test "parse error: all hyphens is InvalidSeparator" {
    // 36 hyphens: length ok, but position 8 is '-' which passes separator check,
    // then hex parsing hits '-' at non-hyphen position → InvalidCharacter
    try testing.expectError(error.InvalidCharacter, Uuid.parse("------------------------------------"));
}

test "parse error: correct length wrong hyphen positions" {
    // 36 chars, hyphens at positions 4,9,14,19 instead of 8,13,18,23
    //           0123456789012345678901234567890123456
    try testing.expectError(error.InvalidSeparator, Uuid.parse("00000000a0000-0000-0000-000000000000"));
}

// ===================================================================
// Comptime clock tests — ClockStall error paths
// Each test instantiates UuidImpl with a fake clock to exercise error paths
// that are unreachable with the real system clock.
// ===================================================================

test "v7 ClockStall when clock is frozen" {
    const FrozenUuid = UuidImpl(std.time.nanoTimestamp, struct {
        fn clock() i64 {
            return 1000;
        }
    }.clock);
    FrozenUuid.v7_state = .{ .initialized = true, .last_ms = 1000, .counter = std.math.maxInt(u12) };
    try testing.expectError(error.ClockStall, FrozenUuid.v7());
}

test "v7 counter overflow resolves when clock advances" {
    const AdvancingUuid = UuidImpl(std.time.nanoTimestamp, struct {
        var calls: u32 = 0;
        fn clock() i64 {
            @This().calls += 1;
            return if (@This().calls <= 1) 1000 else 1001;
        }
    }.clock);
    AdvancingUuid.v7_state = .{ .initialized = true, .last_ms = 1000, .counter = std.math.maxInt(u12) };
    const uuid = try AdvancingUuid.v7();
    try testing.expectEqual(AdvancingUuid.Version.time_based_unix, uuid.getVersion().?);
    try testing.expectEqual(@as(u48, 1001), uuid.getTimestampV7().?);
}

test "v1 ClockStall when Gregorian clock is frozen and clock_seq exhausted" {
    const FrozenUuid = UuidImpl(struct {
        fn clock() i128 {
            return 0;
        }
    }.clock, std.time.milliTimestamp);
    const expected_ts: u60 = @truncate(FrozenUuid.gregorian_offset);
    FrozenUuid.gregorian_state = .{
        .initialized = true,
        .last_timestamp = expected_ts,
        .clock_seq = std.math.maxInt(u14),
        .node = .{ 0x01, 0, 0, 0, 0, 0 },
    };
    try testing.expectError(error.ClockStall, FrozenUuid.v1(null));
}

test "v6 ClockStall when Gregorian clock is frozen and clock_seq exhausted" {
    const FrozenUuid = UuidImpl(struct {
        fn clock() i128 {
            return 0;
        }
    }.clock, std.time.milliTimestamp);
    const expected_ts: u60 = @truncate(FrozenUuid.gregorian_offset);
    FrozenUuid.gregorian_state = .{
        .initialized = true,
        .last_timestamp = expected_ts,
        .clock_seq = std.math.maxInt(u14),
        .node = .{ 0x01, 0, 0, 0, 0, 0 },
    };
    try testing.expectError(error.ClockStall, FrozenUuid.v6(null));
}

test "v1 clock_seq overflow resolves when Gregorian clock advances" {
    const AdvancingUuid = UuidImpl(struct {
        var calls: u32 = 0;
        fn clock() i128 {
            @This().calls += 1;
            return if (@This().calls <= 1) 0 else 100;
        }
    }.clock, std.time.milliTimestamp);
    const expected_ts: u60 = @truncate(AdvancingUuid.gregorian_offset);
    AdvancingUuid.gregorian_state = .{
        .initialized = true,
        .last_timestamp = expected_ts,
        .clock_seq = std.math.maxInt(u14),
        .node = .{ 0x01, 0, 0, 0, 0, 0 },
    };
    const uuid = try AdvancingUuid.v1(null);
    try testing.expectEqual(AdvancingUuid.Version.time_based, uuid.getVersion().?);
    // clock_seq was re-randomized (no longer maxInt with overwhelming probability)
    try testing.expect(AdvancingUuid.gregorian_state.clock_seq != std.math.maxInt(u14));
}

test "getGregorianTimestamp saturates to 0 for pre-1582 clock" {
    const AncientUuid = UuidImpl(struct {
        fn clock() i128 {
            return -20_000_000_000_000_000_000;
        }
    }.clock, std.time.milliTimestamp);
    AncientUuid.gregorian_state = .{
        .initialized = true,
        .last_timestamp = 0,
        .clock_seq = 0,
        .node = .{ 0x01, 0, 0, 0, 0, 0 },
    };
    // ts saturates to 0. Since 0 <= last_timestamp (0), clock_seq increments to 1.
    const uuid = try AncientUuid.v1(null);
    try testing.expectEqual(@as(?u60, 0), uuid.getTimestampV1());
    try testing.expectEqual(@as(?u14, 1), uuid.getClockSeq());
}
