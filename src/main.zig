const std = @import("std");
const curl = @import("curl");
const posix = std.posix;

const Curl = curl.libcurl;

// ── ANSI ──────────────────────────────────────────────────────────────
const esc = struct {
    const clear = "\x1b[2J\x1b[H";
    const hide_cursor = "\x1b[?25l";
    const show_cursor = "\x1b[?25h";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const red = "\x1b[31m";
    const bold_red = "\x1b[1;31m";
    const cyan = "\x1b[36m";
    const dim = "\x1b[90m";
    const bold = "\x1b[1m";
    const reset = "\x1b[0m";
    const reverse = "\x1b[7m";
};

fn colorForStatus(code: u32) []const u8 {
    return switch (code) {
        200...299 => esc.green,
        300...399 => esc.yellow,
        400...499 => esc.red,
        500...599 => esc.bold_red,
        else => esc.dim,
    };
}

// ── Formatting helpers ────────────────────────────────────────────────
const FmtVal = struct { val: f64, unit: []const u8 };

fn fmtBytes(bytes: f64) FmtVal {
    if (bytes < 1024) return .{ .val = bytes, .unit = "B" };
    if (bytes < 1024 * 1024) return .{ .val = bytes / 1024, .unit = "KB" };
    return .{ .val = bytes / (1024 * 1024), .unit = "MB" };
}

fn fmtTime(secs: f64) FmtVal {
    if (secs < 0.001) return .{ .val = secs * 1_000_000, .unit = "µs" };
    if (secs < 1.0) return .{ .val = secs * 1000, .unit = "ms" };
    return .{ .val = secs, .unit = "s" };
}

fn fmtTimeBuf(buf: []u8, secs: f64) []const u8 {
    const t = fmtTime(secs);
    return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ t.val, t.unit }) catch "?";
}

// ── Curl info helpers ─────────────────────────────────────────────────
fn getDouble(handle: *Curl.CURL, info: Curl.CURLINFO) ?f64 {
    var val: f64 = 0;
    if (Curl.curl_easy_getinfo(handle, info, &val) == Curl.CURLE_OK) return val;
    return null;
}

fn getLong(handle: *Curl.CURL, info: Curl.CURLINFO) ?c_long {
    var val: c_long = 0;
    if (Curl.curl_easy_getinfo(handle, info, &val) == Curl.CURLE_OK) return val;
    return null;
}

fn getStr(handle: *Curl.CURL, info: Curl.CURLINFO) ?[]const u8 {
    var ptr: [*c]const u8 = null;
    if (Curl.curl_easy_getinfo(handle, info, &ptr) == Curl.CURLE_OK) {
        if (ptr) |p| return std.mem.sliceTo(p, 0);
    }
    return null;
}

const max_body_store = 256 * 1024; // 256KB cap

const BodyAccum = struct {
    buf: std.ArrayListUnmanaged(u8) = .empty,
    alloc: std.mem.Allocator,
    total: usize = 0,

    fn init(alloc: std.mem.Allocator) BodyAccum {
        return .{ .alloc = alloc };
    }

    fn reset(self: *BodyAccum) void {
        self.buf.clearRetainingCapacity();
        self.total = 0;
    }

    fn deinit(self: *BodyAccum) void {
        self.buf.deinit(self.alloc);
    }

    fn body(self: *const BodyAccum) []const u8 {
        return self.buf.items;
    }
};

fn bodyWriteCallback(ptr: [*c]c_char, size: c_uint, nmemb: c_uint, user_data: *anyopaque) callconv(.c) c_uint {
    const total = size * nmemb;
    const acc: *BodyAccum = @ptrCast(@alignCast(user_data));
    acc.total += total;
    if (acc.buf.items.len < max_body_store) {
        const src: [*]const u8 = @ptrCast(ptr);
        const to_store = @min(total, max_body_store - acc.buf.items.len);
        acc.buf.appendSlice(acc.alloc, src[0..to_store]) catch {};
    }
    return total;
}

// ── Cert info extraction ─────────────────────────────────────────────
fn extractCertField(slist: [*c]Curl.struct_curl_slist, prefix: []const u8) ?[]const u8 {
    var node = slist;
    while (node != null) : (node = node.*.next) {
        if (node.*.data) |data_ptr| {
            const entry = std.mem.sliceTo(data_ptr, 0);
            if (std.mem.startsWith(u8, entry, prefix)) {
                return entry[prefix.len..];
            }
        }
    }
    return null;
}

// ── Stats tracker ────────────────────────────────────────────────────
const Sampler = struct {
    count: u32 = 0,
    sum: f64 = 0,
    min: f64 = std.math.inf(f64),
    max: f64 = 0,

    fn add(self: *Sampler, val: f64) void {
        self.count += 1;
        self.sum += val;
        if (val < self.min) self.min = val;
        if (val > self.max) self.max = val;
    }

    fn avg(self: Sampler) f64 {
        if (self.count == 0) return 0;
        return self.sum / @as(f64, @floatFromInt(self.count));
    }
};

const Stats = struct {
    runs: u32 = 0,
    total: Sampler = .{},
    dns: Sampler = .{},
    connect: Sampler = .{},
    tls: Sampler = .{},
    ttfb: Sampler = .{},
    download: Sampler = .{},
};

// ── Format buffers ───────────────────────────────────────────────────
const FmtBufs = struct {
    status: [64]u8 = undefined,
    size: [32]u8 = undefined,
    redir: [256]u8 = undefined,
    dns: [64]u8 = undefined,
    conn: [64]u8 = undefined,
    tls: [64]u8 = undefined,
    ttfb: [64]u8 = undefined,
    dl: [64]u8 = undefined,
    total: [64]u8 = undefined,
    // Per-phase stats detail buffers
    dns_st: [128]u8 = undefined,
    conn_st: [128]u8 = undefined,
    tls_st: [128]u8 = undefined,
    ttfb_st: [128]u8 = undefined,
    dl_st: [128]u8 = undefined,
    total_st: [128]u8 = undefined,
    err_prev: [96]u8 = undefined,
    body_val: [64]u8 = undefined,
};

// ── Row ──────────────────────────────────────────────────────────────
const Row = struct {
    label: []const u8,
    value: []const u8,
    detail: ?[]const u8 = null,
    body_ref: ?*const BodyAccum = null, // for Body row: full content
    bar_frac: ?f64 = null,
    follow_url: ?[:0]const u8 = null,
};

fn getTermSize() struct { rows: u16, cols: u16 } {
    var ws: posix.winsize = undefined;
    const rc = std.os.linux.ioctl(posix.STDOUT_FILENO, std.os.linux.T.IOCGWINSZ, @intFromPtr(&ws));
    if (rc == 0) return .{ .rows = ws.row, .cols = ws.col };
    return .{ .rows = 24, .cols = 80 };
}

// ── Terminal raw mode ─────────────────────────────────────────────────
const RawTerm = struct {
    orig: posix.termios,

    fn enter() !RawTerm {
        var t = posix.tcgetattr(posix.STDIN_FILENO) catch return error.NotATty;
        const orig = t;
        t.lflag.ECHO = false;
        t.lflag.ICANON = false;
        t.lflag.ISIG = false;
        t.cc[@intFromEnum(posix.V.MIN)] = 1;
        t.cc[@intFromEnum(posix.V.TIME)] = 0;
        try posix.tcsetattr(posix.STDIN_FILENO, .FLUSH, t);
        return .{ .orig = orig };
    }

    fn leave(self: RawTerm) void {
        posix.tcsetattr(posix.STDIN_FILENO, .FLUSH, self.orig) catch {};
    }
};

// ── Usage ─────────────────────────────────────────────────────────────
const usage =
    \\zur — quick check on an HTTP endpoint
    \\
    \\Usage: zur [options] <url>
    \\
    \\Options:
    \\  -X <method>     HTTP method (default: GET)
    \\  -H <header>     Add header (repeatable, "Name: Value")
    \\  -d <data>       Request body (implies POST)
    \\  -k              Skip TLS verification
    \\  --no-follow     Disable following redirects
    \\  -q              Quiet mode (exit code only)
    \\  -h, --help      Show this help
    \\
    \\TUI: ↑/↓ navigate  ⏎ details  r retry  q quit
    \\
;

// ── Main ──────────────────────────────────────────────────────────────
pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stderr_file = std.fs.File{ .handle = posix.STDERR_FILENO };
    var err_buf: [4096]u8 = undefined;
    var ew = stderr_file.writer(&err_buf);
    const err_ = &ew.interface;

    // Parse args
    var url_arg: ?[:0]const u8 = null;
    var method_arg: ?[]const u8 = null;
    var body_arg: ?[]const u8 = null;
    var skip_verify = false;
    var quiet = false;
    var follow_redirects = true;
    var header_list: std.ArrayListUnmanaged([:0]const u8) = .empty;
    defer header_list.deinit(allocator);

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            const stdout_file = std.fs.File{ .handle = posix.STDOUT_FILENO };
            var ob: [4096]u8 = undefined;
            var ow = stdout_file.writer(&ob);
            try ow.interface.writeAll(usage);
            try ow.interface.flush();
            return;
        } else if (std.mem.eql(u8, arg, "-X")) {
            i += 1;
            if (i >= args.len) { try err_.writeAll("zur: -X requires a method\n"); try err_.flush(); std.process.exit(1); }
            method_arg = args[i];
        } else if (std.mem.eql(u8, arg, "-H")) {
            i += 1;
            if (i >= args.len) { try err_.writeAll("zur: -H requires a header\n"); try err_.flush(); std.process.exit(1); }
            try header_list.append(allocator, args[i]);
        } else if (std.mem.eql(u8, arg, "-d")) {
            i += 1;
            if (i >= args.len) { try err_.writeAll("zur: -d requires data\n"); try err_.flush(); std.process.exit(1); }
            body_arg = args[i];
        } else if (std.mem.eql(u8, arg, "-k")) {
            skip_verify = true;
        } else if (std.mem.eql(u8, arg, "-q")) {
            quiet = true;
        } else if (std.mem.eql(u8, arg, "--no-follow")) {
            follow_redirects = false;
        } else if (arg.len > 0 and arg[0] != '-') {
            url_arg = arg;
        } else {
            try err_.print("zur: unknown option '{s}'\n", .{arg});
            try err_.flush();
            std.process.exit(1);
        }
    }

    const target_url: [:0]const u8 = url_arg orelse {
        try err_.writeAll("zur: no URL provided\n\n");
        try err_.writeAll(usage);
        try err_.flush();
        std.process.exit(1);
    };

    // Init curl
    const ca_bundle = curl.allocCABundle(allocator) catch null;
    defer if (ca_bundle) |cab| cab.deinit();

    var easy = curl.Easy.init(.{ .ca_bundle = ca_bundle }) catch |e| {
        try err_.print("zur: curl init failed: {}\n", .{e});
        try err_.flush();
        std.process.exit(1);
    };
    defer easy.deinit();

    const handle = easy.handle;

    if (skip_verify) {
        _ = Curl.curl_easy_setopt(handle, Curl.CURLOPT_SSL_VERIFYPEER, @as(c_long, 0));
        _ = Curl.curl_easy_setopt(handle, Curl.CURLOPT_SSL_VERIFYHOST, @as(c_long, 0));
    }
    if (follow_redirects) {
        try easy.setFollowLocation(true);
        try easy.setMaxRedirects(10);
    }

    const m: curl.Easy.Method = if (method_arg) |mstr| blk: {
        var buf: [16]u8 = .{0} ** 16;
        const len = @min(mstr.len, 16);
        for (0..len) |j| buf[j] = std.ascii.toUpper(mstr[j]);
        const upper = buf[0..len];
        if (std.mem.eql(u8, upper, "GET")) break :blk .GET;
        if (std.mem.eql(u8, upper, "POST")) break :blk .POST;
        if (std.mem.eql(u8, upper, "PUT")) break :blk .PUT;
        if (std.mem.eql(u8, upper, "DELETE")) break :blk .DELETE;
        if (std.mem.eql(u8, upper, "PATCH")) break :blk .PATCH;
        if (std.mem.eql(u8, upper, "HEAD")) break :blk .HEAD;
        try err_.print("zur: unsupported method '{s}'\n", .{mstr});
        try err_.flush();
        std.process.exit(1);
    } else if (body_arg != null) .POST else .GET;

    _ = Curl.curl_easy_setopt(handle, Curl.CURLOPT_CERTINFO, @as(c_long, 1));

    var body_acc = BodyAccum.init(allocator);
    defer body_acc.deinit();
    try easy.setWritefunction(bodyWriteCallback);
    _ = Curl.curl_easy_setopt(handle, Curl.CURLOPT_WRITEDATA, @as(*anyopaque, @ptrCast(&body_acc)));

    var fetch_opts: curl.Easy.FetchOptions = .{ .method = m, .body = body_arg };
    if (header_list.items.len > 0) fetch_opts.headers = header_list.items;

    // ── Stats across retries ──────────────────────────────────────────
    var stats: Stats = .{};

    var bufs: FmtBufs = undefined;

    var rows: std.ArrayListUnmanaged(Row) = .empty;
    defer {
        for (rows.items) |row| {
            if (row.follow_url) |furl| allocator.free(furl);
        }
        rows.deinit(allocator);
    }

    // Current state
    var status: u32 = 0;
    var failed = false;
    var content_type_str: []const u8 = "";

    // ── Fetch + build rows (called on first run and each retry) ───────
    const doFetch = struct {
        fn run(
            e: *curl.Easy,
            h: *Curl.CURL,
            turl: [:0]const u8,
            fopts: curl.Easy.FetchOptions,
            bacc: *BodyAccum,
            st: *Stats,
            rw: *std.ArrayListUnmanaged(Row),
            alloc: std.mem.Allocator,
            b: *FmtBufs,
        ) !struct { status: u32, failed: bool } {
            // Free old follow_urls
            for (rw.items) |row| {
                if (row.follow_url) |furl| alloc.free(furl);
            }
            rw.clearRetainingCapacity();

            bacc.reset();

            const resp = e.fetch(turl, fopts) catch {
                st.runs += 1;
                // Build error rows so TUI can display the failure
                try rw.append(alloc, .{
                    .label = "Status",
                    .value = "✗ FAILED",
                    .detail = if (e.diagnostics.getMessage()) |msg| msg else "Connection failed",
                });
                if (st.runs > 1) {
                    const tt = fmtTime(st.total.avg());
                    try rw.append(alloc, .{
                        .label = "Prev avg",
                        .value = std.fmt.bufPrint(&b.err_prev, "{d:.1} {s}  ×{d} ok", .{ tt.val, tt.unit, st.total.count }) catch "?",
                    });
                }
                return .{ .status = 0, .failed = true };
            };

            const stat: u32 = @intCast(resp.status_code);
            st.runs += 1;

            // Timing
            const dns_time = getDouble(h, Curl.CURLINFO_NAMELOOKUP_TIME) orelse 0;
            const connect_time = getDouble(h, Curl.CURLINFO_CONNECT_TIME) orelse 0;
            const tls_time = getDouble(h, Curl.CURLINFO_APPCONNECT_TIME) orelse 0;
            const start_transfer = getDouble(h, Curl.CURLINFO_STARTTRANSFER_TIME) orelse 0;
            const total_time = getDouble(h, Curl.CURLINFO_TOTAL_TIME) orelse 0;
            const download_size: f64 = @floatFromInt(bacc.total);
            const redirect_count = getLong(h, Curl.CURLINFO_REDIRECT_COUNT) orelse 0;
            const effective_url = getStr(h, Curl.CURLINFO_EFFECTIVE_URL);
            const content_type = getStr(h, Curl.CURLINFO_CONTENT_TYPE);
            const ip = getStr(h, Curl.CURLINFO_PRIMARY_IP);
            const scheme = getStr(h, Curl.CURLINFO_SCHEME);
            const ssl_verify: ?c_long = getLong(h, Curl.CURLINFO_SSL_VERIFYRESULT);

            // Update stats
            st.total.add(total_time);
            if (dns_time > 0.0001) st.dns.add(dns_time);
            const conn_dt = if (connect_time > dns_time + 0.0001) connect_time - dns_time else 0;
            if (conn_dt > 0.0001) st.connect.add(conn_dt);
            const tls_dt = if (tls_time > connect_time + 0.0001) tls_time - connect_time else 0;
            if (tls_dt > 0.0001) st.tls.add(tls_dt);
            const base = @max(tls_time, connect_time);
            const ttfb_dt = if (start_transfer > base + 0.0001) start_transfer - base else 0;
            if (ttfb_dt > 0.0001) st.ttfb.add(ttfb_dt);
            const dl_dt = if (total_time > start_transfer + 0.0001) total_time - start_transfer else 0;
            if (dl_dt > 0.0001) st.download.add(dl_dt);

            // Cert info
            var cert_subject: ?[]const u8 = null;
            var cert_issuer: ?[]const u8 = null;
            var cert_expire: ?[]const u8 = null;
            {
                var ci: ?*Curl.struct_curl_certinfo = null;
                if (Curl.curl_easy_getinfo(h, Curl.CURLINFO_CERTINFO, &ci) == Curl.CURLE_OK) {
                    if (ci) |info| {
                        if (info.num_of_certs > 0) {
                            const first_cert = info.certinfo[0];
                            cert_subject = extractCertField(first_cert, "Subject:");
                            cert_issuer = extractCertField(first_cert, "Issuer:");
                            cert_expire = extractCertField(first_cert, "Expire date:");
                        }
                    }
                }
            }

            const is_https = if (scheme) |s| std.ascii.eqlIgnoreCase(s, "https") else (tls_time > 0.0001);
            const total_ms = total_time * 1000;
            const has_stats = st.runs > 1;

            // ── Build rows ───────────────────────────────────────────
            const status_str = std.fmt.bufPrint(&b.status, "{d}", .{stat}) catch "???";
            try rw.append(alloc, .{
                .label = "Status",
                .value = status_str,
                .detail = if (stat >= 200 and stat < 300) "OK" else if (stat >= 300 and stat < 400) "Redirect" else if (stat >= 400 and stat < 500) "Client Error" else if (stat >= 500) "Server Error" else null,
            });

            if (ip) |addr| try rw.append(alloc, .{ .label = "IP", .value = addr });
            if (content_type) |ct| try rw.append(alloc, .{ .label = "Content-Type", .value = ct });

            if (download_size > 0) {
                const sz = fmtBytes(download_size);
                const truncated = bacc.total > max_body_store;
                const size_str = if (truncated)
                    std.fmt.bufPrint(&b.size, "{d:.1} {s} (truncated)", .{ sz.val, sz.unit }) catch "?"
                else
                    std.fmt.bufPrint(&b.size, "{d:.1} {s}", .{ sz.val, sz.unit }) catch "?";
                try rw.append(alloc, .{ .label = "Size", .value = size_str });
            }

            // Body row — show size, Enter opens full-screen viewer
            if (bacc.body().len > 0) {
                const sz = fmtBytes(@floatFromInt(bacc.total));
                const truncated = bacc.total > max_body_store;
                const body_label = if (truncated)
                    std.fmt.bufPrint(&b.body_val, "{d:.1} {s} ⏎ view (truncated)", .{ sz.val, sz.unit }) catch "⏎ view"
                else
                    std.fmt.bufPrint(&b.body_val, "{d:.1} {s} ⏎ view", .{ sz.val, sz.unit }) catch "⏎ view";
                try rw.append(alloc, .{
                    .label = "Body",
                    .value = body_label,
                    .body_ref = bacc,
                });
            }

            if (redirect_count > 0) {
                if (effective_url) |eu| {
                    const redir_str = std.fmt.bufPrint(&b.redir, "{d}x → {s}", .{ redirect_count, eu }) catch eu;
                    const follow = try alloc.dupeZ(u8, eu);
                    try rw.append(alloc, .{
                        .label = "Redirected",
                        .value = redir_str,
                        .detail = "⏎ to check this URL",
                        .follow_url = follow,
                    });
                }
            }

            // TLS / cert
            if (is_https) {
                const verify_ok = if (ssl_verify) |v| v == 0 else false;
                try rw.append(alloc, .{
                    .label = "TLS",
                    .value = if (verify_ok) "✓ verified" else "⚠ unverified",
                    .detail = if (cert_subject) |subj| subj else null,
                });
                if (cert_issuer) |issuer| try rw.append(alloc, .{ .label = "Issuer", .value = issuer });
                if (cert_expire) |expire| try rw.append(alloc, .{ .label = "Expires", .value = expire });
            } else {
                try rw.append(alloc, .{ .label = "TLS", .value = "✗ plain HTTP (no SSL)" });
            }

            // Separator
            try rw.append(alloc, .{ .label = "─────────", .value = "──────────────────" });

            // Timing rows — each phase has its own value + stats buffer
            if (dns_time > 0.0001) {
                try rw.append(alloc, .{
                    .label = "DNS",
                    .value = fmtTimeBuf(&b.dns, dns_time),
                    .bar_frac = if (total_ms > 0) (dns_time * 1000) / total_ms else 0,
                    .detail = if (has_stats and st.dns.count > 1) fmtStatsLine(&b.dns_st, st.dns) else null,
                });
            }
            if (conn_dt > 0.0001) {
                try rw.append(alloc, .{
                    .label = "Connect",
                    .value = fmtTimeBuf(&b.conn, conn_dt),
                    .bar_frac = if (total_ms > 0) (conn_dt * 1000) / total_ms else 0,
                    .detail = if (has_stats and st.connect.count > 1) fmtStatsLine(&b.conn_st, st.connect) else null,
                });
            }
            if (tls_dt > 0.0001) {
                try rw.append(alloc, .{
                    .label = "TLS handshk",
                    .value = fmtTimeBuf(&b.tls, tls_dt),
                    .bar_frac = if (total_ms > 0) (tls_dt * 1000) / total_ms else 0,
                    .detail = if (has_stats and st.tls.count > 1) fmtStatsLine(&b.tls_st, st.tls) else null,
                });
            }
            if (ttfb_dt > 0.0001) {
                try rw.append(alloc, .{
                    .label = "First Byte",
                    .value = fmtTimeBuf(&b.ttfb, ttfb_dt),
                    .bar_frac = if (total_ms > 0) (ttfb_dt * 1000) / total_ms else 0,
                    .detail = if (has_stats and st.ttfb.count > 1) fmtStatsLine(&b.ttfb_st, st.ttfb) else null,
                });
            }
            if (dl_dt > 0.0001) {
                try rw.append(alloc, .{
                    .label = "Download",
                    .value = fmtTimeBuf(&b.dl, dl_dt),
                    .bar_frac = if (total_ms > 0) (dl_dt * 1000) / total_ms else 0,
                    .detail = if (has_stats and st.download.count > 1) fmtStatsLine(&b.dl_st, st.download) else null,
                });
            }

            // Total row
            try rw.append(alloc, .{
                .label = "Total",
                .value = fmtTimeBuf(&b.total, total_time),
                .detail = if (has_stats) fmtStatsLine(&b.total_st, st.total) else @as(?[]const u8, "End-to-end request time"),
            });

            return .{ .status = stat, .failed = false };
        }
    }.run;

    // ── Initial fetch ─────────────────────────────────────────────────
    const result = try doFetch(
        &easy, handle, target_url, fetch_opts, &body_acc, &stats, &rows, allocator, &bufs,
    );
    status = result.status;
    failed = result.failed;
    content_type_str = getStr(handle, Curl.CURLINFO_CONTENT_TYPE) orelse "";

    if (failed) {
        if (quiet) std.process.exit(1);
        try err_.print(esc.red ++ "✗" ++ esc.reset ++ " {s}\n", .{target_url});
        if (easy.diagnostics.getMessage()) |msg| try err_.print("  {s}\n", .{msg});
        try err_.flush();
        std.process.exit(1);
    }

    if (quiet) std.process.exit(if (status >= 200 and status < 400) 0 else 1);

    // ── Non-interactive output ────────────────────────────────────────
    const is_tty = posix.isatty(posix.STDOUT_FILENO) and posix.isatty(posix.STDIN_FILENO);

    if (!is_tty) {
        const stdout_file = std.fs.File{ .handle = posix.STDOUT_FILENO };
        var ob: [8192]u8 = undefined;
        var ow = stdout_file.writer(&ob);
        const out = &ow.interface;
        for (rows.items) |row| {
            try out.print("{s:<14} {s}\n", .{ row.label, row.value });
        }
        try out.flush();
        return;
    }

    // ── TUI loop ──────────────────────────────────────────────────────
    const raw = RawTerm.enter() catch {
        const stdout_file = std.fs.File{ .handle = posix.STDOUT_FILENO };
        var ob: [8192]u8 = undefined;
        var ow = stdout_file.writer(&ob);
        const out = &ow.interface;
        for (rows.items) |row| {
            try out.print("{s:<14} {s}\n", .{ row.label, row.value });
        }
        try out.flush();
        return;
    };
    defer raw.leave();

    const stdout_file = std.fs.File{ .handle = posix.STDOUT_FILENO };
    var ob: [16384]u8 = undefined;
    var ow = stdout_file.writer(&ob);
    const out = &ow.interface;

    var cursor: usize = 0;
    var show_detail = false;

    while (true) {
        // Clear and draw
        try out.writeAll(esc.hide_cursor ++ esc.clear);

        // Header
        try out.writeAll(esc.bold ++ " zur" ++ esc.reset ++ "  ");
        if (failed) {
            try out.writeAll(esc.red ++ "FAIL" ++ esc.reset);
        } else {
            try out.writeAll(colorForStatus(status));
            try out.print("{d}", .{status});
            try out.writeAll(esc.reset);
        }
        try out.writeAll("  ");
        try out.writeAll(esc.dim);
        try out.writeAll(target_url);
        try out.writeAll(esc.reset);

        // Retry counter in header
        if (stats.runs > 1) {
            try out.writeAll("  ");
            try out.writeAll(esc.cyan);
            try out.print("#{d}", .{stats.runs});
            try out.writeAll(esc.reset);
            // Compact avg total
            try out.writeAll(esc.dim);
            const avg_t = fmtTime(stats.total.avg());
            try out.print("  avg {d:.0}{s}", .{ avg_t.val, avg_t.unit });
            try out.writeAll(esc.reset);
        }

        try out.writeByte('\n');
        try out.writeAll(esc.dim ++ " ─────────────────────────────────────────────" ++ esc.reset ++ "\n");

        // Rows
        for (rows.items, 0..) |row, idx| {
            const selected = idx == cursor;

            if (selected) try out.writeAll(esc.reverse);

            try out.print(" {s:<14}", .{row.label});

            if (row.bar_frac) |frac| {
                try out.print(" {s:<10} ", .{row.value});
                if (!selected) try out.writeAll(esc.cyan);
                const bar_w: u16 = 20;
                const filled: u16 = @intFromFloat(@min(@as(f64, @floatFromInt(bar_w)), frac * @as(f64, @floatFromInt(bar_w))));
                for (0..filled) |_| try out.writeAll("█");
                if (!selected) try out.writeAll(esc.dim);
                for (0..bar_w - filled) |_| try out.writeAll("░");
                if (!selected) try out.writeAll(esc.reset);
            } else {
                try out.print(" {s}", .{row.value});
            }

            if (selected) try out.writeAll(esc.reset);
            try out.writeByte('\n');

            // Detail panel (expanded) — not for body (body uses full-screen)
            if (selected and show_detail and row.body_ref == null) {
                if (row.detail) |detail| {
                    try out.writeAll(esc.dim ++ "   ↳ " ++ esc.reset);
                    try out.writeAll(detail);
                    try out.writeByte('\n');
                }
            }
        }

        // Footer
        try out.writeAll("\n" ++ esc.dim ++ " ↑↓ navigate  ⏎ details  r retry  q quit" ++ esc.reset);

        try out.flush();

        // Read key
        var read_buf: [8]u8 = undefined;
        const n = posix.read(posix.STDIN_FILENO, &read_buf) catch break;
        if (n == 0) break;

        const key = read_buf[0..n];
        if (key.len == 1) {
            switch (key[0]) {
                'q', 27 => break,
                'j', 'J' => {
                    if (cursor + 1 < rows.items.len) cursor += 1;
                    show_detail = false;
                },
                'k', 'K' => {
                    if (cursor > 0) cursor -= 1;
                    show_detail = false;
                },
                '\r', '\n' => {
                    // Follow redirect URL
                    if (rows.items[cursor].follow_url) |furl| {
                        raw.leave();
                        try out.writeAll(esc.show_cursor);
                        try out.flush();
                        var new_args: std.ArrayListUnmanaged([]const u8) = .empty;
                        defer new_args.deinit(allocator);
                        for (args) |a| {
                            if (a.ptr == target_url.ptr) continue;
                            try new_args.append(allocator, a);
                        }
                        try new_args.append(allocator, furl);
                        std.process.execve(allocator, new_args.items, null) catch {};
                        break;
                    }
                    // Full-screen body viewer
                    if (rows.items[cursor].body_ref) |bref| {
                        try bodyViewer(out, bref, target_url, content_type_str);
                        continue; // redraw overview
                    }
                    show_detail = !show_detail;
                },
                'r', 'R' => {
                    // In-process retry: re-fetch and rebuild rows
                    const r = doFetch(
                        &easy, handle, target_url, fetch_opts, &body_acc, &stats, &rows, allocator, &bufs,
                    ) catch continue;
                    status = r.status;
                    failed = r.failed;
                    content_type_str = getStr(handle, Curl.CURLINFO_CONTENT_TYPE) orelse "";
                    show_detail = false;
                    // Keep cursor in bounds
                    if (cursor >= rows.items.len and rows.items.len > 0) cursor = rows.items.len - 1;
                },
                else => {},
            }
        } else if (key.len >= 3 and key[0] == 27 and key[1] == '[') {
            switch (key[2]) {
                'A' => { // Up
                    if (cursor > 0) cursor -= 1;
                    show_detail = false;
                },
                'B' => { // Down
                    if (cursor + 1 < rows.items.len) cursor += 1;
                    show_detail = false;
                },
                else => {},
            }
        }
    }

    try out.writeAll(esc.show_cursor ++ esc.clear);
    try out.flush();
}

fn bodyViewer(out: *std.Io.Writer, bref: *const BodyAccum, url: []const u8, ctype: []const u8) !void {
    const body_data = bref.body();
    var scroll: usize = 0;

    // Count total lines
    var total_lines: usize = 1;
    for (body_data) |ch| {
        if (ch == '\n') total_lines += 1;
    }

    while (true) {
        const term = getTermSize();
        const view_h: usize = @as(usize, term.rows) -| 3; // header + footer
        const view_w: usize = @as(usize, term.cols) -| 2;

        try out.writeAll(esc.hide_cursor ++ esc.clear);

        // Header
        try out.writeAll(esc.bold ++ " Body" ++ esc.reset ++ "  ");
        try out.writeAll(esc.dim);
        try out.writeAll(url);
        if (ctype.len > 0) {
            try out.writeAll("  ");
            try out.writeAll(ctype);
        }
        try out.writeAll(esc.reset ++ "\n");

        // Separator
        try out.writeAll(esc.dim);
        var sep_i: usize = 0;
        while (sep_i < @min(view_w + 1, 60)) : (sep_i += 1) try out.writeAll("─");
        try out.writeAll(esc.reset ++ "\n");

        // Body lines
        var line_start: usize = 0;
        var line_num: usize = 0;
        var displayed: usize = 0;
        while (line_start <= body_data.len and displayed < view_h) {
            if (line_start == body_data.len) break;
            const nl = std.mem.indexOfScalarPos(u8, body_data, line_start, '\n') orelse body_data.len;
            if (line_num >= scroll) {
                // Line number gutter
                try out.writeAll(esc.dim);
                try out.print("{d:>4}│" ++ esc.reset, .{line_num + 1});
                const line_end = @min(nl, line_start + view_w -| 5);
                try out.writeAll(body_data[line_start..line_end]);
                try out.writeByte('\n');
                displayed += 1;
            }
            line_start = nl + 1;
            line_num += 1;
        }

        // Footer
        const sz = fmtBytes(@floatFromInt(bref.total));
        try out.writeAll(esc.dim);
        try out.print("\n {d}/{d} lines  {d:.1} {s}  ↑↓/j/k scroll  q/Esc back", .{
            @min(scroll + view_h, total_lines),
            total_lines,
            sz.val,
            sz.unit,
        });
        try out.writeAll(esc.reset);

        try out.flush();

        // Key input
        var read_buf: [8]u8 = undefined;
        const n = posix.read(posix.STDIN_FILENO, &read_buf) catch return;
        if (n == 0) return;

        const key = read_buf[0..n];
        if (key.len == 1) {
            switch (key[0]) {
                'q', 27 => return,
                'j', 'J' => scroll += 1,
                'k', 'K' => {
                    if (scroll > 0) scroll -= 1;
                },
                ' ' => scroll +|= view_h, // page down
                'g' => scroll = 0, // top
                'G' => scroll = total_lines -| view_h, // bottom
                else => {},
            }
        } else if (key.len >= 3 and key[0] == 27 and key[1] == '[') {
            switch (key[2]) {
                'A' => {
                    if (scroll > 0) scroll -= 1;
                },
                'B' => scroll += 1,
                '5' => scroll -|= view_h, // Page Up
                '6' => scroll +|= view_h, // Page Down
                else => {},
            }
        }

        // Clamp scroll
        if (total_lines > view_h) {
            if (scroll > total_lines - view_h) scroll = total_lines - view_h;
        } else {
            scroll = 0;
        }
    }
}

fn fmtStatsLine(buf: *[128]u8, s: Sampler) ?[]const u8 {
    if (s.count <= 1) return null;
    var tmp1: [16]u8 = undefined;
    var tmp2: [16]u8 = undefined;
    var tmp3: [16]u8 = undefined;
    return std.fmt.bufPrint(buf, "avg {s}  min {s}  max {s}  ×{d}", .{
        fmtTimeBuf(&tmp1, s.avg()),
        fmtTimeBuf(&tmp2, s.min),
        fmtTimeBuf(&tmp3, s.max),
        s.count,
    }) catch null;
}
