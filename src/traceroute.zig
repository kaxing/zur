// TCP SYN traceroute — no root needed, passes most firewalls.
// Falls back to system `traceroute` on non-Linux.

const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const native_os = builtin.os.tag;
const linux = if (native_os == .linux) std.os.linux else undefined;

pub const Backend = enum { tcp_syn, system };
pub const backend: Backend = if (native_os == .linux) .tcp_syn else .system;

const IP_TTL: u32 = 2;
const IP_RECVERR: u32 = 11;
const SOL_IP: i32 = 0;
const SOL_SOCKET: i32 = 1;
const SO_LINGER: u32 = 13;
const SO_ERROR: u32 = 4;

const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_DEST_UNREACH: u8 = 3;

const SockExtendedErr = extern struct {
    ee_errno: u32,
    ee_origin: u8,
    ee_type: u8,
    ee_code: u8,
    ee_pad: u8,
    ee_info: u32,
    ee_data: u32,
};

const Linger = extern struct {
    l_onoff: c_int,
    l_linger: c_int,
};

pub const Hop = struct {
    ttl: u8,
    addr_buf: [46]u8 = .{0} ** 46,
    addr_len: u8 = 0,
    rtt_us: i64 = -1,
    reached: bool = false,

    pub fn addr(self: *const Hop) ?[]const u8 {
        if (self.addr_len == 0) return null;
        return self.addr_buf[0..self.addr_len];
    }
};

pub const Tracer = if (native_os == .linux) LinuxTracer else SystemTracer;

const LinuxTracer = struct {
    dest_addr: u32,
    port: u16,

    pub fn init(ip_str: []const u8, port: u16) !Tracer {
        const address = std.net.Address.resolveIp(ip_str, port) catch return error.InvalidAddress;
        return .{
            .dest_addr = address.in.sa.addr,
            .port = address.in.sa.port,
        };
    }

    pub fn probe(self: *const Tracer, ttl: u8, timeout_ms: i32) Hop {
        var result = Hop{ .ttl = ttl };

        const sock = posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM | posix.SOCK.NONBLOCK,
            posix.IPPROTO.TCP,
        ) catch return result;
        defer posix.close(sock);

        const ttl_val: c_int = @intCast(ttl);
        posix.setsockopt(sock, SOL_IP, IP_TTL, std.mem.asBytes(&ttl_val)) catch return result;

        const one: c_int = 1;
        posix.setsockopt(sock, SOL_IP, IP_RECVERR, std.mem.asBytes(&one)) catch return result;

        // RST on close instead of TIME_WAIT
        const linger = Linger{ .l_onoff = 1, .l_linger = 0 };
        posix.setsockopt(sock, SOL_SOCKET, SO_LINGER, std.mem.asBytes(&linger)) catch {};

        var dest: linux.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = self.port,
            .addr = self.dest_addr,
            .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };

        const start = std.time.microTimestamp();
        posix.connect(sock, @ptrCast(&dest), @sizeOf(linux.sockaddr.in)) catch |err| {
            if (err != error.WouldBlock) return result;
        };

        // POLLOUT = destination reached, POLLERR = ICMP error (intermediate hop)
        var pfd = [1]linux.pollfd{.{
            .fd = sock,
            .events = @as(i16, linux.POLL.OUT | linux.POLL.ERR),
            .revents = 0,
        }};
        const poll_rc = linux.poll(&pfd, 1, timeout_ms);
        if (@as(isize, @bitCast(poll_rc)) <= 0) return result;

        result.rtt_us = std.time.microTimestamp() - start;

        if (pfd[0].revents & linux.POLL.ERR != 0) {
            self.readErrorQueue(sock, &result);
        } else if (pfd[0].revents & linux.POLL.OUT != 0) {
            result.reached = true;
            const ip_bytes: [4]u8 = @bitCast(self.dest_addr);
            const formatted = std.fmt.bufPrint(&result.addr_buf, "{d}.{d}.{d}.{d}", .{
                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
            }) catch return result;
            result.addr_len = @intCast(formatted.len);
        }

        return result;
    }

    /// Extract ICMP sender IP from the socket error queue (MSG_ERRQUEUE)
    fn readErrorQueue(self: *const Tracer, sock: posix.fd_t, result: *Hop) void {
        _ = self;
        var msg_buf: [512]u8 = undefined;
        var ctrl_buf: [512]u8 align(@alignOf(CmsgHdr)) = undefined;
        var name_buf: linux.sockaddr.in = undefined;

        var iov: posix.iovec = .{
            .base = &msg_buf,
            .len = msg_buf.len,
        };

        var msg: linux.msghdr = .{
            .name = @ptrCast(&name_buf),
            .namelen = @sizeOf(linux.sockaddr.in),
            .iov = @ptrCast(&iov),
            .iovlen = 1,
            .control = @ptrCast(&ctrl_buf),
            .controllen = ctrl_buf.len,
            .flags = 0,
        };

        const rc = linux.recvmsg(sock, &msg, linux.MSG.ERRQUEUE);
        const signed: isize = @bitCast(rc);
        if (signed < 0) return;

        // Walk cmsg headers — copy fields individually to avoid alignment traps
        const ctrl_bytes: [*]const u8 = @ptrCast(&ctrl_buf);
        var offset: usize = 0;
        while (offset + @sizeOf(CmsgHdr) <= msg.controllen) {
            var cmsg_len: usize = 0;
            var cmsg_level: i32 = 0;
            var cmsg_type: u32 = 0;
            @memcpy(std.mem.asBytes(&cmsg_len), ctrl_bytes[offset..][0..@sizeOf(usize)]);
            @memcpy(std.mem.asBytes(&cmsg_level), ctrl_bytes[offset + @sizeOf(usize) ..][0..@sizeOf(i32)]);
            @memcpy(std.mem.asBytes(&cmsg_type), ctrl_bytes[offset + @sizeOf(usize) + @sizeOf(i32) ..][0..@sizeOf(u32)]);

            if (cmsg_len < @sizeOf(CmsgHdr)) break;

            if (cmsg_level == SOL_IP and cmsg_type == IP_RECVERR) {
                const data_start = offset + cmsgAlign(@sizeOf(CmsgHdr));
                if (data_start + @sizeOf(SockExtendedErr) + @sizeOf(linux.sockaddr.in) <= msg.controllen) {
                    var see: SockExtendedErr = undefined;
                    @memcpy(std.mem.asBytes(&see), ctrl_bytes[data_start..][0..@sizeOf(SockExtendedErr)]);

                    var offender: linux.sockaddr.in = undefined;
                    const off_start = data_start + @sizeOf(SockExtendedErr);
                    @memcpy(std.mem.asBytes(&offender), ctrl_bytes[off_start..][0..@sizeOf(linux.sockaddr.in)]);

                    const ip_bytes: [4]u8 = @bitCast(offender.addr);
                    const formatted = std.fmt.bufPrint(&result.addr_buf, "{d}.{d}.{d}.{d}", .{
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                    }) catch return;
                    result.addr_len = @intCast(formatted.len);

                    if (see.ee_type == ICMP_DEST_UNREACH) {
                        result.reached = true;
                    }
                }
                break;
            }

            offset += cmsgAlign(cmsg_len);
        }
    }
};

const CmsgHdr = extern struct {
    len: usize,
    level: i32,
    type: u32,
};

fn cmsgAlign(len: usize) usize {
    return (len + @sizeOf(usize) - 1) & ~(@as(usize, @sizeOf(usize) - 1));
}

pub fn fmtHop(buf: []u8, hop: Hop) []const u8 {
    if (hop.addr()) |ip| {
        if (hop.rtt_us >= 0) {
            const ms = @as(f64, @floatFromInt(hop.rtt_us)) / 1000.0;
            return std.fmt.bufPrint(buf, "{d:>2}: {s:<40} {d:.2} ms{s}", .{
                hop.ttl,
                ip,
                ms,
                if (hop.reached) "  ← destination" else "",
            }) catch "?";
        }
    }
    return std.fmt.bufPrint(buf, "{d:>2}: *", .{hop.ttl}) catch "?";
}

const SystemTracer = struct {
    ip_str: []const u8,

    pub fn init(ip_str: []const u8, port: u16) !SystemTracer {
        _ = port;
        return .{ .ip_str = ip_str };
    }

    pub fn probe(_: *const SystemTracer, _: u8, _: i32) Hop {
        return Hop{ .ttl = 0 };
    }
};
