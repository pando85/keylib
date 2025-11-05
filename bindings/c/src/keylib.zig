const std = @import("std");
const allocator = std.heap.c_allocator;

// Import CTAP modules for implementation
const keylib = @import("keylib");
const uhid = @import("uhid");
const Auth = keylib.ctap.authenticator.Auth;
const User = keylib.common.User;
const RelyingParty = keylib.common.RelyingParty;
const PinUvAuth = keylib.ctap.pinuv.PinUvAuth;

// CTAPHID imports
const ctaphid = keylib.ctap.transports.ctaphid;
const CtapHid = ctaphid.authenticator.CtapHid;
const CtapHidMsg = ctaphid.authenticator.CtapHidMsg;
const CtapHidMessageIterator = ctaphid.authenticator.CtapHidMessageIterator;

pub const Error = enum(i32) {
    SUCCESS = 0,
    DoesAlreadyExist = -1,
    DoesNotExist = -2,
    KeyStoreFull = -3,
    OutOfMemory = -4,
    Timeout = -5,
    Other = -6,
};

pub const UpResult = enum(i32) {
    Denied = 0,
    Accepted = 1,
    Timeout = 2,
};

pub const UvResult = enum(i32) {
    Denied = 0,
    Accepted = 1,
    AcceptedWithUp = 2,
    Timeout = 3,
};

pub const Callbacks = extern struct {
    up: ?*const fn ([*c]const u8, [*c]const u8, [*c]const u8) callconv(.c) UpResult,
    uv: ?*const fn ([*c]const u8, [*c]const u8, [*c]const u8) callconv(.c) UvResult,
    select: ?*const fn ([*c]const u8, [*c][*c]u8) callconv(.c) c_int,
    read: ?*const fn ([*c]const u8, [*c]const u8, [*c][*c][*c]u8) callconv(.c) c_int,
    write: ?*const fn ([*c]const u8, [*c]const u8, [*c]const u8) callconv(.c) c_int,
    del: ?*const fn ([*c]const u8) callconv(.c) c_int,
    read_first: ?*const fn ([*c]const u8, [*c]const u8, [*c]const u8, [*c][*c]u8) callconv(.c) c_int,
    read_next: ?*const fn ([*c][*c]u8) callconv(.c) c_int,
};

pub const AuthSettings = extern struct {
    aaguid: [16]u8 = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
};

// Global for C callbacks (hack for single-threaded)
var c_callbacks: *Callbacks = undefined;

// Global CTAPHID instance
var ctaphid_instance: ?CtapHid = null;

// Global iterator for response packets
var current_iterator: ?CtapHidMessageIterator = null;

// Global UHID instance
var uhid_instance: ?uhid.Uhid = null;

export fn auth_init(callbacks: *Callbacks, settings: AuthSettings) ?*anyopaque {
    c_callbacks = callbacks;

    const a = allocator.create(Auth) catch {
        return null;
    };

    // Wrapper functions
    const wrapper_up = struct {
        fn f(info: []const u8, user: ?User, rp: ?RelyingParty) keylib.ctap.authenticator.callbacks.UpResult {
            if (c_callbacks.up == null) return .Denied;
            const c_info = @as([*c]const u8, @ptrCast(info.ptr));
            const c_user = if (user) |u| @as([*c]const u8, @ptrCast(u.getName().ptr)) else null;
            const c_rp = if (rp) |r| @as([*c]const u8, @ptrCast(r.id.get().ptr)) else null;
            const result = c_callbacks.up.?(c_info, c_user, c_rp);
            return switch (result) {
                .Denied => .Denied,
                .Accepted => .Accepted,
                .Timeout => .Timeout,
            };
        }
    }.f;

    const wrapper_uv = struct {
        fn f(info: []const u8, user: ?User, rp: ?RelyingParty) keylib.ctap.authenticator.callbacks.UvResult {
            if (c_callbacks.uv == null) return .Denied;
            const c_info = @as([*c]const u8, @ptrCast(info.ptr));
            const c_user = if (user) |u| @as([*c]const u8, @ptrCast(u.getName().ptr)) else null;
            const c_rp = if (rp) |r| @as([*c]const u8, @ptrCast(r.id.get().ptr)) else null;
            const result = c_callbacks.uv.?(c_info, c_user, c_rp);
            return switch (result) {
                .Denied => .Denied,
                .Accepted => .Accepted,
                .AcceptedWithUp => .AcceptedWithUp,
                .Timeout => .Timeout,
            };
        }
    }.f;

    // Stub wrappers for other callbacks
    const stub_read_first = struct {
        fn f(id: ?keylib.common.dt.ABS64B, rp: ?keylib.common.dt.ABS128T, hash: ?[32]u8) keylib.ctap.authenticator.callbacks.CallbackError!keylib.ctap.authenticator.Credential {
            _ = id;
            _ = rp;
            _ = hash;
            return error.DoesNotExist;
        }
    }.f;

    const stub_read_next = struct {
        fn f() keylib.ctap.authenticator.callbacks.CallbackError!keylib.ctap.authenticator.Credential {
            return error.DoesNotExist;
        }
    }.f;

    const stub_write = struct {
        fn f(data: keylib.ctap.authenticator.Credential) keylib.ctap.authenticator.callbacks.CallbackError!void {
            _ = data;
            return error.KeyStoreFull;
        }
    }.f;

    const stub_delete = struct {
        fn f(id: [*c]const u8) callconv(.c) keylib.ctap.authenticator.callbacks.Error {
            _ = id;
            return .DoesNotExist;
        }
    }.f;

    const stub_read_settings = struct {
        fn f() keylib.ctap.authenticator.Meta {
            return .{};
        }
    }.f;

    const stub_write_settings = struct {
        fn f(data: keylib.ctap.authenticator.Meta) void {
            _ = data;
        }
    }.f;

    a.* = Auth{
        .callbacks = .{
            .up = wrapper_up,
            .uv = wrapper_uv,
            .read_first = stub_read_first,
            .read_next = stub_read_next,
            .write = stub_write,
            .delete = stub_delete,
            .read_settings = stub_read_settings,
            .write_settings = stub_write_settings,
            .processPinHash = null,
        },
        .commands = &.{
            .{ .cmd = 0x01, .cb = keylib.ctap.commands.authenticator.authenticatorMakeCredential },
            .{ .cmd = 0x02, .cb = keylib.ctap.commands.authenticator.authenticatorGetAssertion },
            .{ .cmd = 0x04, .cb = keylib.ctap.commands.authenticator.authenticatorGetInfo },
            .{ .cmd = 0x06, .cb = keylib.ctap.commands.authenticator.authenticatorClientPin },
            .{ .cmd = 0x0b, .cb = keylib.ctap.commands.authenticator.authenticatorSelection },
        },
        .settings = .{
            .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
            .extensions = &.{"credProtect"},
            .aaguid = settings.aaguid,
            .options = .{
                .rk = true,
                .up = true,
                .uv = if (c_callbacks.uv != null) true else false,
                .plat = false,
            },
        },
        .token = PinUvAuth.v2(std.crypto.random),
        .algorithms = &.{keylib.ctap.crypto.algorithms.Es256},
        .random = std.crypto.random,
        .milliTimestamp = std.time.milliTimestamp,
    };

    return @as(*anyopaque, @ptrCast(a));
}

export fn auth_deinit(a: *anyopaque) void {
    const auth = @as(*Auth, @ptrCast(@alignCast(a)));
    allocator.destroy(auth);
}

export fn auth_handle(a: *anyopaque, m: ?*anyopaque) void {
    if (m == null) return;

    const auth = @as(*Auth, @ptrCast(@alignCast(a)));
    const msg = @as(*keylib.ctap.transports.ctaphid.authenticator.CtapHidMsg, @ptrCast(@alignCast(m.?)));

    // TODO: implement response handling
    _ = auth;
    _ = msg;
}

// UHID functions
export fn uhid_open() c_int {
    if (uhid_instance != null) {
        return -1; // Already open
    }

    uhid_instance = uhid.Uhid.open() catch return -1;
    return @intCast(uhid_instance.?.device.handle);
}

export fn uhid_read_packet(fd: c_int, out: [*c]u8) c_int {
    _ = fd; // We use the global instance

    if (uhid_instance == null) return -1;

    var buffer: [64]u8 = undefined;
    const result = uhid_instance.?.read(&buffer) orelse return 0;

    @memcpy(out[0..result.len], result);
    return @intCast(result.len);
}

export fn uhid_write_packet(fd: c_int, data: [*c]u8, len: usize) c_int {
    _ = fd; // We use the global instance

    if (uhid_instance == null) return -1;

    const slice = data[0..len];
    uhid_instance.?.write(slice) catch return -1;
    return @intCast(len);
}

export fn uhid_close(fd: c_int) void {
    _ = fd; // We use the global instance

    if (uhid_instance) |*instance| {
        instance.close();
        uhid_instance = null;
    }
}

// CTAP HID functions (stub implementations)
export fn ctaphid_init() ?*anyopaque {
    if (ctaphid_instance != null) {
        return null; // Already initialized
    }

    ctaphid_instance = CtapHid.init(allocator, std.crypto.random);
    return @as(*anyopaque, @ptrCast(&ctaphid_instance.?));
}

export fn ctaphid_deinit(a: *anyopaque) void {
    _ = a; // We use the global instance
    if (ctaphid_instance) |*instance| {
        instance.deinit();
        ctaphid_instance = null;
    }
}

export fn ctaphid_handle(a: *anyopaque, data: [*c]const u8, len: usize) ?*anyopaque {
    _ = a; // We use the global instance

    if (ctaphid_instance == null) return null;

    // Convert the C data to a slice
    const packet = data[0..len];

    // Handle the packet
    const response = ctaphid_instance.?.handle(packet) orelse return null;

    // Allocate memory for the response message and return it
    const response_copy = allocator.create(CtapHidMsg) catch return null;
    response_copy.* = response;
    return @as(*anyopaque, @ptrCast(response_copy));
}

export fn ctaphid_iterator(a: ?*anyopaque) ?*anyopaque {
    if (a == null) return null;

    const msg = @as(*CtapHidMsg, @ptrCast(@alignCast(a.?)));
    current_iterator = msg.iterator();

    // Return a dummy pointer since we use the global iterator
    return @as(*anyopaque, @ptrCast(&current_iterator.?));
}

export fn ctaphid_iterator_next(a: ?*anyopaque, out: [*c]u8) c_int {
    _ = a; // We use the global iterator

    if (current_iterator == null) return 0;

    const packet = current_iterator.?.next() orelse {
        current_iterator = null;
        return 0;
    };

    // Copy the packet data to the output buffer
    @memcpy(out[0..packet.len], packet);

    return @intCast(packet.len);
}

export fn ctaphid_iterator_deinit(a: ?*anyopaque) void {
    _ = a; // We use the global iterator
    if (current_iterator) |*iter| {
        iter.deinit();
        current_iterator = null;
    }
}

export fn ctaphid_response_get_cmd(response: ?*anyopaque) c_int {
    if (response == null) return -1;

    const msg = @as(*CtapHidMsg, @ptrCast(@alignCast(response.?)));
    return @intFromEnum(msg.cmd);
}

export fn ctaphid_response_get_data(response: ?*anyopaque, out: [*c]u8, max_len: usize) usize {
    if (response == null) return 0;

    const msg = @as(*CtapHidMsg, @ptrCast(@alignCast(response.?)));
    const data = msg.getData();
    const len = @min(data.len, max_len);
    @memcpy(out[0..len], data[0..len]);
    return len;
}

export fn ctaphid_response_set_data(response: ?*anyopaque, data: [*c]const u8, len: usize) c_int {
    if (response == null) return -1;

    const msg = @as(*CtapHidMsg, @ptrCast(@alignCast(response.?)));
    if (len > msg._data.len) return -1;

    @memcpy(msg._data[0..len], data[0..len]);
    msg.len = len;
    return 0;
}

// Client-side APIs

// Transport types and structures
pub const TransportType = enum(c_int) {
    USB = 0,
    NFC = 1,
    BLE = 2,
};

pub const Transport = extern struct {
    handle: ?*anyopaque,
    type: TransportType,
    description: [*c]u8,
};

pub const TransportList = extern struct {
    transports: [*c]?*Transport,
    count: usize,
};

// Import client modules
const client = @import("clientlib");
const ClientTransport = client.Transports.Transport;
const ClientTransports = client.Transports;

// Transport enumeration
export fn transport_enumerate() ?*TransportList {
    var transports = ClientTransports.enumerate(allocator, .{}) catch return null;

    if (transports.devices.len == 0) {
        transports.deinit(); // Deinit if no devices
        return null;
    }

    // Allocate transport list
    const list = allocator.create(TransportList) catch return null;
    errdefer allocator.destroy(list);

    // Allocate array of transport pointers
    const transport_array = allocator.alloc(?*Transport, transports.devices.len) catch {
        allocator.destroy(list);
        return null;
    };
    errdefer allocator.free(transport_array);

    // Convert each client transport to C transport
    for (transports.devices, 0..) |*device, i| {
        const c_transport = allocator.create(Transport) catch {
            // Clean up already allocated transports
            for (0..i) |j| {
                if (transport_array[j]) |t| {
                    allocator.free(std.mem.span(@as([*:0]const u8, @ptrCast(t.description))));
                    allocator.destroy(t);
                }
            }
            allocator.free(transport_array);
            allocator.destroy(list);
            return null;
        };

        // Get device description
        const desc = device.allocPrint(allocator) catch {
            allocator.destroy(c_transport);
            for (0..i) |j| {
                if (transport_array[j]) |t| {
                    allocator.free(std.mem.span(@as([*:0]const u8, @ptrCast(t.description))));
                    allocator.destroy(t);
                }
            }
            allocator.free(transport_array);
            allocator.destroy(list);
            return null;
        };

        // Create null-terminated copy for C string
        const desc_c = allocator.dupeZ(u8, desc) catch {
            allocator.free(desc);
            allocator.destroy(c_transport);
            for (0..i) |j| {
                if (transport_array[j]) |t| {
                    allocator.free(std.mem.span(@as([*:0]const u8, @ptrCast(t.description))));
                    allocator.destroy(t);
                }
            }
            allocator.free(transport_array);
            allocator.destroy(list);
            return null;
        };
        allocator.free(desc); // Free the original slice

        c_transport.* = Transport{
            .handle = @ptrCast(device),
            .type = .USB, // Assume USB for now
            .description = @constCast(desc_c.ptr),
        };

        transport_array[i] = c_transport;
    }

    list.* = TransportList{
        .transports = @ptrCast(transport_array.ptr),
        .count = transports.devices.len,
    };

    allocator.free(transports.devices); // Free slice, devices already moved to C structs
    return list;
}

export fn transport_list_free(list: ?*TransportList) void {
    if (list == null) return;

    const l = list.?;
    for (0..l.count) |i| {
        if (l.transports[i]) |transport| {
            // Deinitialize the duplicated client transport
            const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.handle.?)));
            t.deinit();
            allocator.destroy(t);

            allocator.free(std.mem.span(@as([*:0]const u8, @ptrCast(transport.description))));
            allocator.destroy(transport);
        }
    }
    allocator.free(@as([*]?*Transport, @ptrCast(l.transports))[0..l.count]);
    allocator.destroy(l);
}

// Transport operations
export fn transport_open(transport: ?*Transport) c_int {
    if (transport == null) return -1;
    if (transport.?.handle == null) return -1;

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.?.handle.?)));

    t._open(t.obj) catch return -1;
    return 0;
}

export fn transport_close(transport: ?*Transport) void {
    if (transport == null) return;

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.?.handle.?)));
    t.close();
}

export fn transport_write(transport: ?*Transport, data: [*c]const u8, len: usize) c_int {
    if (transport == null) return -1;

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.?.handle.?)));
    const slice = data[0..len];
    t.write(slice) catch return -1;
    return 0;
}

export fn transport_read(transport: ?*Transport, buffer: [*c]u8, max_len: usize, timeout_ms: c_int) c_int {
    _ = timeout_ms; // Timeout is handled by the Promise, not individual reads
    if (transport == null) return -1;

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.?.handle.?)));
    const result = t.read(allocator) catch return -1;
    if (result) |data| {
        defer allocator.free(data);
        const copy_len = @min(data.len, max_len);
        @memcpy(buffer[0..copy_len], data[0..copy_len]);
        return @intCast(copy_len);
    }
    return 0;
}

export fn transport_get_type(transport: ?*Transport) TransportType {
    if (transport == null) return .USB;
    return transport.?.type;
}

export fn transport_get_description(transport: ?*Transport) [*c]const u8 {
    if (transport == null) return "";
    return transport.?.description;
}

export fn transport_free(transport: ?*Transport) void {
    if (transport == null) return;
    // Note: transport is freed by transport_list_free
}

// CBOR command status enum (matches C enum)
pub const CborCommandStatus = enum(c_int) {
    Pending = 0,
    Fulfilled = 1,
    Rejected = 2,
};

// CBOR command structures
pub const CborCommand = extern struct {
    promise: ?*anyopaque,
    transport: ?*anyopaque,
};

pub const CborCommandResult = extern struct {
    status: c_int,
    data: [*c]u8,
    data_len: usize,
    error_code: c_int,
};

// AuthenticatorGetInfo
export fn cbor_authenticator_get_info(transport: ?*Transport) ?*CborCommand {
    if (transport == null) return null;

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.?.handle.?)));
    const promise = client.cbor_commands.authenticatorGetInfo(t) catch return null;

    const cmd = allocator.create(CborCommand) catch return null;
    cmd.* = CborCommand{
        .promise = @ptrCast(@constCast(&promise)),
        .transport = @ptrCast(t),
    };

    return cmd;
}

export fn cbor_command_get_result(cmd: ?*CborCommand, timeout_ms: c_int) ?*CborCommandResult {
    _ = timeout_ms; // Timeout is handled by the Promise creation
    if (cmd == null) return null;

    const c = cmd.?;
    const promise = @as(*client.cbor_commands.Promise, @ptrCast(@alignCast(c.promise.?)));
    const state = promise.get(allocator);

    const result = allocator.create(CborCommandResult) catch return null;

    switch (state) {
        .pending => {
            result.* = CborCommandResult{
                .status = @intFromEnum(CborCommandStatus.Pending),
                .data = null,
                .data_len = 0,
                .error_code = 0,
            };
        },
        .fulfilled => |data| {
            const data_copy = allocator.dupe(u8, data) catch {
                allocator.destroy(result);
                return null;
            };
            result.* = CborCommandResult{
                .status = @intFromEnum(CborCommandStatus.Fulfilled),
                .data = @ptrCast(data_copy.ptr),
                .data_len = data_copy.len,
                .error_code = 0,
            };
        },
        .rejected => |err| {
            result.* = CborCommandResult{
                .status = @intFromEnum(CborCommandStatus.Rejected),
                .data = null,
                .data_len = 0,
                .error_code = @intFromError(err),
            };
        },
    }

    return result;
}

export fn cbor_command_free(cmd: ?*CborCommand) void {
    if (cmd == null) return;
    allocator.destroy(cmd.?);
}

export fn cbor_command_result_free(result: ?*CborCommandResult) void {
    if (result == null) return;

    const r = result.?;
    if (r.data != null) {
        allocator.free(std.mem.span(r.data));
    }
    allocator.destroy(r);
}
