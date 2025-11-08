const std = @import("std");
const allocator = std.heap.c_allocator;
const keylib = @import("keylib");
const cbor = @import("zbor");
const uhid = @import("uhid");
const Auth = keylib.ctap.authenticator.Auth;
const User = keylib.common.User;
const RelyingParty = keylib.common.RelyingParty;
const PinUvAuth = keylib.ctap.pinuv.PinUvAuth;
const ctaphid = keylib.ctap.transports.ctaphid;
const CtapHid = ctaphid.authenticator.CtapHid;
const CtapHidMsg = ctaphid.authenticator.CtapHidMsg;
const CtapHidMessageIterator = ctaphid.authenticator.CtapHidMessageIterator;

// Import credential management functions to ensure they're compiled
const credential_management = @import("credential_management.zig");
const client_pin = @import("client_pin.zig");

// Force credential management and client_pin functions to be compiled by referencing them
comptime {
    _ = credential_management;
    _ = client_pin;
}

pub const Error = enum(i32) {
    SUCCESS = 0,
    DoesAlreadyExist = -1,
    DoesNotExist = -2,
    KeyStoreFull = -3,
    OutOfMemory = -4,
    Timeout = -5,
    Other = -6,
};

pub const UpResult = enum(c_int) {
    Denied = 0,
    Accepted = 1,
    Timeout = 2,
};

pub const UvResult = enum(c_int) {
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
    write: ?*const fn ([*c]const FfiCredential) callconv(.c) c_int,
    del: ?*const fn ([*c]const u8) callconv(.c) c_int,
    read_first: ?*const fn ([*c]const u8, [*c]const u8, [*c]const u8, [*c]FfiCredential) callconv(.c) c_int,
    read_next: ?*const fn ([*c]FfiCredential) callconv(.c) c_int,
};

pub const AuthSettings = extern struct {
    aaguid: [16]u8 = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
};

pub const FfiCredential = extern struct {
    id: [64]u8,
    id_len: u8,
    rp_id: [128]u8,
    rp_id_len: u8,
    rp_name: [64]u8,
    rp_name_len: u8,
    user_id: [64]u8,
    user_id_len: u8,
    sign_count: u32,
    alg: i32,
    private_key: [32]u8,
    created: i64,
    discoverable: u8,
    cred_protect: u8,
};

var c_callbacks_storage: Callbacks = undefined;
var c_callbacks: *Callbacks = &c_callbacks_storage;

fn ffiCredentialToZig(ffi: FfiCredential) keylib.ctap.authenticator.callbacks.CallbackError!keylib.ctap.authenticator.Credential {
    var cred: keylib.ctap.authenticator.Credential = undefined;

    cred.id = (keylib.common.dt.ABS64B.fromSlice(ffi.id[0..ffi.id_len]) catch return error.Other) orelse return error.Other;

    cred.rp = .{
        .id = (keylib.common.dt.ABS128T.fromSlice(ffi.rp_id[0..ffi.rp_id_len]) catch return error.Other) orelse return error.Other,
        .name = if (ffi.rp_name_len > 0)
            (keylib.common.dt.ABS64T.fromSlice(ffi.rp_name[0..ffi.rp_name_len]) catch return error.Other)
        else
            null,
    };

    cred.user = .{
        .id = (keylib.common.dt.ABS64B.fromSlice(ffi.user_id[0..ffi.user_id_len]) catch return error.Other) orelse return error.Other,
        .name = null,
        .displayName = null,
    };

    cred.sign_count = ffi.sign_count;

    cred.key = .{
        .P256 = .{
            .alg = @enumFromInt(ffi.alg),
            .x = undefined,
            .y = undefined,
            .d = ffi.private_key,
        },
    };

    cred.created = ffi.created;
    cred.discoverable = ffi.discoverable != 0;
    cred.policy = @enumFromInt(ffi.cred_protect);

    return cred;
}

fn zigCredentialToFfi(cred: keylib.ctap.authenticator.Credential) FfiCredential {
    var ffi: FfiCredential = undefined;

    const id_slice = cred.id.get();
    @memcpy(ffi.id[0..id_slice.len], id_slice);
    ffi.id_len = @intCast(id_slice.len);

    const rp_id_slice = cred.rp.id.get();
    @memcpy(ffi.rp_id[0..rp_id_slice.len], rp_id_slice);
    ffi.rp_id_len = @intCast(rp_id_slice.len);

    if (cred.rp.name) |name| {
        const rp_name_slice = name.get();
        @memcpy(ffi.rp_name[0..rp_name_slice.len], rp_name_slice);
        ffi.rp_name_len = @intCast(rp_name_slice.len);
    } else {
        ffi.rp_name_len = 0;
    }

    const user_id_slice = cred.user.id.get();
    @memcpy(ffi.user_id[0..user_id_slice.len], user_id_slice);
    ffi.user_id_len = @intCast(user_id_slice.len);

    ffi.sign_count = @intCast(cred.sign_count);
    ffi.alg = @intFromEnum(cred.key.P256.alg);
    ffi.private_key = cred.key.P256.d orelse [_]u8{0} ** 32;
    ffi.created = cred.created;
    ffi.discoverable = if (cred.discoverable) 1 else 0;
    ffi.cred_protect = @intFromEnum(cred.policy);

    return ffi;
}

fn wrapper_up(info: []const u8, user: ?User, rp: ?RelyingParty) keylib.ctap.authenticator.callbacks.UpResult {
    if (c_callbacks.up == null) return .Denied;
    var info_buf: [256]u8 = undefined;
    @memcpy(info_buf[0..info.len], info);
    info_buf[info.len] = 0;
    const c_info: [*c]const u8 = @ptrCast(&info_buf);

    var user_buf: [256]u8 = undefined;
    const c_user: ?[*c]const u8 = if (user) |u| blk: {
        const name = u.getName();
        @memcpy(user_buf[0..name.len], name);
        user_buf[name.len] = 0;
        break :blk @ptrCast(&user_buf);
    } else null;

    var rp_buf: [256]u8 = undefined;
    const c_rp: ?[*c]const u8 = if (rp) |r| blk: {
        const id = r.id.get();
        @memcpy(rp_buf[0..id.len], id);
        rp_buf[id.len] = 0;
        break :blk @ptrCast(&rp_buf);
    } else null;

    const result = c_callbacks.up.?(c_info, c_user orelse null, c_rp orelse null);
    return switch (result) {
        .Denied => .Denied,
        .Accepted => .Accepted,
        .Timeout => .Timeout,
    };
}

fn wrapper_uv(info: []const u8, user: ?User, rp: ?RelyingParty) keylib.ctap.authenticator.callbacks.UvResult {
    if (c_callbacks.uv == null) return .Denied;
    var info_buf: [256]u8 = undefined;
    @memcpy(info_buf[0..info.len], info);
    info_buf[info.len] = 0;
    const c_info: [*c]const u8 = @ptrCast(&info_buf);

    var user_buf: [256]u8 = undefined;
    const c_user: ?[*c]const u8 = if (user) |u| blk: {
        const name = u.getName();
        @memcpy(user_buf[0..name.len], name);
        user_buf[name.len] = 0;
        break :blk @ptrCast(&user_buf);
    } else null;

    var rp_buf: [256]u8 = undefined;
    const c_rp: ?[*c]const u8 = if (rp) |r| blk: {
        const id = r.id.get();
        @memcpy(rp_buf[0..id.len], id);
        rp_buf[id.len] = 0;
        break :blk @ptrCast(&rp_buf);
    } else null;

    const result = c_callbacks.uv.?(c_info, c_user orelse null, c_rp orelse null);
    return switch (result) {
        .Denied => .Denied,
        .Accepted => .Accepted,
        .AcceptedWithUp => .AcceptedWithUp,
        .Timeout => .Timeout,
    };
}

fn wrapper_read_first(id: ?keylib.common.dt.ABS64B, rp: ?keylib.common.dt.ABS128T, hash: ?[32]u8) keylib.ctap.authenticator.callbacks.CallbackError!keylib.ctap.authenticator.Credential {
    if (c_callbacks.read_first == null) return error.DoesNotExist;

    var id_buf: [64]u8 = undefined;
    const c_id: ?[*c]const u8 = if (id) |i| blk: {
        @memcpy(id_buf[0..i.get().len], i.get());
        id_buf[i.get().len] = 0;
        break :blk @ptrCast(&id_buf);
    } else null;

    var rp_buf: [128]u8 = undefined;
    const c_rp: ?[*c]const u8 = if (rp) |r| blk: {
        @memcpy(rp_buf[0..r.get().len], r.get());
        rp_buf[r.get().len] = 0;
        break :blk @ptrCast(&rp_buf);
    } else null;

    const c_hash: ?[*c]const u8 = if (hash) |*h| @ptrCast(h) else null;

    var ffi_cred: FfiCredential = undefined;
    const result = c_callbacks.read_first.?(c_id orelse null, c_rp orelse null, c_hash orelse null, @ptrCast(&ffi_cred));

    if (result != 0) {
        return switch (result) {
            -1 => error.DoesAlreadyExist,
            -2 => error.DoesNotExist,
            -3 => error.KeyStoreFull,
            -4 => error.OutOfMemory,
            -5 => error.Timeout,
            else => error.Other,
        };
    }

    return ffiCredentialToZig(ffi_cred);
}

fn wrapper_read_next() keylib.ctap.authenticator.callbacks.CallbackError!keylib.ctap.authenticator.Credential {
    if (c_callbacks.read_next == null) return error.DoesNotExist;

    var ffi_cred: FfiCredential = undefined;
    const result = c_callbacks.read_next.?(@ptrCast(&ffi_cred));

    if (result != 0) {
        return switch (result) {
            -1 => error.DoesAlreadyExist,
            -2 => error.DoesNotExist,
            -3 => error.KeyStoreFull,
            -4 => error.OutOfMemory,
            -5 => error.Timeout,
            else => error.Other,
        };
    }

    return ffiCredentialToZig(ffi_cred);
}

fn wrapper_write(data: keylib.ctap.authenticator.Credential) keylib.ctap.authenticator.callbacks.CallbackError!void {
    if (c_callbacks.write == null) return error.KeyStoreFull;

    const ffi_cred = zigCredentialToFfi(data);
    const result = c_callbacks.write.?(@ptrCast(&ffi_cred));

    if (result != 0) {
        return switch (result) {
            -1 => error.DoesAlreadyExist,
            -2 => error.DoesNotExist,
            -3 => error.KeyStoreFull,
            -4 => error.OutOfMemory,
            -5 => error.Timeout,
            else => error.Other,
        };
    }
}

fn wrapper_delete(id: [*c]const u8) callconv(.c) keylib.ctap.authenticator.callbacks.Error {
    if (c_callbacks.del == null) return .DoesNotExist;

    const result = c_callbacks.del.?(id);
    return switch (result) {
        0 => .SUCCESS,
        -1 => .DoesAlreadyExist,
        -2 => .DoesNotExist,
        -3 => .KeyStoreFull,
        -4 => .OutOfMemory,
        -5 => .Timeout,
        else => .Other,
    };
}

// Settings callbacks - now supports PIN configuration
var pin_hash_storage: ?[63]u8 = null;

fn stub_read_settings() keylib.ctap.authenticator.Meta {
    return .{
        .pin = pin_hash_storage,
    };
}

fn stub_write_settings(data: keylib.ctap.authenticator.Meta) void {
    pin_hash_storage = data.pin;
}

export fn auth_set_pin_hash(pin_hash: [*]const u8, len: usize) void {
    if (len > 63) return;

    var new_pin: [63]u8 = undefined;
    @memset(&new_pin, 0);
    @memcpy(new_pin[0..len], pin_hash[0..len]);
    pin_hash_storage = new_pin;
}

var ctaphid_instance: ?CtapHid = null;
var current_iterator: ?CtapHidMessageIterator = null;
var uhid_instance: ?uhid.Uhid = null;

export fn auth_init(callbacks: Callbacks, settings: AuthSettings) ?*anyopaque {
    c_callbacks_storage = callbacks;
    c_callbacks = &c_callbacks_storage;

    const a = allocator.create(Auth) catch return null;

    a.* = Auth{
        .callbacks = .{
            .up = wrapper_up,
            .uv = wrapper_uv,
            .read_first = wrapper_read_first,
            .read_next = wrapper_read_next,
            .write = wrapper_write,
            .delete = wrapper_delete,
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
            .remainingDiscoverableCredentials = 9999,
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

    a.init() catch {
        allocator.destroy(a);
        return null;
    };

    return @as(*anyopaque, @ptrCast(a));
}

export fn auth_deinit(a: *anyopaque) void {
    const auth = @as(*Auth, @ptrCast(@alignCast(a)));
    allocator.destroy(auth);
}

export fn auth_handle(
    a: *anyopaque,
    request_data: [*c]const u8,
    request_len: usize,
    response_buffer: [*c]u8,
    response_buffer_size: usize,
) usize {
    if (request_data == null or response_buffer == null) return 0;
    if (request_len == 0 or request_len > 7609) return 0;
    if (response_buffer_size < 7609) return 0;

    const auth = @as(*Auth, @ptrCast(@alignCast(a)));
    const request = request_data[0..request_len];
    const response_buf_ptr = @as(*[7609]u8, @ptrCast(@alignCast(response_buffer)));
    const response = auth.handle(response_buf_ptr, request);

    return response.len;
}

export fn ctaphid_init() ?*anyopaque {
    ctaphid_instance = CtapHid.init(allocator, std.crypto.random);
    return @as(*anyopaque, @ptrCast(&ctaphid_instance.?));
}

export fn ctaphid_deinit(a: *anyopaque) void {
    _ = a;
    if (ctaphid_instance) |*instance| {
        instance.deinit();
        ctaphid_instance = null;
    }
}

export fn ctaphid_handle(a: *anyopaque, data: [*c]const u8, len: usize) ?*anyopaque {
    _ = a;
    if (ctaphid_instance == null) return null;

    const packet = data[0..len];
    const response = ctaphid_instance.?.handle(packet) orelse return null;

    const response_copy = allocator.create(CtapHidMsg) catch return null;
    response_copy.* = response;
    return @as(*anyopaque, @ptrCast(response_copy));
}

export fn ctaphid_iterator(a: ?*anyopaque) ?*anyopaque {
    if (a == null) return null;

    const msg = @as(*CtapHidMsg, @ptrCast(@alignCast(a.?)));
    current_iterator = msg.iterator();

    return @as(*anyopaque, @ptrCast(&current_iterator.?));
}

export fn ctaphid_iterator_next(a: ?*anyopaque, out: [*c]u8) c_int {
    _ = a;
    if (current_iterator == null) return 0;

    const packet = current_iterator.?.next() orelse {
        current_iterator = null;
        return 0;
    };

    @memcpy(out[0..packet.len], packet);
    return @intCast(packet.len);
}

export fn ctaphid_iterator_deinit(a: ?*anyopaque) void {
    _ = a;
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
    _internal: ?*anyopaque = null,
};

const client = @import("clientlib");
const ClientTransport = client.Transports.Transport;
const ClientTransports = client.Transports;

export fn transport_enumerate() ?*TransportList {
    const transports_ptr = allocator.create(ClientTransports) catch return null;
    errdefer allocator.destroy(transports_ptr);

    transports_ptr.* = ClientTransports.enumerate(allocator, .{}) catch {
        allocator.destroy(transports_ptr);
        return null;
    };

    if (transports_ptr.devices.len == 0) {
        transports_ptr.deinit();
        allocator.destroy(transports_ptr);
        return null;
    }

    const list = allocator.create(TransportList) catch {
        transports_ptr.deinit();
        allocator.destroy(transports_ptr);
        return null;
    };
    errdefer allocator.destroy(list);

    const transport_array = allocator.alloc(?*Transport, transports_ptr.devices.len) catch {
        transports_ptr.deinit();
        allocator.destroy(transports_ptr);
        allocator.destroy(list);
        return null;
    };
    errdefer allocator.free(transport_array);

    for (transports_ptr.devices, 0..) |*device, i| {
        const c_transport = allocator.create(Transport) catch {
            for (0..i) |j| {
                if (transport_array[j]) |t| {
                    allocator.free(std.mem.span(@as([*:0]const u8, @ptrCast(t.description))));
                    allocator.destroy(t);
                }
            }
            allocator.free(transport_array);
            transports_ptr.deinit();
            allocator.destroy(transports_ptr);
            allocator.destroy(list);
            return null;
        };

        const desc = device.allocPrint(allocator) catch {
            allocator.destroy(c_transport);
            for (0..i) |j| {
                if (transport_array[j]) |t| {
                    allocator.free(std.mem.span(@as([*:0]const u8, @ptrCast(t.description))));
                    allocator.destroy(t);
                }
            }
            allocator.free(transport_array);
            transports_ptr.deinit();
            allocator.destroy(transports_ptr);
            allocator.destroy(list);
            return null;
        };

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
            transports_ptr.deinit();
            allocator.destroy(transports_ptr);
            allocator.destroy(list);
            return null;
        };
        allocator.free(desc);

        c_transport.* = Transport{
            .handle = @ptrCast(device),
            .type = .USB,
            .description = @constCast(desc_c.ptr),
        };

        transport_array[i] = c_transport;
    }

    list.* = TransportList{
        .transports = @ptrCast(transport_array.ptr),
        .count = transports_ptr.devices.len,
        ._internal = @ptrCast(transports_ptr),
    };

    return list;
}

export fn transport_list_free(list: ?*TransportList) void {
    if (list == null) return;

    const l = list.?;
    for (0..l.count) |i| {
        if (l.transports[i]) |transport| {
            allocator.free(std.mem.span(@as([*:0]const u8, @ptrCast(transport.description))));
            allocator.destroy(transport);
        }
    }
    allocator.free(@as([*]?*Transport, @ptrCast(l.transports))[0..l.count]);

    if (l._internal) |internal| {
        const transports_ptr = @as(*ClientTransports, @ptrCast(@alignCast(internal)));
        transports_ptr.deinit();
        allocator.destroy(transports_ptr);
    }

    allocator.destroy(l);
}

export fn transport_open(transport: ?*Transport) c_int {
    if (transport == null or transport.?.handle == null) return -1;

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.?.handle.?)));
    t.open() catch return -1;
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
    _ = timeout_ms;
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
    _ = transport;
}

pub const CborCommandStatus = enum(c_int) {
    Pending = 0,
    Fulfilled = 1,
    Rejected = 2,
};

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

const CredentialCreationOptions = extern struct {
    challenge: [*c]const u8,
    challenge_len: usize,
    rp_id: [*c]const u8,
    rp_name: [*c]const u8,
    user_id: [*c]const u8,
    user_id_len: usize,
    user_name: [*c]const u8,
    user_display_name: [*c]const u8,
    timeout_ms: u32,
    require_resident_key: c_int,
    require_user_verification: c_int,
    attestation_preference: [*c]const u8,
    exclude_credentials_json: [*c]const u8,
    extensions_json: [*c]const u8,
};

const CredentialAssertionOptions = extern struct {
    rp_id: [*c]const u8,
    challenge: [*c]const u8,
    challenge_len: usize,
    timeout_ms: u32,
    user_verification: [*c]const u8,
    allow_credentials_json: [*c]const u8,
};

export fn cbor_credentials_create(transport: ?*Transport, options: ?*CredentialCreationOptions) ?*CborCommand {
    _ = transport;
    _ = options;

    const cmd = allocator.create(CborCommand) catch return null;
    cmd.* = CborCommand{
        .promise = null,
        .transport = null,
    };
    return cmd;
}

export fn cbor_credentials_get(transport: ?*Transport, options: ?*CredentialAssertionOptions) ?*CborCommand {
    _ = transport;
    _ = options;

    const cmd = allocator.create(CborCommand) catch return null;
    cmd.* = CborCommand{
        .promise = null,
        .transport = null,
    };
    return cmd;
}

export fn cbor_command_get_result(cmd: ?*CborCommand, timeout_ms: c_int) ?*CborCommandResult {
    _ = timeout_ms;
    if (cmd == null) return null;

    const c = cmd.?;
    const promise = @as(*client.cbor_commands.Promise, @ptrCast(@alignCast(c.promise.?)));
    const state = promise.get(allocator);

    const result: *CborCommandResult = allocator.create(CborCommandResult) catch return null;

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
