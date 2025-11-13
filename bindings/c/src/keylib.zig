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

// Configure logging for C bindings - completely disabled
// This keeps the FFI layer quiet while allowing the main library to be configured
pub const std_options: std.Options = .{
    .log_level = .err,
    .logFn = struct {
        fn log(
            comptime _: std.log.Level,
            comptime _: @TypeOf(.enum_literal),
            comptime _: []const u8,
            _: anytype,
        ) void {
            // Do nothing - logging disabled
        }
    }.log,
};

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

pub const AuthOptions = extern struct {
    rk: c_int = 1,
    up: c_int = 1,
    uv: c_int = -1,
    plat: c_int = 0,
    client_pin: c_int = 1,
    pin_uv_auth_token: c_int = 1,
    cred_mgmt: c_int = 0,
    bio_enroll: c_int = 0,
    large_blobs: c_int = 0,
    ep: c_int = -1,
    always_uv: c_int = -1,
};

pub const CustomCommandHandler = ?*const fn (
    auth: ?*anyopaque,
    request: [*c]const u8,
    request_len: usize,
    response: [*c]u8,
    response_size: usize,
) callconv(.c) usize;

pub const CustomCommand = extern struct {
    cmd: u8,
    handler: CustomCommandHandler,
};

pub const AuthSettings = extern struct {
    aaguid: [16]u8 = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,

    // Command configuration
    /// Pointer to array of command bytes to enable. NULL = use defaults
    enabled_commands: ?[*]const u8 = null,
    /// Length of enabled_commands array. 0 = use defaults
    enabled_commands_len: usize = 0,
    /// Pointer to array of custom vendor commands. NULL = no custom commands
    custom_commands: ?[*]const CustomCommand = null,
    /// Length of custom_commands array
    custom_commands_len: usize = 0,

    // Authenticator options
    /// Options flags. If NULL, uses defaults
    options: ?*const AuthOptions = null,

    // Credential management
    /// Maximum number of discoverable credentials. 0 = use default (9999)
    max_credentials: u32 = 0,

    // Extensions
    /// Pointer to array of extension name strings. NULL = use defaults
    extensions: ?[*]const [*c]const u8 = null,
    /// Length of extensions array
    extensions_len: usize = 0,

    // Firmware version
    /// Firmware version (0 = not set, will use null)
    firmware_version: u32 = 0,

    // Transports
    /// Transport flags: 1=USB, 2=NFC, 4=BLE
    transports: u8 = 0,
};

/// Wrapper to track authenticator and any allocated resources
const AuthWrapper = struct {
    auth: *Auth,
    allocated_commands: ?[]Ctap2CommandMapping = null,
    stored_settings: ?*AuthSettings = null, // Store settings to keep custom command handlers accessible
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

// Settings callbacks - now supports PIN configuration and always_uv
var pin_hash_storage: ?[63]u8 = null;
var always_uv_storage: bool = false;

fn stub_read_settings() keylib.ctap.authenticator.Meta {
    return .{
        .pin = pin_hash_storage,
        .always_uv = always_uv_storage,
    };
}

fn stub_write_settings(data: keylib.ctap.authenticator.Meta) void {
    pin_hash_storage = data.pin;
    always_uv_storage = data.always_uv;
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

const Ctap2CommandMapping = keylib.ctap.authenticator.callbacks.Ctap2CommandMapping;

/// Map a command byte to its implementation
fn getCommandMapping(cmd: u8) ?Ctap2CommandMapping {
    return switch (cmd) {
        0x01 => .{ .cmd = 0x01, .cb = keylib.ctap.commands.authenticator.authenticatorMakeCredential },
        0x02 => .{ .cmd = 0x02, .cb = keylib.ctap.commands.authenticator.authenticatorGetAssertion },
        0x04 => .{ .cmd = 0x04, .cb = keylib.ctap.commands.authenticator.authenticatorGetInfo },
        0x06 => .{ .cmd = 0x06, .cb = keylib.ctap.commands.authenticator.authenticatorClientPin },
        0x08 => .{ .cmd = 0x08, .cb = keylib.ctap.commands.authenticator.authenticatorGetNextAssertion },
        // Note: CredentialManagement (0x0a) has compilation issues in upstream Zig library
        0x0b => .{ .cmd = 0x0b, .cb = keylib.ctap.commands.authenticator.authenticatorSelection },
        // Note: Reset, BioEnrollment, LargeBlobs, Config not exposed yet
        else => null,
    };
}

/// Storage for custom command handlers (persistent for auth lifetime)
var custom_handler_storage: ?*AuthWrapper = null;

// Constants
const DEFAULT_MAX_CREDENTIALS: u32 = 9999;

/// Result of building commands array
const CommandBuildResult = struct {
    commands: []const Ctap2CommandMapping,
    allocated: ?[]Ctap2CommandMapping,
};

/// Result of building extensions array
const ExtensionBuildResult = struct {
    extensions: []const []const u8,
    allocated: ?[][]const u8,
};

/// External C function that dispatches to custom command handlers
/// This is called from Zig trampolines when custom commands are invoked
/// The implementation can be provided by any language that can export C functions
extern fn dispatch_custom_command(
    cmd_byte: u8,
    auth: ?*anyopaque,
    request: [*c]const u8,
    request_len: usize,
    response: [*c]u8,
    response_size: usize,
) callconv(.c) usize;

/// Generic trampoline for custom vendor commands
///
/// This bridges custom command handlers to Zig's I/O writer interface.
/// The handler is dispatched through dispatch_custom_command.
fn makeCustomCommandTrampoline(comptime cmd_byte: u8) keylib.ctap.authenticator.callbacks.Ctap2CommandCallback {
    const Trampoline = struct {
        fn call(
            auth_opaque: *keylib.ctap.authenticator.Auth,
            req: []const u8,
            writer: *std.Io.Writer,
        ) keylib.ctap.StatusCodes {
            // The command byte has been consumed by the outer dispatcher.
            // This trampoline knows it's handling cmd_byte due to comptime generation.

            // Allocate response buffer (max CTAP message size)
            var response_buf: [7609]u8 = undefined;

            // Call the external dispatcher which looks up the handler
            const response_len = dispatch_custom_command(
                cmd_byte,
                @ptrCast(auth_opaque),
                req.ptr,
                req.len,
                &response_buf,
                response_buf.len,
            );

            if (response_len == 0) return .ctap2_err_vendor_first;

            // Write response to the writer
            writer.writeAll(response_buf[0..response_len]) catch return .ctap2_err_vendor_first;

            return .ctap1_err_success;
        }
    };

    return Trampoline.call;
} // Static array of trampoline functions for custom commands (0x40-0xBF)
const custom_command_trampolines = blk: {
    var trampolines: [0xBF - 0x40 + 1]keylib.ctap.authenticator.callbacks.Ctap2CommandCallback = undefined;
    var i: u8 = 0x40;
    while (i <= 0xBF) : (i += 1) {
        trampolines[i - 0x40] = makeCustomCommandTrampoline(i);
    }
    break :blk trampolines;
};

// Special trampoline for 0x0a (CredentialManagement) to allow custom override
const credential_mgmt_trampoline = makeCustomCommandTrampoline(0x0a);

fn getCustomCommandTrampoline(cmd: u8) ?keylib.ctap.authenticator.callbacks.Ctap2CommandCallback {
    // Special case: allow 0x0a (CredentialManagement) as custom command
    if (cmd == 0x0a) return credential_mgmt_trampoline;

    // Standard vendor command range (0x40-0xBF)
    if (cmd < 0x40 or cmd > 0xBF) return null;
    return custom_command_trampolines[cmd - 0x40];
}

/// Get default command mappings
fn getDefaultCommands() []const Ctap2CommandMapping {
    return &.{
        .{ .cmd = 0x01, .cb = keylib.ctap.commands.authenticator.authenticatorMakeCredential },
        .{ .cmd = 0x02, .cb = keylib.ctap.commands.authenticator.authenticatorGetAssertion },
        .{ .cmd = 0x04, .cb = keylib.ctap.commands.authenticator.authenticatorGetInfo },
        .{ .cmd = 0x06, .cb = keylib.ctap.commands.authenticator.authenticatorClientPin },
        .{ .cmd = 0x0b, .cb = keylib.ctap.commands.authenticator.authenticatorSelection },
    };
}

/// Build commands array from settings
/// Returns error if no valid commands are configured
fn buildCommandsArray(settings: AuthSettings) !CommandBuildResult {
    // Require explicit command configuration
    if (settings.enabled_commands == null or settings.enabled_commands_len == 0) {
        return error.NoCommandsSpecified;
    }

    const cmd_bytes = settings.enabled_commands.?;
    const total_cmd_count = settings.enabled_commands_len + settings.custom_commands_len;

    var cmd_list = try allocator.alloc(Ctap2CommandMapping, total_cmd_count);
    errdefer allocator.free(cmd_list);

    var valid_count: usize = 0;

    // Add standard commands
    for (cmd_bytes[0..settings.enabled_commands_len]) |cmd_byte| {
        if (getCommandMapping(cmd_byte)) |mapping| {
            cmd_list[valid_count] = mapping;
            valid_count += 1;
        }
    }

    // Add custom vendor commands (0x40-0xbf range) and special case 0x0a
    if (settings.custom_commands) |custom_cmds| {
        for (custom_cmds[0..settings.custom_commands_len]) |custom_cmd| {
            // Accept standard vendor range (0x40-0xBF) or special case 0x0a (CredentialManagement)
            const is_vendor_range = custom_cmd.cmd >= 0x40 and custom_cmd.cmd <= 0xbf;
            const is_cred_mgmt = custom_cmd.cmd == 0x0a;

            if (is_vendor_range or is_cred_mgmt) {
                // NOTE: handler can be null here - Zig creates trampolines
                // that dispatch through dispatch_custom_command
                // Use the appropriate trampoline for this command byte
                if (getCustomCommandTrampoline(custom_cmd.cmd)) |trampoline| {
                    cmd_list[valid_count] = .{
                        .cmd = custom_cmd.cmd,
                        .cb = trampoline,
                    };
                    valid_count += 1;
                }
            }
        }
    }

    // Fail if no valid commands were configured
    if (valid_count == 0) {
        allocator.free(cmd_list);
        return error.NoValidCommands;
    }

    return CommandBuildResult{
        .commands = cmd_list[0..valid_count],
        .allocated = cmd_list,
    };
}

/// Build extensions array from settings
/// Returns error if no extensions are configured
fn buildExtensionsArray(settings: AuthSettings) !ExtensionBuildResult {
    // Require explicit extension configuration
    if (settings.extensions == null or settings.extensions_len == 0) {
        return error.NoExtensionsSpecified;
    }

    const ext_ptrs = settings.extensions.?;
    var ext_list = try allocator.alloc([]const u8, settings.extensions_len);
    errdefer allocator.free(ext_list);

    for (ext_ptrs[0..settings.extensions_len], 0..) |ext_ptr, i| {
        ext_list[i] = std.mem.span(ext_ptr);
    }

    return ExtensionBuildResult{
        .extensions = ext_list,
        .allocated = ext_list,
    };
}

/// Configure authenticator options from settings
fn configureOptions(settings: AuthSettings, has_uv_callback: bool) keylib.ctap.authenticator.Options {
    var opts = keylib.ctap.authenticator.Options{
        .rk = if (settings.options) |o| (o.rk != 0) else true,
        .up = if (settings.options) |o| (o.up != 0) else true,
        .plat = if (settings.options) |o| (o.plat != 0) else false,
    };

    if (settings.options) |o| {
        // Handle tri-state options (-1 = not set, 0 = false, 1 = true)
        if (o.uv >= 0) opts.uv = (o.uv != 0);
        if (o.client_pin >= 0) opts.clientPin = (o.client_pin != 0);
        if (o.pin_uv_auth_token >= 0) opts.pinUvAuthToken = (o.pin_uv_auth_token != 0);
        if (o.cred_mgmt >= 0) opts.credMgmt = (o.cred_mgmt != 0);
        if (o.bio_enroll >= 0) opts.bioEnroll = (o.bio_enroll != 0);
        if (o.large_blobs >= 0) opts.largeBlobs = (o.large_blobs != 0);
        if (o.ep >= 0) opts.ep = (o.ep != 0);
        if (o.always_uv >= 0) opts.alwaysUv = (o.always_uv != 0);
    } else {
        // Apply callback-based defaults when no explicit options provided
        opts.uv = has_uv_callback;
        opts.clientPin = true;
        opts.pinUvAuthToken = true;
    }

    return opts;
}

/// Resource manager for auth initialization cleanup
const AuthInitResources = struct {
    auth: ?*Auth = null,
    allocated_commands: ?[]Ctap2CommandMapping = null,
    allocated_extensions: ?[][]const u8 = null,
    settings_copy: ?*AuthSettings = null,
    wrapper: ?*AuthWrapper = null,

    fn cleanup(self: *AuthInitResources) void {
        if (self.wrapper) |w| allocator.destroy(w);
        if (self.settings_copy) |s| allocator.destroy(s);
        if (self.allocated_extensions) |e| allocator.free(e);
        if (self.allocated_commands) |c| allocator.free(c);
        if (self.auth) |a| allocator.destroy(a);
    }
};

export fn auth_init(callbacks: Callbacks, settings: AuthSettings) ?*anyopaque {
    c_callbacks_storage = callbacks;
    c_callbacks = &c_callbacks_storage;

    var resources = AuthInitResources{};
    errdefer resources.cleanup();

    // Allocate Auth struct
    const auth = allocator.create(Auth) catch return null;
    resources.auth = auth;

    // Build commands array
    const cmd_result = buildCommandsArray(settings) catch {
        resources.cleanup();
        return null;
    };
    resources.allocated_commands = cmd_result.allocated;

    // Build extensions array
    const ext_result = buildExtensionsArray(settings) catch {
        resources.cleanup();
        return null;
    };
    resources.allocated_extensions = ext_result.allocated;

    // Configure options
    const opts = configureOptions(settings, c_callbacks.uv != null);

    // Store always_uv in global storage so it can be returned by stub_read_settings
    always_uv_storage = opts.alwaysUv orelse false;

    // Configure transports (currently hardcoded to USB)
    const transports_list: ?[]const keylib.common.AuthenticatorTransports = &.{.usb};

    // Determine max credentials
    const max_creds = if (settings.max_credentials > 0)
        settings.max_credentials
    else
        DEFAULT_MAX_CREDENTIALS;

    // Initialize Auth struct
    auth.* = Auth{
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
        .commands = cmd_result.commands,
        .settings = .{
            .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
            .extensions = ext_result.extensions,
            .aaguid = settings.aaguid,
            .remainingDiscoverableCredentials = max_creds,
            .pinUvAuthProtocols = &.{.V2},
            .options = opts,
            .transports = transports_list,
            .firmwareVersion = if (settings.firmware_version > 0) settings.firmware_version else null,
        },
        .token = PinUvAuth.v2(std.crypto.random),
        .algorithms = &.{keylib.ctap.crypto.algorithms.Es256},
        .random = std.crypto.random,
        .milliTimestamp = std.time.milliTimestamp,
        .constSignCount = true,
    };

    auth.init() catch {
        resources.cleanup();
        return null;
    };

    // Store settings copy for custom command access
    const settings_copy = allocator.create(AuthSettings) catch {
        resources.cleanup();
        return null;
    };
    settings_copy.* = settings;
    resources.settings_copy = settings_copy;

    // Create wrapper
    const wrapper = allocator.create(AuthWrapper) catch {
        resources.cleanup();
        return null;
    };
    resources.wrapper = wrapper;

    wrapper.* = .{
        .auth = auth,
        .allocated_commands = resources.allocated_commands,
        .stored_settings = settings_copy,
    };

    // Make wrapper available to custom command trampoline
    custom_handler_storage = wrapper;

    // Clear resources struct so cleanup doesn't free everything
    resources = AuthInitResources{};

    return @as(*anyopaque, @ptrCast(wrapper));
}

export fn auth_deinit(a: *anyopaque) void {
    const wrapper = @as(*AuthWrapper, @ptrCast(@alignCast(a)));

    // Clear global custom handler storage
    if (custom_handler_storage == wrapper) {
        custom_handler_storage = null;
    }

    // Free allocated commands
    if (wrapper.allocated_commands) |cmd_list| {
        allocator.free(cmd_list);
    }

    // Free stored settings copy
    if (wrapper.stored_settings) |settings| {
        allocator.destroy(settings);
    }

    allocator.destroy(wrapper.auth);
    allocator.destroy(wrapper);
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

    const wrapper = @as(*AuthWrapper, @ptrCast(@alignCast(a)));
    const auth = wrapper.auth;
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

        const device_ptr: *ClientTransport = &transports_ptr.devices[i];

        c_transport.* = Transport{
            .handle = @as(?*anyopaque, @ptrCast(device_ptr)),
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
    if (transport == null) return -1;

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.?.handle.?)));
    const result = t.readWithTimeout(allocator, timeout_ms) catch return -1;
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
