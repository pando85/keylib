const std = @import("std");
const allocator = std.heap.c_allocator;
const keylib = @import("keylib");
const client = @import("clientlib");
const cbor = @import("zbor");

// Types from the library
const Encapsulation = client.cbor_commands.client_pin.Encapsulation;
const ClientTransport = client.Transports.Transport;
const PinProtocol = keylib.ctap.pinuv.common.PinProtocol;
const Permissions = client.cbor_commands.client_pin.Permissions;

// C wrapper types from keylib.zig
const CTransport = extern struct {
    handle: ?*anyopaque,
    type: u32, // TransportType
    description: [*c]u8,
};

/// Create a new PIN encapsulation for key agreement with the authenticator
/// Returns opaque pointer to Encapsulation on success, null on error
export fn client_pin_encapsulation_new(
    transport: *CTransport,
    protocol: u8,
) callconv(.c) ?*Encapsulation {
    if (transport.handle == null) return null;

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.handle.?)));
    const proto: PinProtocol = if (protocol == 1) .V1 else .V2;

    const enc = client.cbor_commands.client_pin.getKeyAgreement(
        t,
        proto,
        allocator,
    ) catch |e| {
        std.log.err("getKeyAgreement failed: {}", .{e});
        return null;
    };

    const enc_ptr = allocator.create(Encapsulation) catch return null;
    enc_ptr.* = enc;
    return enc_ptr;
}

/// Get the platform public key from an encapsulation (65 bytes: 0x04 || x || y)
/// public_key_out must point to a buffer of at least 65 bytes
/// Returns 0 on success, -1 on error
export fn client_pin_encapsulation_get_platform_key(
    encapsulation: *const Encapsulation,
    public_key_out: [*]u8,
) callconv(.c) i32 {
    const pub_key = encapsulation.platform_key_agreement_key.public_key.toUncompressedSec1();
    @memcpy(public_key_out[0..65], &pub_key);
    return 0;
}

/// Free a PIN encapsulation
export fn client_pin_encapsulation_free(
    encapsulation: *Encapsulation,
) callconv(.c) void {
    allocator.destroy(encapsulation);
}

/// Get PIN token from authenticator (CTAP 2.0)
/// Returns 0 on success with allocated token, -1 on failure
/// Caller must free the returned buffer with client_pin_free_token
export fn client_pin_get_pin_token(
    transport: *CTransport,
    enc: *Encapsulation,
    pin: [*]const u8,
    pin_len: usize,
    token_out: *[*]u8,
    token_len_out: *usize,
) callconv(.c) i32 {
    if (transport.handle == null) return -1;

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.handle.?)));
    const pin_slice = pin[0..pin_len];

    const token = client.cbor_commands.client_pin.getPinToken(
        t,
        enc,
        pin_slice,
        allocator,
    ) catch |e| {
        std.log.err("getPinToken failed: {}", .{e});
        return -1;
    };

    // Return the token directly - caller takes ownership
    token_out.* = @constCast(token.ptr);
    token_len_out.* = token.len;

    return 0;
}

/// Convert permissions byte to Permissions struct
fn permissionsFromByte(byte: u8) Permissions {
    return .{
        .mc = @truncate(byte & 0x01),
        .ga = @truncate((byte >> 1) & 0x01),
        .cm = @truncate((byte >> 2) & 0x01),
        .be = @truncate((byte >> 3) & 0x01),
        .lbw = @truncate((byte >> 4) & 0x01),
        .acfg = @truncate((byte >> 5) & 0x01),
    };
}

/// Get PIN/UV auth token with permissions (CTAP 2.1+)
/// Returns 0 on success with allocated token, -1 on failure
/// rp_id can be null if not needed for the requested permissions
export fn client_pin_get_pin_uv_auth_token_using_pin_with_permissions(
    transport: *CTransport,
    enc: *Encapsulation,
    pin: [*]const u8,
    pin_len: usize,
    permissions: u8,
    rp_id: ?[*]const u8,
    rp_id_len: usize,
    token_out: *[*]u8,
    token_len_out: *usize,
) callconv(.c) i32 {
    if (transport.handle == null) return -1;

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.handle.?)));
    const pin_slice = pin[0..pin_len];
    const rp_id_slice = if (rp_id) |r| r[0..rp_id_len] else null;
    const perms = permissionsFromByte(permissions);

    // Actual order is: transport, enc, permissions, rpId, pin, allocator
    const token = client.cbor_commands.client_pin.getPinUvAuthTokenUsingPinWithPermissions(
        t,
        enc,
        perms,
        rp_id_slice,
        pin_slice,
        allocator,
    ) catch |e| {
        std.log.err("getPinUvAuthTokenUsingPinWithPermissions failed: {}", .{e});
        return -1;
    };

    // Return the token directly - caller takes ownership
    token_out.* = @constCast(token.ptr);
    token_len_out.* = token.len;

    return 0;
}

/// Get PIN/UV auth token using UV with permissions (CTAP 2.1+)
/// Returns 0 on success with allocated token, -1 on failure
/// rp_id can be null if not needed for the requested permissions
export fn client_pin_get_pin_uv_auth_token_using_uv_with_permissions(
    transport: *CTransport,
    enc: *Encapsulation,
    permissions: u8,
    rp_id: ?[*]const u8,
    rp_id_len: usize,
    token_out: *[*]u8,
    token_len_out: *usize,
) callconv(.c) i32 {
    if (transport.handle == null) return -1;

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport.handle.?)));
    const rp_id_slice = if (rp_id) |r| r[0..rp_id_len] else null;
    const perms = permissionsFromByte(permissions);

    const token = client.cbor_commands.client_pin.getPinUvAuthTokenUsingUvWithPermissions(
        t,
        enc,
        perms,
        rp_id_slice,
        allocator,
    ) catch |e| {
        std.log.err("getPinUvAuthTokenUsingUvWithPermissions failed: {}", .{e});
        return -1;
    };

    // Return the token directly - caller takes ownership
    token_out.* = @constCast(token.ptr);
    token_len_out.* = token.len;

    return 0;
}

/// Free PIN token buffer allocated by the library
export fn client_pin_free_token(token: [*]u8, len: usize) callconv(.c) void {
    const slice = token[0..len];
    allocator.free(slice);
}
