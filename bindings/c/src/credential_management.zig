const std = @import("std");
const allocator = std.heap.c_allocator;
const client = @import("clientlib");
const fido = @import("keylib");
const cbor = @import("zbor");
const client_err = client.err;
const ClientTransport = client.Transports.Transport;
const CredentialManagementRequest = fido.ctap.request.CredentialManagement;
const CredentialManagementResponse = fido.ctap.response.CredentialManagement;
const FfiCredential = @import("keylib.zig").FfiCredential;
const Transport = @import("keylib.zig").Transport;

pub const CredentialManagementError = enum(c_int) {
    SUCCESS = 0,
    INVALID_COMMAND = 1,
    INVALID_PARAMETER = 2,
    INVALID_LENGTH = 3,
    INVALID_SEQ = 4,
    TIMEOUT = 5,
    CHANNEL_BUSY = 6,
    LOCK_REQUIRED = 7,
    INVALID_CHANNEL = 8,
    CBOR_UNEXPECTED_TYPE = 9,
    INVALID_CBOR = 10,
    MISSING_PARAMETER = 11,
    LIMIT_EXCEEDED = 12,
    UNSUPPORTED_EXTENSION = 13,
    CREDENTIAL_EXCLUDED = 14,
    PROCESSING = 15,
    INVALID_CREDENTIAL = 16,
    USER_ACTION_PENDING = 17,
    OPERATION_PENDING = 18,
    NO_OPERATIONS = 19,
    UNSUPPORTED_ALGORITHM = 20,
    OPERATION_DENIED = 21,
    KEY_STORE_FULL = 22,
    NOT_BUSY = 23,
    NO_OPERATION_PENDING = 24,
    UNSUPPORTED_OPTION = 25,
    INVALID_OPTION = 26,
    KEEPALIVE_CANCEL = 27,
    NO_CREDENTIALS = 28,
    USER_ACTION_TIMEOUT = 29,
    NOT_ALLOWED = 30,
    PIN_INVALID = 31,
    PIN_BLOCKED = 32,
    PIN_AUTH_INVALID = 33,
    PIN_AUTH_BLOCKED = 34,
    PIN_NOT_SET = 35,
    PIN_REQUIRED = 36,
    PIN_POLICY_VIOLATION = 37,
    PIN_TOKEN_EXPIRED = 38,
    REQUEST_TOO_LARGE = 39,
    ACTION_TIMEOUT = 40,
    UP_REQUIRED = 41,
    UV_BLOCKED = 42,
    INTEGRITY_FAILURE = 43,
    INVALID_SUBCOMMAND = 44,
    UV_INVALID = 45,
    UNAUTHORIZED_PERMISSION = 46,
    OTHER = -1,
};

fn cborErrorToCredentialManagementError(e: anyerror) CredentialManagementError {
    return switch (e) {
        error.InvalidCommand => .INVALID_COMMAND,
        error.InvalidParameter => .INVALID_PARAMETER,
        error.InvalidLength => .INVALID_LENGTH,
        error.InvalidSeq => .INVALID_SEQ,
        error.Timeout => .TIMEOUT,
        error.ChannelBusy => .CHANNEL_BUSY,
        error.LockRequired => .LOCK_REQUIRED,
        error.InvalidChannel => .INVALID_CHANNEL,
        error.CborUnexpectedType => .CBOR_UNEXPECTED_TYPE,
        error.InvalidCbor => .INVALID_CBOR,
        error.MissingParameter => .MISSING_PARAMETER,
        error.LimitExceeded => .LIMIT_EXCEEDED,
        error.UnsupportedExtension => .UNSUPPORTED_EXTENSION,
        error.CredentialExcluded => .CREDENTIAL_EXCLUDED,
        error.Processing => .PROCESSING,
        error.InvalidCredential => .INVALID_CREDENTIAL,
        error.UserActionPending => .USER_ACTION_PENDING,
        error.OperationPending => .OPERATION_PENDING,
        error.NoOperations => .NO_OPERATIONS,
        error.UnsupportedAlgorithm => .UNSUPPORTED_ALGORITHM,
        error.OperationDenied => .OPERATION_DENIED,
        error.KeyStoreFull => .KEY_STORE_FULL,
        error.NotBusy => .NOT_BUSY,
        error.NoOperationPending => .NO_OPERATION_PENDING,
        error.UnsupportedOption => .UNSUPPORTED_OPTION,
        error.InvalidOption => .INVALID_OPTION,
        error.KeepaliveCancel => .KEEPALIVE_CANCEL,
        error.NoCredentials => .NO_CREDENTIALS,
        error.UserActionTimeout => .USER_ACTION_TIMEOUT,
        error.NotAllowed => .NOT_ALLOWED,
        error.PinInvalid => .PIN_INVALID,
        error.PinBlocked => .PIN_BLOCKED,
        error.PinAuthInvalid => .PIN_AUTH_INVALID,
        error.PinAuthBlocked => .PIN_AUTH_BLOCKED,
        error.PinNotSet => .PIN_NOT_SET,
        error.PinRequired => .PIN_REQUIRED,
        error.PinPolicyViolation => .PIN_POLICY_VIOLATION,
        error.PinTokenExpired => .PIN_TOKEN_EXPIRED,
        error.RequestTooLarge => .REQUEST_TOO_LARGE,
        error.ActionTimeout => .ACTION_TIMEOUT,
        error.UpRequired => .UP_REQUIRED,
        error.UvBlocked => .UV_BLOCKED,
        error.IntegrityFailure => .INTEGRITY_FAILURE,
        error.InvalidSubcommand => .INVALID_SUBCOMMAND,
        error.UvInvalid => .UV_INVALID,
        error.UnauthorizedPermission => .UNAUTHORIZED_PERMISSION,
        else => .OTHER,
    };
}

fn executeCredentialManagementCommand(
    transport: *ClientTransport,
    sub_command: CredentialManagementRequest.SubCommand,
    params: ?CredentialManagementRequest.SubCommandParams,
    pin_token: []const u8,
    protocol: u8,
) !CredentialManagementResponse {
    // Convert protocol to enum
    const pin_protocol: fido.ctap.pinuv.common.PinProtocol = if (protocol == 1) .V1 else .V2;

    // Calculate pinUvAuthParam based on subCommand
    const pin_uv_auth_param = blk: {
        // Skip PIN auth if token is all zeros (placeholder)
        if (pin_token.len == 0 or std.mem.allEqual(u8, pin_token, 0)) {
            break :blk null;
        }

        const PinUvAuth = fido.ctap.pinuv.PinUvAuth;
        const sub_cmd_byte: []const u8 = switch (sub_command) {
            .getCredsMetadata => "\x01",
            .enumerateRPsBegin => "\x02",
            .enumerateRPsGetNextRP => break :blk null, // No auth for continuation
            .enumerateCredentialsBegin => "\x04",
            .enumerateCredentialsGetNextCredential => break :blk null, // No auth for continuation
            .deleteCredential => "\x05",
            .updateUserInformation => "\x06",
        };

        const auth_param = switch (pin_protocol) {
            .V1 => PinUvAuth.authenticate_v1(pin_token, sub_cmd_byte),
            .V2 => PinUvAuth.authenticate_v2(pin_token, sub_cmd_byte),
        };
        break :blk auth_param.get();
    };

    // Build the request
    const request = CredentialManagementRequest{
        .subCommand = sub_command,
        .subCommandParams = params,
        .pinUvAuthProtocol = if (pin_uv_auth_param != null) pin_protocol else null,
        .pinUvAuthParam = pin_uv_auth_param,
    };

    // Serialize the request - use the module-level allocator constant
    var arr = std.Io.Writer.Allocating.init(allocator);
    defer arr.deinit();

    try arr.writer.writeByte(0x0a); // authenticatorCredentialManagement command
    try cbor.stringify(request, .{}, &arr.writer);

    // Send the request
    try transport.write(arr.written());

    // Read the response
    const response = try transport.read(allocator) orelse return error.MissingResponse;
    defer allocator.free(response);

    // Check status code
    if (response.len == 0) return error.InvalidResponse;

    if (response[0] != 0) {
        return client_err.errorFromInt(response[0]);
    }

    // Parse the response
    if (response.len < 2) {
        // Empty success response (e.g., for delete operations)
        return CredentialManagementResponse{};
    }

    var parsed = try cbor.parse(CredentialManagementResponse, try cbor.DataItem.new(response[1..]), .{ .allocator = allocator });
    defer parsed.deinit(allocator);

    // Create a copy of the response that owns its data
    return CredentialManagementResponse{
        .existingResidentCredentialsCount = parsed.existingResidentCredentialsCount,
        .maxPossibleRemainingResidentCredentialsCount = parsed.maxPossibleRemainingResidentCredentialsCount,
        .rp = if (parsed.rp) |rp| .{
            .id = (try fido.common.dt.ABS128T.fromSlice(rp.id.get())) orelse return error.InvalidData,
            .name = if (rp.name) |n| (try fido.common.dt.ABS64T.fromSlice(n.get())) else null,
        } else null,
        .rpIDHash = if (parsed.rpIDHash) |hash| hash else null,
        .totalRPs = parsed.totalRPs,
        .user = if (parsed.user) |u| .{
            .id = (try fido.common.dt.ABS64B.fromSlice(u.id.get())) orelse return error.InvalidData,
            .name = if (u.name) |n| (try fido.common.dt.ABS64T.fromSlice(n.get())) else null,
            .displayName = if (u.displayName) |d| (try fido.common.dt.ABS64T.fromSlice(d.get())) else null,
        } else null,
        .credentialID = if (parsed.credentialID) |cred_id| .{
            .id = (try fido.common.dt.ABS64B.fromSlice(cred_id.id.get())) orelse return error.InvalidData,
            .type = cred_id.type,
            .transports = cred_id.transports,
        } else null,
        .publicKey = parsed.publicKey,
        .totalCredentials = parsed.totalCredentials,
        .credProtect = parsed.credProtect,
        .largeBlobKey = parsed.largeBlobKey,
    };
}

fn credentialToFfi(cred: fido.ctap.authenticator.Credential) FfiCredential {
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

// Get credentials metadata (total count)
export fn credential_management_get_metadata(
    transport: ?*anyopaque,
    pin_token: [*c]const u8,
    pin_token_len: usize,
    protocol: u8,
    existing_count_out: *u32,
    max_remaining_out: *u32,
) callconv(.c) c_int {
    if (transport == null or pin_token == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }

    const transport_ptr = @as(*Transport, @ptrCast(@alignCast(transport.?)));
    if (transport_ptr.handle == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }

    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport_ptr.handle.?)));
    const pin_token_slice = pin_token[0..pin_token_len];

    const response = executeCredentialManagementCommand(
        t,
        .getCredsMetadata,
        null,
        pin_token_slice,
        protocol,
    ) catch |err| return @intFromEnum(cborErrorToCredentialManagementError(err));

    existing_count_out.* = response.existingResidentCredentialsCount orelse 0;
    max_remaining_out.* = response.maxPossibleRemainingResidentCredentialsCount orelse 0;

    return @intFromEnum(CredentialManagementError.SUCCESS);
}

// Begin RP enumeration - returns total count
export fn credential_management_enumerate_rps_begin(
    transport: ?*anyopaque,
    pin_token: [*c]const u8,
    pin_token_len: usize,
    protocol: u8,
    total_rps_out: ?*u32,
    rp_id_hash_out: ?*[32]u8,
    rp_id_out: ?*[*c]u8,
    rp_id_len_out: ?*usize,
) callconv(.c) c_int {
    if (transport == null or pin_token == null or total_rps_out == null or rp_id_hash_out == null or rp_id_out == null or rp_id_len_out == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }

    const transport_ptr = @as(*Transport, @ptrCast(@alignCast(transport.?)));
    if (transport_ptr.handle == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }
    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport_ptr.handle.?)));
    const pin_token_slice = pin_token[0..pin_token_len];

    const response = executeCredentialManagementCommand(
        t,
        .enumerateRPsBegin,
        null,
        pin_token_slice,
        protocol,
    ) catch |err| return @intFromEnum(cborErrorToCredentialManagementError(err));

    total_rps_out.?.* = response.totalRPs orelse 0;

    if (response.rpIDHash) |hash| {
        @memcpy(rp_id_hash_out.?, &hash);
    } else {
        @memset(rp_id_hash_out.?, 0);
    }

    if (response.rp) |rp| {
        const rp_id_slice = rp.id.get();
        const rp_id_copy = allocator.dupeZ(u8, rp_id_slice) catch return @intFromEnum(CredentialManagementError.OTHER);
        rp_id_out.?.* = rp_id_copy.ptr;
        rp_id_len_out.?.* = rp_id_slice.len;
    } else {
        rp_id_out.?.* = null;
        rp_id_len_out.?.* = 0;
    }

    return @intFromEnum(CredentialManagementError.SUCCESS);
}

// Get next RP in enumeration
export fn credential_management_enumerate_rps_next(
    transport: ?*anyopaque,
    rp_id_hash_out: ?*[32]u8,
    rp_id_out: ?*[*c]u8,
    rp_id_len_out: ?*usize,
) callconv(.c) c_int {
    if (transport == null or rp_id_hash_out == null or rp_id_out == null or rp_id_len_out == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }

    const transport_ptr = @as(*Transport, @ptrCast(@alignCast(transport.?)));
    if (transport_ptr.handle == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }
    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport_ptr.handle.?)));

    const response = executeCredentialManagementCommand(
        t,
        .enumerateRPsGetNextRP,
        null,
        &[_]u8{}, // Empty pin token for continuation
        0, // Protocol not needed for continuation
    ) catch |err| return @intFromEnum(cborErrorToCredentialManagementError(err));

    if (response.rpIDHash) |hash| {
        @memcpy(rp_id_hash_out.?, &hash);
    } else {
        @memset(rp_id_hash_out.?, 0);
    }

    if (response.rp) |rp| {
        const rp_id_slice = rp.id.get();
        const rp_id_copy = allocator.dupeZ(u8, rp_id_slice) catch return @intFromEnum(CredentialManagementError.OTHER);
        rp_id_out.?.* = rp_id_copy.ptr;
        rp_id_len_out.?.* = rp_id_slice.len;
    } else {
        rp_id_out.?.* = null;
        rp_id_len_out.?.* = 0;
    }

    return @intFromEnum(CredentialManagementError.SUCCESS);
}

// Begin credential enumeration for an RP
export fn credential_management_enumerate_credentials_begin(
    transport: ?*anyopaque,
    rp_id_hash: ?*const [32]u8,
    pin_token: [*c]const u8,
    pin_token_len: usize,
    protocol: u8,
    total_credentials_out: ?*u32,
    credential_out: ?*FfiCredential,
) callconv(.c) c_int {
    if (transport == null or rp_id_hash == null or pin_token == null or total_credentials_out == null or credential_out == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }

    const transport_ptr = @as(*Transport, @ptrCast(@alignCast(transport.?)));
    if (transport_ptr.handle == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }
    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport_ptr.handle.?)));
    const pin_token_slice = pin_token[0..pin_token_len];

    const params = CredentialManagementRequest.SubCommandParams{
        .rpIDHash = rp_id_hash.?.*,
    };

    const response = executeCredentialManagementCommand(
        t,
        .enumerateCredentialsBegin,
        params,
        pin_token_slice,
        protocol,
    ) catch |err| return @intFromEnum(cborErrorToCredentialManagementError(err));

    total_credentials_out.?.* = response.totalCredentials orelse 0;

    if (response.user != null or response.credentialID != null or response.publicKey != null) {
        // Create a synthetic credential from the response
        var cred: fido.ctap.authenticator.Credential = undefined;

        if (response.credentialID) |cred_id| {
            cred.id = cred_id.id;
        } else {
            return @intFromEnum(CredentialManagementError.INVALID_CREDENTIAL);
        }

        // We need RP ID hash, but we don't have the full RP info here
        // This is a limitation - we might need to store RP context
        cred.rp = .{
            .id = (fido.common.dt.ABS128T.fromSlice("placeholder") catch null) orelse return @intFromEnum(CredentialManagementError.OTHER),
            .name = null,
        };

        if (response.user) |user| {
            cred.user = user;
        } else {
            cred.user = .{
                .id = (fido.common.dt.ABS64B.fromSlice("placeholder") catch null) orelse return @intFromEnum(CredentialManagementError.OTHER),
                .name = null,
                .displayName = null,
            };
        }

        cred.sign_count = 0; // Not provided in enumeration
        cred.key = .{
            .P256 = .{
                .alg = .Es256,
                .x = undefined,
                .y = undefined,
                .d = [_]u8{0} ** 32,
            },
        };
        cred.created = 0;
        cred.discoverable = true;
        cred.policy = .userVerificationOptional;

        credential_out.?.* = credentialToFfi(cred);
    }

    return @intFromEnum(CredentialManagementError.SUCCESS);
}

// Get next credential in enumeration
export fn credential_management_enumerate_credentials_next(
    transport: ?*anyopaque,
    credential_out: ?*FfiCredential,
) callconv(.c) c_int {
    if (transport == null or credential_out == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }

    const transport_ptr = @as(*Transport, @ptrCast(@alignCast(transport.?)));
    if (transport_ptr.handle == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }
    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport_ptr.handle.?)));

    const response = executeCredentialManagementCommand(
        t,
        .enumerateCredentialsGetNextCredential,
        null,
        &[_]u8{}, // Empty pin token for continuation
        0, // Protocol not needed for continuation
    ) catch |err| return @intFromEnum(cborErrorToCredentialManagementError(err));

    if (response.user != null or response.credentialID != null or response.publicKey != null) {
        // Create a synthetic credential from the response
        var cred: fido.ctap.authenticator.Credential = undefined;

        if (response.credentialID) |cred_id| {
            cred.id = cred_id.id;
        } else {
            return @intFromEnum(CredentialManagementError.INVALID_CREDENTIAL);
        }

        // We need RP ID hash, but we don't have the full RP info from next call
        // This is a limitation - using placeholder
        cred.rp = .{
            .id = (fido.common.dt.ABS128T.fromSlice("placeholder") catch null) orelse return @intFromEnum(CredentialManagementError.OTHER),
            .name = null,
        };

        if (response.user) |user| {
            cred.user = user;
        } else {
            cred.user = .{
                .id = (fido.common.dt.ABS64B.fromSlice("placeholder") catch null) orelse return @intFromEnum(CredentialManagementError.OTHER),
                .name = null,
                .displayName = null,
            };
        }

        cred.sign_count = 0;
        cred.key = .{
            .P256 = .{
                .alg = .Es256,
                .x = undefined,
                .y = undefined,
                .d = [_]u8{0} ** 32,
            },
        };
        cred.created = 0;
        cred.discoverable = true;
        cred.policy = .userVerificationOptional;

        credential_out.?.* = credentialToFfi(cred);
    }

    return @intFromEnum(CredentialManagementError.SUCCESS);
}

// Delete a credential by ID
export fn credential_management_delete_credential(
    transport: ?*anyopaque,
    credential_id: [*c]const u8,
    credential_id_len: usize,
    pin_token: [*c]const u8,
    pin_token_len: usize,
    protocol: u8,
) callconv(.c) c_int {
    if (transport == null or credential_id == null or pin_token == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }

    const transport_ptr = @as(*Transport, @ptrCast(@alignCast(transport.?)));
    if (transport_ptr.handle == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }
    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport_ptr.handle.?)));
    const cred_id_slice = credential_id[0..credential_id_len];
    const pin_token_slice = pin_token[0..pin_token_len];

    const cred_id_abs = (fido.common.dt.ABS64B.fromSlice(cred_id_slice) catch return @intFromEnum(CredentialManagementError.INVALID_CREDENTIAL)) orelse return @intFromEnum(CredentialManagementError.INVALID_CREDENTIAL);

    const cred_desc = fido.common.PublicKeyCredentialDescriptor{
        .id = cred_id_abs,
        .type = .@"public-key",
        .transports = null,
    };

    const params = CredentialManagementRequest.SubCommandParams{
        .credentialID = cred_desc,
    };

    _ = executeCredentialManagementCommand(
        t,
        .deleteCredential,
        params,
        pin_token_slice,
        protocol,
    ) catch |err| return @intFromEnum(cborErrorToCredentialManagementError(err));

    return @intFromEnum(CredentialManagementError.SUCCESS);
}

// Update user information for a credential
export fn credential_management_update_user_information(
    transport: ?*anyopaque,
    credential_id: [*c]const u8,
    credential_id_len: usize,
    user_id: [*c]const u8,
    user_id_len: usize,
    user_name: [*c]const u8,
    user_name_len: usize,
    user_display_name: [*c]const u8,
    user_display_name_len: usize,
    pin_token: [*c]const u8,
    pin_token_len: usize,
    protocol: u8,
) callconv(.c) c_int {
    if (transport == null or credential_id == null or user_id == null or pin_token == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }

    const transport_ptr = @as(*Transport, @ptrCast(@alignCast(transport.?)));
    if (transport_ptr.handle == null) {
        return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);
    }
    const t = @as(*ClientTransport, @ptrCast(@alignCast(transport_ptr.handle.?)));
    const cred_id_slice = credential_id[0..credential_id_len];
    const user_id_slice = user_id[0..user_id_len];
    const pin_token_slice = pin_token[0..pin_token_len];

    const cred_id_abs = (fido.common.dt.ABS64B.fromSlice(cred_id_slice) catch return @intFromEnum(CredentialManagementError.INVALID_CREDENTIAL)) orelse return @intFromEnum(CredentialManagementError.INVALID_CREDENTIAL);
    const uid_abs = (fido.common.dt.ABS64B.fromSlice(user_id_slice) catch return @intFromEnum(CredentialManagementError.INVALID_PARAMETER)) orelse return @intFromEnum(CredentialManagementError.INVALID_PARAMETER);

    const cred_desc = fido.common.PublicKeyCredentialDescriptor{
        .id = cred_id_abs,
        .type = .@"public-key",
        .transports = null,
    };

    var user = fido.common.User{
        .id = uid_abs,
        .name = null,
        .displayName = null,
    };

    if (user_name_len > 0) {
        user.name = (fido.common.dt.ABS64T.fromSlice(user_name[0..user_name_len]) catch null) orelse null;
    }

    if (user_display_name_len > 0) {
        user.displayName = (fido.common.dt.ABS64T.fromSlice(user_display_name[0..user_display_name_len]) catch null) orelse null;
    }

    const params = CredentialManagementRequest.SubCommandParams{
        .credentialID = cred_desc,
        .user = user,
    };

    _ = executeCredentialManagementCommand(
        t,
        .updateUserInformation,
        params,
        pin_token_slice,
        protocol,
    ) catch |err| return @intFromEnum(cborErrorToCredentialManagementError(err));

    return @intFromEnum(CredentialManagementError.SUCCESS);
}

// Free allocated strings
export fn credential_management_free_string(str: [*c]u8) void {
    if (str != null) {
        allocator.free(std.mem.span(str));
    }
}
