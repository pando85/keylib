const std = @import("std");
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const cbor = @import("zbor");
const fido = @import("../../../main.zig");
const dt = fido.common.dt;

pub fn authenticatorClientPin(
    auth: *fido.ctap.authenticator.Auth,
    request: []const u8,
    out: *std.Io.Writer,
) fido.ctap.StatusCodes {
    const retry_state = struct {
        threadlocal var ctr: u8 = 3;
        threadlocal var powerCycleState: bool = false;
    };

    const client_pin_param = cbor.parse(
        fido.ctap.request.ClientPin,
        cbor.DataItem.new(request) catch {
            return .ctap2_err_invalid_cbor;
        },
        .{},
    ) catch {
        return .ctap2_err_invalid_cbor;
    };

    var client_pin_response: ?fido.ctap.response.ClientPin = null;

    // Handle one of the sub-commands
    switch (client_pin_param.subCommand) {
        .getPinRetries => {
            const settings = auth.callbacks.read_settings();

            client_pin_response = .{
                .pinRetries = settings.pinRetries,
                .powerCycleState = retry_state.powerCycleState,
            };
        },
        .getUVRetries => {
            const settings = auth.callbacks.read_settings();

            client_pin_response = .{
                .uvRetries = settings.uvRetries,
            };
        },
        .getKeyAgreement => {
            const protocol = if (client_pin_param.pinUvAuthProtocol) |prot| prot else {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            };

            // return error if authenticator doesn't support the selected protocol.
            if (protocol != auth.token.version) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            client_pin_response = .{
                .keyAgreement = auth.token.getPublicKey(),
            };
        },
        .getPinUvAuthTokenUsingUvWithPermissions => {
            if (retry_state.ctr == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_blocked;
            }

            if (client_pin_param.pinUvAuthProtocol == null or
                client_pin_param.permissions == null or
                client_pin_param.permissions == null or
                client_pin_param.keyAgreement == null)
            {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            if (client_pin_param.pinUvAuthProtocol.? != auth.token.version) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            if (client_pin_param.permissions.? == 0) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            // Check if all requested premissions are valid
            const options = auth.settings.options;
            const cm = client_pin_param.cmPermissionSet() and (options.credMgmt == null or options.credMgmt.? == false);
            const be = client_pin_param.bePermissionSet() and (options.bioEnroll == null);
            const lbw = client_pin_param.lbwPermissionSet() and (options.largeBlobs == null or options.largeBlobs.? == false);
            const acfg = client_pin_param.acfgPermissionSet() and (options.authnrCfg == null or options.authnrCfg.? == false);
            // The mc and ga permissions are always considered authorized, thus they are not listed below.
            if (cm or be or lbw or acfg) {
                return fido.ctap.StatusCodes.ctap2_err_unauthorized_permission;
            }

            if (!auth.uvSupported()) {
                return fido.ctap.StatusCodes.ctap2_err_not_allowed;
            }

            const settings = auth.callbacks.read_settings();

            if (settings.uvRetries == 0) {
                return fido.ctap.StatusCodes.ctap2_err_uv_blocked;
            }

            var user_present = false;
            switch (auth.token.performBuiltInUv(
                true,
                auth,
                "User Verification",
                null,
                null,
            )) {
                .Blocked => return fido.ctap.StatusCodes.ctap2_err_uv_blocked,
                .Timeout => return fido.ctap.StatusCodes.ctap2_err_user_action_timeout,
                .Denied => {
                    return fido.ctap.StatusCodes.ctap2_err_uv_invalid;
                },
                .Accepted => {},
                .AcceptedWithUp => user_present = true,
            }

            auth.token.resetPinUvAuthToken(); // invalidates existing tokens
            auth.token.beginUsingPinUvAuthToken(user_present, auth.milliTimestamp());

            auth.token.permissions = client_pin_param.permissions.?;

            // If the rpId parameter is present, associate the permissions RP ID
            // with the pinUvAuthToken.
            if (client_pin_param.rpId) |rpId| {
                auth.token.setRpId(rpId.get()) catch {
                    // rpId is unexpectedly long
                    return fido.ctap.StatusCodes.ctap1_err_other;
                };
            }

            // Obtain the shared secret
            const shared_secret = auth.token.ecdh(
                client_pin_param.keyAgreement.?,
            ) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };

            // The authenticator returns the encrypted pinUvAuthToken for the
            // specified pinUvAuthProtocol, i.e. encrypt(shared secret, pinUvAuthToken).
            var enc_shared_secret: [48]u8 = undefined;
            auth.token.encrypt(
                &auth.token,
                shared_secret.get(),
                enc_shared_secret[0..],
                auth.token.pin_token[0..],
            );

            // Response
            client_pin_response = .{
                .pinUvAuthToken = (dt.ABS48B.fromSlice(&enc_shared_secret) catch unreachable).?,
            };
        },
        .getPinUvAuthTokenUsingPinWithPermissions => {
            // CTAP 2.1 - Get PIN token with permissions
            if (client_pin_param.pinUvAuthProtocol == null or
                client_pin_param.keyAgreement == null or
                client_pin_param.pinHashEnc == null or
                client_pin_param.permissions == null)
            {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            if (client_pin_param.pinUvAuthProtocol.? != auth.token.version) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            if (client_pin_param.permissions.? == 0) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            const settings = auth.callbacks.read_settings();

            // Check if PIN is set
            if (settings.pin == null) {
                return fido.ctap.StatusCodes.ctap2_err_pin_not_set;
            }

            // Check PIN retries
            if (settings.pinRetries == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
            }

            // Check if all requested permissions are valid
            const options = auth.settings.options;
            const cm = client_pin_param.cmPermissionSet() and (options.credMgmt == null or options.credMgmt.? == false);
            const be = client_pin_param.bePermissionSet() and (options.bioEnroll == null);
            const lbw = client_pin_param.lbwPermissionSet() and (options.largeBlobs == null or options.largeBlobs.? == false);
            const acfg = client_pin_param.acfgPermissionSet() and (options.authnrCfg == null or options.authnrCfg.? == false);

            if (cm or be or lbw or acfg) {
                return fido.ctap.StatusCodes.ctap2_err_unauthorized_permission;
            }

            // Obtain the shared secret
            const shared_secret = auth.token.ecdh(
                client_pin_param.keyAgreement.?,
            ) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };

            // Decrypt the PIN hash
            var decrypted_pin_hash: [16]u8 = undefined;
            const pin_hash_enc = client_pin_param.pinHashEnc.?.get();
            const shared_secret_bytes = shared_secret.get();

            // Create mutable key buffer (decrypt function pointer incorrectly requires mutable slice)
            var key_buffer_v1: [32]u8 = undefined;
            var key_buffer_v2: [64]u8 = undefined;

            switch (auth.token.version) {
                .V1 => {
                    // V1 uses first 32 bytes of shared secret, pinHashEnc is just 16 bytes
                    @memcpy(&key_buffer_v1, shared_secret_bytes[0..32]);
                    auth.token.decrypt(
                        &key_buffer_v1,
                        &decrypted_pin_hash,
                        pin_hash_enc[0..16],
                    );
                },
                .V2 => {
                    // V2 needs full 64-byte shared secret
                    // decrypt_v2 extracts IV from demCiphertext[0..16] and decrypts from [16..]
                    // So we pass the full 32-byte pinHashEnc (IV + encrypted data)
                    @memcpy(&key_buffer_v2, shared_secret_bytes[0..64]);
                    auth.token.decrypt(
                        &key_buffer_v2,
                        &decrypted_pin_hash,
                        pin_hash_enc[0..32],
                    );
                },
            }

            // Verify PIN by comparing hashes
            // Note: settings.pin already contains the SHA-256 hash of the PIN,
            // so we compare the first 16 bytes directly with the decrypted PIN hash
            const stored_pin_hash = settings.pin.?[0..16];

            if (!std.mem.eql(u8, &decrypted_pin_hash, stored_pin_hash)) {
                std.log.err("PIN verification failed - hashes don't match", .{});
                return fido.ctap.StatusCodes.ctap2_err_pin_invalid;
            }

            // PIN correct - generate and encrypt token with permissions
            auth.token.resetPinUvAuthToken();
            auth.token.beginUsingPinUvAuthToken(false, auth.milliTimestamp());
            auth.token.permissions = client_pin_param.permissions.?;

            // If the rpId parameter is present, associate it with the token
            if (client_pin_param.rpId) |rpId| {
                auth.token.setRpId(rpId.get()) catch {
                    return fido.ctap.StatusCodes.ctap1_err_other;
                };
            }

            var enc_shared_secret: [48]u8 = undefined;
            auth.token.encrypt(
                &auth.token,
                shared_secret_bytes,
                enc_shared_secret[0..],
                auth.token.pin_token[0..],
            );

            client_pin_response = .{
                .pinUvAuthToken = (dt.ABS48B.fromSlice(&enc_shared_secret) catch unreachable).?,
            };
        },
        else => {
            return fido.ctap.StatusCodes.ctap2_err_invalid_subcommand;
        },
    }

    // Serialize response and return
    if (client_pin_response) |resp| {
        cbor.stringify(resp, .{}, out) catch {
            return fido.ctap.StatusCodes.ctap1_err_other;
        };
    }

    return fido.ctap.StatusCodes.ctap1_err_success;
}
