#include <stdint.h>
#include <stdlib.h>

typedef enum{
    // The given operation was successful
    Error_SUCCESS = 0,
    // The given value already exists
    Error_DoesAlreadyExist = -1,
    // The requested value doesn't exist
    Error_DoesNotExist = -2,
    // Credentials can't be inserted into the key-store
    Error_KeyStoreFull = -3,
    // The client ran out of memory
    Error_OutOfMemory = -4,
    // The operation timed out
    Error_Timeout = -5,
    // Unspecified operation
    Error_Other = -6,
} Error;

typedef enum{
    // The user has denied the action
    UpResult_Denied = 0,
    // The user has accepted the action
    UpResult_Accepted = 1,
    // The user presence check has timed out
    UpResult_Timeout = 2,
} UpResult;

typedef enum{
    // The user has denied the action
    UvResult_Denied = 0,
    // The user has accepted the action
    UvResult_Accepted = 1,
    // The user has accepted the action
    UvResult_AcceptedWithUp = 2,
    // The user presence check has timed out
    UvResult_Timeout = 3,
} UvResult;

typedef enum{
    Transports_usb = 1,
    Transports_nfc = 2,
    Transports_ble = 4,
} Transports;


typedef struct {
    uint8_t id[64];
    uint8_t id_len;
    uint8_t rp_id[128];
    uint8_t rp_id_len;
    uint8_t rp_name[64];
    uint8_t rp_name_len;
    uint8_t user_id[64];
    uint8_t user_id_len;
    uint8_t user_name[64];
    uint8_t user_name_len;
    uint8_t user_display_name[64];
    uint8_t user_display_name_len;
    uint32_t sign_count;
    int32_t alg;
    uint8_t private_key[32];
    int64_t created;
    uint8_t discoverable;
    uint8_t cred_protect;
} FfiCredential;

typedef struct{
    UpResult (*up)(const char* info, const char* user, const char* rp);
    UvResult (*uv)(const char* info, const char* user, const char* rp);
    int (*select)(const char* rpId, char** users);
    int (*read)(const char* id, const char* rp, char*** out);
    int (*write)(const FfiCredential* credential);
    int (*del)(const char* id);
    int (*read_first)(const char* id, const char* rp, const char* hash, FfiCredential* out);
    int (*read_next)(FfiCredential* out);
} Callbacks;

// Authenticator options flags
typedef struct {
    // Resident key support (store keys on device)
    int rk;
    // User presence capable
    int up;
    // User verification configured (-1 = not capable, 0 = capable but not configured, 1 = capable and configured)
    int uv;
    // Platform device (can't be removed)
    int plat;
    // Client PIN configured (-1 = not capable, 0 = capable but not set, 1 = capable and set)
    int client_pin;
    // PIN/UV auth token support
    int pin_uv_auth_token;
    // Credential management support
    int cred_mgmt;
    // Biometric enrollment support
    int bio_enroll;
    // Large blobs support
    int large_blobs;
    // Enterprise attestation support (-1 = not supported, 0 = supported but disabled, 1 = supported and enabled)
    int ep;
    // Always require user verification (-1 = not supported, 0 = supported but disabled, 1 = supported and enabled)
    int always_uv;
} AuthOptions;

// Custom command handler function pointer
// Takes: auth context, request data, request length, response buffer, response buffer size
// Returns: response length (0 = error)
typedef size_t (*CustomCommandHandler)(void* auth, const uint8_t* request, size_t request_len,
                                       uint8_t* response, size_t response_size);

// Custom command mapping
typedef struct {
    uint8_t cmd;  // Command byte (0x40-0xbf for vendor-specific)
    CustomCommandHandler handler;
} CustomCommand;

typedef struct{
    // A UUID/ String representing the type of authenticator.
    char aaguid[16];

    // === Command Configuration ===
    // Pointer to array of standard command bytes to enable. NULL = use defaults
    const uint8_t* enabled_commands;
    // Length of enabled_commands array. 0 = use defaults
    size_t enabled_commands_len;
    // Pointer to array of custom vendor commands. NULL = no custom commands
    const CustomCommand* custom_commands;
    // Length of custom_commands array
    size_t custom_commands_len;

    // === Authenticator Options ===
    // Options flags. If NULL, uses defaults
    const AuthOptions* options;

    // === Credential Management ===
    // Maximum number of discoverable credentials. 0 = use default (9999)
    uint32_t max_credentials;

    // === Extensions ===
    // Pointer to array of extension name strings. NULL = use defaults (only "credProtect")
    const char** extensions;
    // Length of extensions array
    size_t extensions_len;

    // === Firmware Version ===
    // Firmware version to report in getInfo. 0 = not specified
    uint32_t firmware_version;

    // === Transports ===
    // Transport flags: 1=USB, 2=NFC, 4=BLE. 0 = no transports specified (library decides)
    uint8_t transports;
} AuthSettings;

void* auth_init(Callbacks, AuthSettings);
void auth_deinit(void*);
// Process CTAP request and write response to buffer
// Returns the length of the response written to response_buffer
size_t auth_handle(void* auth, const uint8_t* request_data, size_t request_len,
                   uint8_t* response_buffer, size_t response_buffer_size);

// Set PIN hash for the authenticator (SHA-256 hash of the PIN, up to 63 bytes)
// This must be called before auth_init if you want the authenticator to support PIN
void auth_set_pin_hash(const uint8_t* pin_hash, size_t len);

// CTAPHID protocol handler functions
void* ctaphid_init();
void ctaphid_deinit(void*);
void* ctaphid_handle(void*, const char*, size_t);
void* ctaphid_iterator(void*);
int ctaphid_iterator_next(void*, char*);
void ctaphid_iterator_deinit(void*);

int ctaphid_response_get_cmd(void* response);
size_t ctaphid_response_get_data(void* response, char* out, size_t max_len);
int ctaphid_response_set_data(void* response, const char* data, size_t len);

int uhid_open();
int uhid_read_packet(int, char*);
int uhid_write_packet(int, char*, size_t);
void uhid_close(int);

// Client-side APIs for device enumeration and communication

// Transport types
typedef enum {
    TransportType_USB = 0,
    TransportType_NFC = 1,
    TransportType_BLE = 2,
} TransportType;

// Transport operations
typedef struct {
    void* handle;
    TransportType type;
    char* description;
} Transport;

// Transport enumeration
typedef struct {
    Transport** transports;
    size_t count;
} TransportList;

TransportList* transport_enumerate();
void transport_list_free(TransportList*);

// Transport operations
int transport_open(Transport* transport);
void transport_close(Transport* transport);
int transport_write(Transport* transport, const char* data, size_t len);
int transport_read(Transport* transport, char* buffer, size_t max_len, int timeout_ms);
TransportType transport_get_type(Transport* transport);
const char* transport_get_description(Transport* transport);
void transport_free(Transport* transport);

// CBOR command operations
typedef struct {
    void* internal;
} CborCommand;

typedef enum {
    CborCommandStatus_Pending = 0,
    CborCommandStatus_Fulfilled = 1,
    CborCommandStatus_Rejected = 2,
} CborCommandStatus;

typedef struct {
    CborCommandStatus status;
    union {
        char* data;      // for fulfilled
        int error_code;  // for rejected
    } result;
    size_t data_len;
} CborCommandResult;

// AuthenticatorGetInfo
CborCommand* cbor_authenticator_get_info(Transport* transport);

// Credential operations
typedef struct {
    const char* challenge;
    size_t challenge_len;
    const char* rp_id;
    const char* rp_name;
    const char* user_id;
    size_t user_id_len;
    const char* user_name;
    const char* user_display_name;
    uint32_t timeout_ms;
    int require_resident_key;
    int require_user_verification;
    const char* attestation_preference; // "none", "direct", "enterprise", "indirect"
    const char* exclude_credentials_json; // JSON array of credential descriptors
    const char* extensions_json; // JSON object of extensions
} CredentialCreationOptions;

typedef struct {
    const char* rp_id;
    const char* challenge;
    size_t challenge_len;
    uint32_t timeout_ms;
    const char* user_verification; // "discouraged", "preferred", "required"
    const char* allow_credentials_json; // JSON array of credential descriptors
} CredentialAssertionOptions;

CborCommand* cbor_credentials_create(Transport* transport, CredentialCreationOptions* options);
CborCommand* cbor_credentials_get(Transport* transport, CredentialAssertionOptions* options);

CborCommandResult* cbor_command_get_result(CborCommand* cmd, int timeout_ms);
void cbor_command_free(CborCommand* cmd);
void cbor_command_result_free(CborCommandResult* result);

// Credential Management operations
typedef enum {
    CredentialManagementError_SUCCESS = 0,
    CredentialManagementError_INVALID_COMMAND = 1,
    CredentialManagementError_INVALID_PARAMETER = 2,
    CredentialManagementError_INVALID_LENGTH = 3,
    CredentialManagementError_INVALID_SEQ = 4,
    CredentialManagementError_TIMEOUT = 5,
    CredentialManagementError_CHANNEL_BUSY = 6,
    CredentialManagementError_LOCK_REQUIRED = 7,
    CredentialManagementError_INVALID_CHANNEL = 8,
    CredentialManagementError_CBOR_UNEXPECTED_TYPE = 9,
    CredentialManagementError_INVALID_CBOR = 10,
    CredentialManagementError_MISSING_PARAMETER = 11,
    CredentialManagementError_LIMIT_EXCEEDED = 12,
    CredentialManagementError_UNSUPPORTED_EXTENSION = 13,
    CredentialManagementError_CREDENTIAL_EXCLUDED = 14,
    CredentialManagementError_PROCESSING = 15,
    CredentialManagementError_INVALID_CREDENTIAL = 16,
    CredentialManagementError_USER_ACTION_PENDING = 17,
    CredentialManagementError_OPERATION_PENDING = 18,
    CredentialManagementError_NO_OPERATIONS = 19,
    CredentialManagementError_UNSUPPORTED_ALGORITHM = 20,
    CredentialManagementError_OPERATION_DENIED = 21,
    CredentialManagementError_KEY_STORE_FULL = 22,
    CredentialManagementError_NOT_BUSY = 23,
    CredentialManagementError_NO_OPERATION_PENDING = 24,
    CredentialManagementError_UNSUPPORTED_OPTION = 25,
    CredentialManagementError_INVALID_OPTION = 26,
    CredentialManagementError_KEEPALIVE_CANCEL = 27,
    CredentialManagementError_NO_CREDENTIALS = 28,
    CredentialManagementError_USER_ACTION_TIMEOUT = 29,
    CredentialManagementError_NOT_ALLOWED = 30,
    CredentialManagementError_PIN_INVALID = 31,
    CredentialManagementError_PIN_BLOCKED = 32,
    CredentialManagementError_PIN_AUTH_INVALID = 33,
    CredentialManagementError_PIN_AUTH_BLOCKED = 34,
    CredentialManagementError_PIN_NOT_SET = 35,
    CredentialManagementError_PIN_REQUIRED = 36,
    CredentialManagementError_PIN_POLICY_VIOLATION = 37,
    CredentialManagementError_PIN_TOKEN_EXPIRED = 38,
    CredentialManagementError_REQUEST_TOO_LARGE = 39,
    CredentialManagementError_ACTION_TIMEOUT = 40,
    CredentialManagementError_UP_REQUIRED = 41,
    CredentialManagementError_UV_BLOCKED = 42,
    CredentialManagementError_INTEGRITY_FAILURE = 43,
    CredentialManagementError_INVALID_SUBCOMMAND = 44,
    CredentialManagementError_UV_INVALID = 45,
    CredentialManagementError_UNAUTHORIZED_PERMISSION = 46,
    CredentialManagementError_OTHER = -1,
} CredentialManagementError;

// Get credentials metadata (total count)
int credential_management_get_metadata(
    void* transport,
    const uint8_t* pin_token,
    size_t pin_token_len,
    uint8_t protocol,
    uint32_t* existing_count_out,
    uint32_t* max_remaining_out
);

// Begin RP enumeration - returns total count
int credential_management_enumerate_rps_begin(
    void* transport,
    const uint8_t* pin_token,
    size_t pin_token_len,
    uint8_t protocol,
    uint32_t* total_rps_out,
    uint8_t* rp_id_hash_out,
    char** rp_id_out,
    size_t* rp_id_len_out
);

// Get next RP in enumeration
int credential_management_enumerate_rps_next(
    void* transport,
    uint8_t* rp_id_hash_out,
    char** rp_id_out,
    size_t* rp_id_len_out
);

// Begin credential enumeration for an RP
int credential_management_enumerate_credentials_begin(
    void* transport,
    const uint8_t* rp_id_hash,
    const uint8_t* pin_token,
    size_t pin_token_len,
    uint8_t protocol,
    uint32_t* total_credentials_out,
    FfiCredential* credential_out
);

// Get next credential in enumeration
int credential_management_enumerate_credentials_next(
    void* transport,
    FfiCredential* credential_out
);

// Delete a credential by ID
int credential_management_delete_credential(
    void* transport,
    const uint8_t* credential_id,
    size_t credential_id_len,
    const uint8_t* pin_token,
    size_t pin_token_len,
    uint8_t protocol
);

// Update user information for a credential
int credential_management_update_user_information(
    void* transport,
    const uint8_t* credential_id,
    size_t credential_id_len,
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* user_name,
    size_t user_name_len,
    const uint8_t* user_display_name,
    size_t user_display_name_len,
    const uint8_t* pin_token,
    size_t pin_token_len,
    uint8_t protocol
);

// Free allocated strings
void credential_management_free_string(char* str);

// Client PIN Protocol operations

/// Establish PIN encapsulation with the authenticator
/// Returns opaque handle to encapsulation on success, null on failure
/// Must be freed with client_pin_encapsulation_free
void* client_pin_encapsulation_new(
    void* transport,
    uint8_t protocol
);

/// Get the platform's public key from an encapsulation
/// Returns 0 on success, negative on failure
/// public_key_out must be at least 65 bytes (uncompressed P-256 point: 0x04 || x || y)
int client_pin_encapsulation_get_platform_key(
    const void* encapsulation,
    uint8_t* public_key_out
);

/// Free PIN encapsulation
void client_pin_encapsulation_free(void* enc);

/// Get PIN token from authenticator
/// Returns 0 on success, negative on failure
/// token_out and token_len_out will be set to allocated buffer and its length
/// Caller must free with client_pin_free_token
int client_pin_get_pin_token(
    void* transport,
    void* enc,
    const uint8_t* pin,
    size_t pin_len,
    uint8_t** token_out,
    size_t* token_len_out
);

/// Get PIN/UV auth token with permissions (CTAP 2.1+)
/// Returns 0 on success, negative on failure
/// permissions: bitmap (mc=1, ga=2, cm=4, be=8, lbw=16, acfg=32)
/// Caller must free token with client_pin_free_token
int client_pin_get_pin_uv_auth_token_using_pin_with_permissions(
    void* transport,
    void* enc,
    const uint8_t* pin,
    size_t pin_len,
    uint8_t permissions,
    const uint8_t* rp_id,
    size_t rp_id_len,
    uint8_t** token_out,
    size_t* token_len_out
);

/// Get PIN/UV auth token using UV with permissions (CTAP 2.1+)
/// Returns 0 on success, negative on failure
/// Caller must free token with client_pin_free_token
int client_pin_get_pin_uv_auth_token_using_uv_with_permissions(
    void* transport,
    void* enc,
    uint8_t permissions,
    const uint8_t* rp_id,
    size_t rp_id_len,
    uint8_t** token_out,
    size_t* token_len_out
);

/// Free PIN token buffer
void client_pin_free_token(uint8_t* token, size_t len);

