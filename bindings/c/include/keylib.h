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

typedef struct{
    // User presence request; user and rp might be NULL!
    UpResult (*up)(const char* info, const char* user, const char* rp);
    // User verification request; user and rp might be NULL!
    UvResult (*uv)(const char* info, const char* user, const char* rp);
    // Callback for selecting a user account.
    // The platform is expected to return the index of the selected user or an error.
    int (*select)(const char* rpId, char** users);
    // Read the payload specified by id and rp into out.
    // The allocated memory is owned by the caller and he is responsible for freeing it.
    // Returns either the length of the string assigned to out or an error.
    int (*read)(const char* id, const char* rp, char*** out);
    // Persist the given data; the id is considered unique.
    int (*write)(const char* id, const char* rp, const char* data);
    // Delete the entry with the given id.
    int (*del)(const char* id);
    // Read the first credential matching the given filters.
    // Used for credential enumeration.
    int (*read_first)(const char* id, const char* rp, const char* hash, char** out);
    // Read the next credential in the enumeration.
    int (*read_next)(char** out);
} Callbacks;

typedef struct{
    // A UUID/ String representing the type of authenticator.
    char aaguid[16];
} AuthSettings;

void* auth_init(Callbacks);
void auth_deinit(void*);
void auth_handle(void*, void*);

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
CborCommandResult* cbor_command_get_result(CborCommand* cmd, int timeout_ms);
void cbor_command_free(CborCommand* cmd);
void cbor_command_result_free(CborCommandResult* result);
