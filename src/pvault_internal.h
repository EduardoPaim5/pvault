#ifndef PVAULT_INTERNAL_H
#define PVAULT_INTERNAL_H

#include "pvault/pvault.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <sodium.h>

#define PV_MAGIC_LEN 8U
#define PV_FILE_MAJOR 1U
#define PV_FILE_MINOR 0U
#define PV_FILE_HEADER_LEN 252U
#define PV_PASSWORD_SLOT_TYPE 1U
#define PV_RECOVERY_SLOT_TYPE 2U
#define PV_KDF_ARGON2ID13 1U
#define PV_AEAD_XCHACHA20POLY1305 1U
#define PV_V1_PASSWORD_OPSLIMIT UINT64_C(3)
#define PV_V1_PASSWORD_MEMLIMIT UINT64_C(268435456)
#define PV_V1_PASSWORD_OPSLIMIT_MIN PV_V1_PASSWORD_OPSLIMIT
#define PV_V1_PASSWORD_OPSLIMIT_MAX UINT64_C(10)
#define PV_V1_PASSWORD_MEMLIMIT_MIN PV_V1_PASSWORD_MEMLIMIT
#define PV_V1_PASSWORD_MEMLIMIT_MAX UINT64_C(1073741824)
#define PV_WRAP_KEY_BYTES crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define PV_WRAP_NONCE_BYTES crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define PV_WRAP_TAG_BYTES crypto_aead_xchacha20poly1305_ietf_ABYTES
#define PV_WRAPPED_VMK_BYTES (PV_WRAP_KEY_BYTES + PV_WRAP_TAG_BYTES)
#define PV_BODY_KEY_BYTES crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define PV_BODY_TAG_BYTES crypto_aead_xchacha20poly1305_ietf_ABYTES
#define PV_SALT_BYTES crypto_pwhash_SALTBYTES
#define PV_RECOVERY_KEY_BYTES 32U
#define PV_RECOVERY_CHECKSUM_BYTES 5U
#define PV_RECOVERY_TEXT_MAX 128U
#define PV_ARENA_CAPACITY PV_MAX_PLAINTEXT

#define PV_RECORD_DELETED 0x01U
#define PV_RECORD_FAVORITE 0x02U
#define PV_FIELD_SECRET 0x01U

#define PV_MAX_TITLE 1024U
#define PV_MAX_USERNAME 4096U
#define PV_MAX_PASSWORD 65536U
#define PV_MAX_URL 8192U
#define PV_MAX_NOTES 262144U
#define PV_MAX_TAG 256U
#define PV_MAX_FIELD_NAME 256U
#define PV_MAX_FIELD_VALUE 65536U
#define PV_MAX_COLLECTION_ITEMS 64U

typedef struct pv_arena {
    uint8_t *base;
    size_t capacity;
    size_t used;
    bool readonly;
} pv_arena;

typedef struct pv_slice {
    uint8_t *data;
    size_t len;
} pv_slice;

typedef struct pv_custom_field {
    pv_slice name;
    pv_slice value;
    uint32_t flags;
} pv_custom_field;

typedef struct pv_record {
    uint8_t id[PV_RECORD_ID_BYTES];
    uint64_t revision;
    int64_t created_ms;
    int64_t updated_ms;
    uint32_t flags;
    pv_slice title;
    pv_slice username;
    pv_slice password;
    pv_slice notes;
    pv_slice *urls;
    size_t url_count;
    pv_slice *tags;
    size_t tag_count;
    pv_custom_field *fields;
    size_t field_count;
} pv_record;

typedef struct pv_vault {
    pv_arena arena;
    uint8_t vault_id[PV_VAULT_ID_BYTES];
    uint8_t device_id[PV_DEVICE_ID_BYTES];
    uint64_t generation;
    int64_t created_ms;
    int64_t updated_ms;
    pv_record *records;
    size_t record_count;
    size_t record_capacity;
    uint8_t *vmk;
    uint8_t source_hash[crypto_generichash_BYTES];
    bool dirty;
    char path[PATH_MAX];
} pv_vault;

typedef struct pv_keyslot_password {
    uint64_t opslimit;
    uint64_t memlimit;
    uint8_t salt[PV_SALT_BYTES];
    uint8_t nonce[PV_WRAP_NONCE_BYTES];
    uint8_t wrapped_vmk[PV_WRAPPED_VMK_BYTES];
} pv_keyslot_password;

typedef struct pv_keyslot_recovery {
    uint8_t nonce[PV_WRAP_NONCE_BYTES];
    uint8_t wrapped_vmk[PV_WRAPPED_VMK_BYTES];
} pv_keyslot_recovery;

typedef struct pv_file_header {
    uint8_t magic[PV_MAGIC_LEN];
    uint16_t major;
    uint16_t minor;
    uint32_t header_len;
    uint32_t flags;
    uint8_t vault_id[PV_VAULT_ID_BYTES];
    uint16_t kdf_id;
    uint16_t wrap_aead_id;
    uint16_t body_aead_id;
    uint16_t slot_count;
    pv_keyslot_password password_slot;
    pv_keyslot_recovery recovery_slot;
    uint8_t body_nonce[PV_WRAP_NONCE_BYTES];
    uint64_t body_ciphertext_len;
} pv_file_header;

typedef struct pv_config {
    char vault_path[PATH_MAX];
    unsigned clipboard_ttl;
    unsigned session_ttl;
    unsigned backup_retention;
    bool picker_rofi;
} pv_config;

pv_status pv_arena_init(pv_arena *arena, size_t capacity);
void *pv_arena_alloc(pv_arena *arena, size_t size, size_t alignment);
pv_status pv_arena_copy(pv_arena *arena, pv_slice *out, const void *data, size_t len, size_t max_len);
pv_status pv_arena_set_readonly(pv_arena *arena);
pv_status pv_arena_set_readwrite(pv_arena *arena);
void pv_arena_reset(pv_arena *arena);
void pv_arena_destroy(pv_arena *arena);

pv_status pv_model_init(pv_vault *vault, const char *path);
void pv_model_destroy(pv_vault *vault);
pv_status pv_model_add_record(pv_vault *vault, const pv_record *source, pv_record **out);
pv_record *pv_model_find(pv_vault *vault, const char *query, size_t *matches);
pv_record *pv_model_find_id(pv_vault *vault, const uint8_t id[PV_RECORD_ID_BYTES]);
pv_status pv_model_delete(pv_vault *vault, pv_record *record);
pv_status pv_model_clone(pv_vault *destination, const pv_vault *source);
pv_status pv_model_validate_record(const pv_record *record);

pv_status pv_cbor_encode(const pv_vault *vault, pv_buffer *output);
pv_status pv_cbor_decode(const uint8_t *input, size_t input_len, pv_vault *vault);
void pv_buffer_secure_free(pv_buffer *buffer);

pv_status pv_crypto_create_header(
    pv_file_header *header,
    const uint8_t *password,
    size_t password_len,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    const uint8_t vmk[PV_WRAP_KEY_BYTES]
);
pv_status pv_crypto_unlock_password(
    const pv_file_header *header,
    const uint8_t *password,
    size_t password_len,
    uint8_t vmk[PV_WRAP_KEY_BYTES]
);
pv_status pv_crypto_unlock_recovery(
    const pv_file_header *header,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    uint8_t vmk[PV_WRAP_KEY_BYTES]
);
pv_status pv_crypto_rewrap_password(
    pv_file_header *header,
    const uint8_t *new_password,
    size_t new_password_len,
    const uint8_t vmk[PV_WRAP_KEY_BYTES]
);
pv_status pv_crypto_rewrap_recovery(
    pv_file_header *header,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    const uint8_t vmk[PV_WRAP_KEY_BYTES]
);
pv_status pv_crypto_encrypt_body(
    pv_file_header *header,
    const uint8_t vmk[PV_WRAP_KEY_BYTES],
    const uint8_t *plaintext,
    size_t plaintext_len,
    pv_buffer *ciphertext
);
pv_status pv_crypto_decrypt_body(
    const pv_file_header *header,
    const uint8_t vmk[PV_WRAP_KEY_BYTES],
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    pv_buffer *plaintext
);

pv_status pv_header_encode(const pv_file_header *header, uint8_t output[PV_FILE_HEADER_LEN]);
pv_status pv_header_decode(const uint8_t input[PV_FILE_HEADER_LEN], pv_file_header *header);
pv_status pv_store_create(
    const char *path,
    const uint8_t *password,
    size_t password_len,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    pv_vault *vault
);
pv_status pv_store_create_consume(
    const char *path,
    pv_buffer *password,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    pv_vault *vault
);
pv_status pv_store_open_password(
    const char *path,
    const uint8_t *password,
    size_t password_len,
    pv_vault *vault,
    pv_file_header *header
);
pv_status pv_store_open_password_consume(
    const char *path,
    pv_buffer *password,
    pv_vault *vault,
    pv_file_header *header
);
pv_status pv_store_open_recovery(
    const char *path,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    pv_vault *vault,
    pv_file_header *header
);
pv_status pv_store_open_recovery_consume(
    const char *path,
    pv_buffer *recovery_key,
    pv_vault *vault,
    pv_file_header *header
);
pv_status pv_store_save(pv_vault *vault, pv_file_header *header, unsigned backup_retention);
pv_status pv_store_backup(
    const char *vault_path,
    const char *output_path,
    const uint8_t expected_hash[crypto_generichash_BYTES]
);
pv_status pv_store_inspect(
    const char *path,
    pv_file_header *header,
    size_t *ciphertext_len
);
pv_status pv_store_recover_authenticated(
    const char *snapshot_path,
    const char *output_path,
    const uint8_t expected_hash[crypto_generichash_BYTES]
);
pv_status pv_store_restore(
    const char *vault_path,
    const char *backup_path,
    const uint8_t expected_hash[crypto_generichash_BYTES]
);
pv_status pv_store_doctor(const char *path, char *message, size_t message_len);

#ifdef PVAULT_TEST_FAULT_INJECTION
typedef enum pv_store_fault_operation {
    PV_STORE_FAULT_OPEN = 0,
    PV_STORE_FAULT_WRITE,
    PV_STORE_FAULT_FSYNC,
    PV_STORE_FAULT_RENAME,
    PV_STORE_FAULT_CLOSE,
    PV_STORE_FAULT_OPERATION_COUNT
} pv_store_fault_operation;

typedef enum pv_store_fault_point {
    PV_STORE_FAULT_POINT_ATOMIC_TEMP_OPEN = 0,
    PV_STORE_FAULT_POINT_ATOMIC_HEADER_WRITE,
    PV_STORE_FAULT_POINT_ATOMIC_BODY_WRITE,
    PV_STORE_FAULT_POINT_ATOMIC_TEMP_FSYNC,
    PV_STORE_FAULT_POINT_ATOMIC_TEMP_CLOSE,
    PV_STORE_FAULT_POINT_ATOMIC_RENAME,
    PV_STORE_FAULT_POINT_ATOMIC_DIR_OPEN,
    PV_STORE_FAULT_POINT_ATOMIC_DIR_FSYNC,
    PV_STORE_FAULT_POINT_SAVE_READBACK,
    PV_STORE_FAULT_POINT_SNAPSHOT_OPEN,
    PV_STORE_FAULT_POINT_SNAPSHOT_WRITE,
    PV_STORE_FAULT_POINT_SNAPSHOT_FSYNC,
    PV_STORE_FAULT_POINT_SNAPSHOT_PARENT_FSYNC,
    PV_STORE_FAULT_POINT_SNAPSHOT_READBACK,
    PV_STORE_FAULT_POINT_COPY_DEST_OPEN,
    PV_STORE_FAULT_POINT_COPY_WRITE,
    PV_STORE_FAULT_POINT_COPY_FSYNC,
    PV_STORE_FAULT_POINT_COPY_PARENT_FSYNC,
    PV_STORE_FAULT_POINT_AUTOMATIC_BACKUP_COLLISION_FSYNC,
    PV_STORE_FAULT_POINT_PRUNE_UNLINK,
    PV_STORE_FAULT_POINT_PRUNE_AFTER_FIRST_UNLINK,
    PV_STORE_FAULT_POINT_PRUNE_DIR_FSYNC,
    PV_STORE_FAULT_POINT_COUNT
} pv_store_fault_point;

void pv_store_test_fault_reset(void);
void pv_store_test_fault_fail(
    pv_store_fault_operation operation,
    uint64_t call_number,
    int error_number
);
void pv_store_test_fault_short_write(uint64_t call_number, size_t maximum_bytes);
uint64_t pv_store_test_fault_call_count(pv_store_fault_operation operation);
void pv_store_test_fault_point_fail(pv_store_fault_point point, int error_number);
uint64_t pv_store_test_fault_point_hit_count(pv_store_fault_point point);
#endif

pv_status pv_recovery_generate(
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    uint8_t key[PV_RECOVERY_KEY_BYTES],
    char *encoded,
    size_t encoded_len
);
pv_status pv_recovery_encode(
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    const uint8_t key[PV_RECOVERY_KEY_BYTES],
    char *encoded,
    size_t encoded_len
);
pv_status pv_recovery_decode(
    const char *encoded,
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    uint8_t key[PV_RECOVERY_KEY_BYTES]
);
pv_status pv_recovery_write_file(const char *path, const char *encoded, const uint8_t vault_id[PV_VAULT_ID_BYTES]);
pv_status pv_recovery_read_file(const char *path, char *encoded, size_t encoded_len);

pv_status pv_config_load(pv_config *config);
pv_status pv_config_defaults(pv_config *config);

pv_status pv_secure_read_secret(const char *prompt, pv_buffer *secret, bool confirm);
pv_status pv_secure_buffer_alloc(pv_buffer *buffer, size_t length);
pv_status pv_secure_process_hardening(void);
bool pv_master_password_is_acceptable(const uint8_t *password, size_t password_len);
void pv_secure_stack_clear(void);
#ifdef PVAULT_TEST_SECURE_ALLOC_TRACKING
size_t pv_test_secure_alloc_outstanding(void);
#endif

bool pv_size_add(size_t a, size_t b, size_t *out);
bool pv_size_mul(size_t a, size_t b, size_t *out);
int64_t pv_now_ms(void);
void pv_hex_encode(const uint8_t *input, size_t input_len, char *output, size_t output_len);
bool pv_hex_decode(const char *input, uint8_t *output, size_t output_len);
bool pv_slice_equal_cstr(const pv_slice *slice, const char *text, bool ascii_casefold);
bool pv_slice_contains_cstr(const pv_slice *slice, const char *text, bool ascii_casefold);
bool pv_utf8_valid(const uint8_t *data, size_t len);
bool pv_text_sanitize(
    const pv_slice *slice,
    uint8_t *output,
    size_t capacity,
    size_t *output_len
);
void pv_text_fprint(FILE *stream, const pv_slice *slice);

#endif
