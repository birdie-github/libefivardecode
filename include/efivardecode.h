// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef EFIVARDECODE_H
#define EFIVARDECODE_H
#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
# ifdef EVD_BUILD
#  define EVD_API __declspec(dllexport)
# else
#  define EVD_API __declspec(dllimport)
# endif
#else
# define EVD_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct evd_registry evd_registry;
typedef struct evd_result evd_result;
typedef struct evd_node evd_node;
typedef struct {
    const char *name, *guid;
    uint32_t attributes;
    const uint8_t *payload;
    size_t size;
} evd_input;
// Return 1 for found, 0 for missing, -1 for unavailable. The payload must
// remain readable until evd_decode returns. Supply only the target payload.
typedef int (*evd_lookup)(void *, const char *guid, const char *name,
                          const uint8_t **payload, size_t *size);
typedef enum { EVD_OK, EVD_UNKNOWN, EVD_MALFORMED } evd_status;
typedef enum { EVD_RECORD, EVD_LIST, EVD_UINT, EVD_TEXT, EVD_GUID,
               EVD_BYTES, EVD_REFERENCE } evd_kind;
// NULL selects default directories. An empty user_dir disables overrides.
// Error strings are thread-local and valid until the next open/decode call.
EVD_API evd_registry *evd_registry_open(const char *system_dir, const char *user_dir);
EVD_API void evd_registry_free(evd_registry *);
EVD_API const char *evd_error(void);
EVD_API evd_result *evd_decode(const evd_registry *, const evd_input *, evd_lookup, void *);
EVD_API void evd_result_free(evd_result *);
EVD_API evd_status evd_result_status(const evd_result *);
EVD_API const char *evd_name(const evd_result *);
EVD_API const char *evd_guid(const evd_result *);
// Attribute metadata has zero-length payload spans.
EVD_API const evd_node *evd_attributes(const evd_result *);
EVD_API const evd_node *evd_root(const evd_result *);
// All returned pointers are owned by the result. Offsets index this payload.
EVD_API const uint8_t *evd_payload(const evd_result *, size_t *size);
EVD_API const char *evd_diagnostic(const evd_result *);
EVD_API size_t evd_error_offset(const evd_result *);
EVD_API const char *evd_rule_file(const evd_result *);
EVD_API const char *evd_rule_selector(const evd_result *);
EVD_API const char *evd_source(const evd_result *);
EVD_API int evd_user_rule(const evd_result *);
EVD_API const char *evd_meaning(const evd_result *);
EVD_API evd_kind evd_node_kind(const evd_node *);
EVD_API const char *evd_field(const evd_node *);
EVD_API uint64_t evd_uint(const evd_node *);
EVD_API const char *evd_text(const evd_node *);
EVD_API const char *evd_unit(const evd_node *);
EVD_API size_t evd_offset(const evd_node *);
EVD_API size_t evd_length(const evd_node *);
EVD_API size_t evd_count(const evd_node *);
EVD_API const evd_node *evd_child(const evd_node *, size_t index);
#ifdef __cplusplus
}
#endif
#endif
