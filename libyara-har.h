#ifndef LIBYARA_HAR_H
#define LIBYARA_HAR_H

#include <yara.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

int yr_har_rules_scan_mem(YR_RULES* rules, const uint8_t* buffer, size_t buffer_size, int flags, YR_CALLBACK_FUNC callback, void* user_data, int timeout);
int yr_har_rules_scan_file(YR_RULES* rules, const char* filename, int flags, YR_CALLBACK_FUNC callback, void* user_data, int timeout);
int yr_har_rules_scan_fd(YR_RULES* rules, YR_FILE_DESCRIPTOR fd, int flags, YR_CALLBACK_FUNC callback, void* user_data, int timeout);
int yr_har_rules_scan_json(YR_RULES* rules, json_t *json, int flags, YR_CALLBACK_FUNC callback, void* user_data, int timeout);

#ifdef __cplusplus
}
#endif

#endif // LIBYARA_HAR_H