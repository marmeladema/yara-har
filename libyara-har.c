#include "libyara-har.h"
#include "mbedtls/base64.h"

#include <yara/error.h>

int yr_har_rules_scan_mem(YR_RULES* rules, const uint8_t* buffer, size_t buffer_size, int flags, YR_CALLBACK_FUNC callback, void* user_data, int timeout) {
	json_error_t json_error;
	memset(&json_error, 0, sizeof(json_error));
	json_t *json = json_loadb(buffer, buffer_size, 0, &json_error);
	if(!json) {
		return -1;
	}
	int ret = yr_har_rules_scan_json(rules, json, flags, callback, user_data, timeout);
	json_decref(json);
	return ret;
}

int yr_har_rules_scan_file(YR_RULES* rules, const char* filename, int flags, YR_CALLBACK_FUNC callback, void* user_data, int timeout) {
	json_error_t json_error;
	memset(&json_error, 0, sizeof(json_error));
	json_t *json = json_load_file(filename, 0, &json_error);
	if(!json) {
		return -1;
	}
	int ret = yr_har_rules_scan_json(rules, json, flags, callback, user_data, timeout);
	json_decref(json);
	return ret;
}

int yr_har_rules_scan_fd(YR_RULES* rules, YR_FILE_DESCRIPTOR fd, int flags, YR_CALLBACK_FUNC callback, void* user_data, int timeout) {
	json_error_t json_error;
	memset(&json_error, 0, sizeof(json_error));
	json_t *json = json_loadfd(fd, 0, &json_error);
	if(!json) {
		return -1;
	}
	int ret = yr_har_rules_scan_json(rules, json, flags, callback, user_data, timeout);
	json_decref(json);
	return ret;
}

struct __user_data {
	YR_CALLBACK_FUNC callback;
	void *user_data;
	void *module_data;
	size_t module_data_size;
};

static int __callback(
	int message,
	void* message_data,
	void* user_data)
{
	struct __user_data *__user_data = (struct __user_data *)user_data;

	YR_MODULE_IMPORT* mi;
	bool show_module_data = false;

	switch(message)
	{

		case CALLBACK_MSG_IMPORT_MODULE:

			mi = (YR_MODULE_IMPORT*) message_data;

			if(strcmp("har_entry", mi->module_name) == 0) {
				mi->module_data = __user_data->module_data;
				mi->module_data_size = __user_data->module_data_size;
				return CALLBACK_CONTINUE;
			}

			return __user_data->callback(message, message_data, __user_data->user_data);

		case CALLBACK_MSG_MODULE_IMPORTED:

			if (show_module_data) {
				YR_OBJECT* object = (YR_OBJECT*) message_data;
				yr_object_print_data(object, 0, 1);
				printf("\n");
			}

			return __user_data->callback(message, message_data, __user_data->user_data);

		default:
			return __user_data->callback(message, message_data, __user_data->user_data);
	}
	abort();
	return CALLBACK_ERROR;
}

static int __scan_text_node(YR_SCANNER *scanner, const json_t *text_node, const char *encoding) {
	if(!text_node) {
		return yr_scanner_scan_mem(scanner, "", 0);
	}

	const char *text_ptr = json_string_value(text_node);
	size_t text_len = json_string_length(text_node);

	if(!text_ptr || !text_len) {
		return yr_scanner_scan_mem(scanner, "", 0);
	}

	const char *decoded_ptr = text_ptr;
	size_t decoded_len = text_len;

	if(encoding) {
		if(strcmp(encoding, "base64") == 0) {
			decoded_ptr = malloc(text_len);
			decoded_len = text_len;

			if(!decoded_ptr) {
				return ERROR_INSUFFICIENT_MEMORY;
			}

			if(mbedtls_base64_decode((unsigned char *)decoded_ptr, decoded_len, &decoded_len, text_ptr, text_len) != 0) {
				free((void *)decoded_ptr);
				decoded_ptr = text_ptr;
				decoded_len = text_len;
			}
		}
	}

	int ret = yr_scanner_scan_mem(scanner, decoded_ptr, decoded_len);

	if(text_ptr != decoded_ptr) {
		free((void *)decoded_ptr);
	}

	return ret;
}

int yr_har_rules_scan_json(YR_RULES* rules, json_t *json, int flags, YR_CALLBACK_FUNC callback, void* user_data, int timeout) {
	YR_SCANNER *scanner = NULL;
	int ret;

	ret = yr_scanner_create(rules, &scanner);
	if(ret != 0) {
		return ret;
	}

	struct __user_data __user_data = {
		.callback = callback,
		.user_data = user_data,
		.module_data = NULL,
		.module_data_size = 0,
	};

	yr_scanner_set_callback(scanner, __callback, &__user_data);

	yr_scanner_set_timeout(scanner, timeout);

	yr_scanner_set_flags(scanner, flags);

	json_t *log_node = json_object_get(json, "log");
	json_t *entries_node = NULL; 
	if(log_node) {
		entries_node = json_object_get(log_node, "entries");
	}
	ret = 0;
	if(entries_node && json_is_array(entries_node)) {
		size_t index;
		json_t *entry_node, *text_node, *encoding_node;
		const char *data;
		json_array_foreach(entries_node, index, entry_node) {
			__user_data.module_data = (void *)entry_node;
			__user_data.module_data_size = 0;

			json_t *request_node = json_object_get(entry_node, "request");
			json_t *postData_node = json_object_get(request_node, "postData");
			encoding_node = json_object_get(postData_node, "encoding");
			text_node = json_object_get(postData_node, "text");

			ret = __scan_text_node(scanner, text_node, json_string_value(encoding_node));
			if(ret != 0) {
				break;
			}

			json_t *response_node = json_object_get(entry_node, "response");
			json_t *content_node = json_object_get(response_node, "content");
			encoding_node = json_object_get(content_node, "encoding");
			text_node = json_object_get(content_node, "text");

			ret = __scan_text_node(scanner, text_node, json_string_value(encoding_node));
			if(ret) {
				break;
			}
		}
	}

	yr_scanner_destroy(scanner);
	return ret;
}
