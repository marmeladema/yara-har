#include <stdlib.h>

#include <libyara-har.h>

static const char *expected_rule = NULL;
static size_t matched_count = 0;

static int handle_message(
    int message,
    YR_RULE* rule,
    void* data)
{
	if(message == CALLBACK_MSG_RULE_MATCHING) {
		printf("matched: %s\n", rule->identifier);
		if(!expected_rule || strcmp(expected_rule, rule->identifier) == 0) {
			matched_count ++;
		}
	}
	return CALLBACK_CONTINUE;
}

static void compiler_callback(
	int error_level,
	const char* file_name,
	int line_number,
	const char* message,
	void* user_data)
{
	const char *prefix = NULL;

	switch(error_level) {
	case YARA_ERROR_LEVEL_WARNING:
		prefix = "WARN";
	break;
	default:
		prefix = "ERROR";
	}

	fprintf(stderr, "[%s] YARA compiler error: %s at %s:%d\n", prefix, message, file_name, line_number);
}

static int scanner_callback(
	int message,
	void* message_data,
	void* user_data)
{
	switch(message)
	{
		case CALLBACK_MSG_RULE_MATCHING:
		case CALLBACK_MSG_RULE_NOT_MATCHING:
			return handle_message(message, (YR_RULE*) message_data, user_data);
		default:
			break;
	}

	return CALLBACK_CONTINUE;
}

int main(int argc, char *argv[]) {
	if(argc < 3 || argc > 4) {
		exit(1);
	}
	const char *rulepath = argv[1];
	const char *filepath = argv[2];
	YR_COMPILER *compiler = NULL;
	FILE *stream = NULL;
	YR_RULES *rules = NULL;
	int ret;

	if(argc == 4) {
		expected_rule = argv[3];
	}

	yr_initialize();

	ret = yr_compiler_create(&compiler);
	if(ret != ERROR_SUCCESS) {
		fprintf(stderr, "Could not create compiler (%d)\n", ret);
		yr_finalize();
		return EXIT_FAILURE;
	}
	yr_compiler_set_callback(compiler, compiler_callback, NULL);

	stream = fopen(rulepath, "r");
	if(!stream) {
		perror("fopen");
		yr_compiler_destroy(compiler);
		yr_finalize();
		return EXIT_FAILURE;

	}

	ret = yr_compiler_add_file(compiler, stream, NULL, rulepath);
	if(ret != 0) {
		fprintf(stderr, "Could not parse rule file %s\n", rulepath);
		fclose(stream);
		yr_compiler_destroy(compiler);
		yr_finalize();
		return EXIT_FAILURE;
	}

	yr_compiler_get_rules(compiler, &rules);

	yr_har_rules_scan_file(rules, filepath, 0, scanner_callback, NULL, 0);

	yr_rules_destroy(rules);

	yr_compiler_destroy(compiler);

	yr_finalize();

	if(expected_rule && !matched_count) {
		fprintf(stderr, "Rule %s did not matched\n", expected_rule);
		return EXIT_FAILURE;
	}

	return 0;
}
