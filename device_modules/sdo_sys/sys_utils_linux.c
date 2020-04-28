/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "safe_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sdo_sys_utils.h"
#include "sdo_sys.h"

/* Allow only alphanumeric file name either shell or python script*/
static bool is_valid_filename(const char *fname)
{
	bool ret = false;
	int strcmp_result = -1;
	uint8_t i = 0;
	static const char * const whitelisted[] = {"sh", "py"};
	char *substring = NULL, *t1 = NULL;
	char filenme_woextension[FILE_NAME_LEN] = {0};

	if (fname == NULL)
		goto end;

	if (strncpy_s(filenme_woextension, FILE_NAME_LEN, fname,
		      strnlen_s(fname, FILE_NAME_LEN))) {
		goto end;
	}

	if (strlastchar_s(filenme_woextension, 10, '.', &substring)) {
		goto end;
	}

	*substring = '\0'; // Nullify the pointer

	// Now the array is as follow
	//  "TEST FILENAME" "ext"

	/* check the whitelisted extension type*/
	substring++;
	for (i = 0; i < (sizeof(whitelisted) / sizeof(whitelisted[0])); i++) {
		strcmp_s(substring, strnlen_s(substring, 3), whitelisted[i],
			 &strcmp_result);
		if (!strcmp_result) {
			/* extension matched  */
			ret = true;
			break;
		}
	}
	if (ret != true) {
		goto end;
	}
	ret = false;
	t1 = filenme_woextension;

	/* check for only alphanumeric no special char except _ */
	while (*t1 != '\0') {
		if ((*t1 >= 'a' && *t1 <= 'z') || (*t1 >= 'A' && *t1 <= 'Z') ||
		    (*t1 >= '0' && *t1 <= '9') || (*t1 == '_')) {
			t1++;
		} else {
			goto end;
		}
	}

	ret = true;
end:
	return ret;
}

void *ModuleAlloc(int size)
{
	void *buf = malloc(size);
	if (!buf) {
		printf("sdoAlloc failed to allocate\n");
		goto end;
	}

	if (memset_s(buf, size, 0) != 0) {
		printf("Memset Failed\n");
		free(buf);
		buf = NULL;
		goto end;
	}

end:
	return buf;
}

bool process_data(sdoSysModMsg type, uint8_t *data, uint32_t dataLen,
		  char *File_name)
{
	int ret = false;
	FILE *fp = NULL;
	int error_code = 0;
	char *new_filename = NULL;
	int new_filename_sz = 0;

	if (!File_name || !data || !dataLen) {
#ifdef DEBUG_LOGS
		printf("NULL params in Process_data");
#endif
		goto end;
	}
#ifdef DEBUG_LOGS
	printf("sdo_sys: Filename : %s :Size: %x\n", File_name, dataLen);
#endif

	// For writing to a file
	if (type == SDO_SYS_MOD_MSG_WRITE) {

		fp = fopen(File_name, "a");
		if (!fp) {
#ifdef DEBUG_LOGS
			printf("Could not open file(path): %s\n", File_name);
#endif
			goto end;
		}

		if (fwrite(data, sizeof(char), dataLen, fp) !=
		    (size_t)dataLen) {
#ifdef DEBUG_LOGS
			printf("Error in fwrite");
#endif
			goto end;
		}
		ret = true;
		goto end;
	}

	// For Exec call
	if (type == SDO_SYS_MOD_MSG_EXEC) {

		/*
		 * Proper error check for system call
		 * Allow only filename (no absolute path for secure env)
		 */
		if (is_valid_filename((const char *)File_name) == false) {
			goto end;
		}

		// Executable permission for current user for the file
		if (chmod(File_name, 0700)) {
			goto end;
		}
		new_filename_sz = strnlen_s(File_name, FILE_NAME_LEN) +
				  3; // 3 for prefix "./"
		if (new_filename_sz <= 3) {
			goto end;
		}

		new_filename = (char *)malloc(new_filename_sz);
		if (new_filename == NULL) {
			goto end;
		}
		if (strncpy_s(new_filename, new_filename_sz, "./", 3)) {
			goto end;
		}

		if (strncat_s(new_filename, new_filename_sz, File_name,
			      strnlen_s(File_name, FILE_NAME_LEN))) {
			goto end;
		}
		error_code = system(new_filename);
		if (error_code == -1)
			goto end;

		ret = true;
	}

end:
	if (fp) {
		if (fclose(fp) == EOF) {
#ifdef DEBUG_LOGS
			printf("Fclose failed\n");
#endif
		}
	}
	if (new_filename) {
		free(new_filename);
	}
	return ret;
}

bool delete_old_file(const char *File_name)
{
	FILE *file = NULL;
	bool ret = false;

	file = fopen(File_name, "w");
	if (file) {
		if (!fclose(file)) {
			ret = true;
		}
	} else {
		ret = true;
	}
	return ret;
}
