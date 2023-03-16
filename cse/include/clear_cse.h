#ifndef __FDO_CLEAR_CSE_H__
#define __FDO_CLEAR_CSE_H__

#include "fdo_cse.h"
#include <linux/mei.h>
#include <metee.h>

#define FDO_APP_ID 1
#define OVH_FILE_ID 0
#define DS_FILE_ID 1

TEESTATUS heci_init(TEEHANDLE *cl);
void heci_deinit(TEEHANDLE *cl);
TEESTATUS fdo_heci_clear_file(TEEHANDLE *cl, uint32_t file_id, FDO_STATUS
                *fdo_status);
int main(void);

#endif /* __FDO_CLEAR_CSE_H__ */