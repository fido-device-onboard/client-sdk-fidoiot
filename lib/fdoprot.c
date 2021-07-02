/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of FDO protocol spec. The APIs in this file realize
 * various aspects of FDO protcol.
 */

#include "fdoCrypto.h"
#include "util.h"
#include "fdoprot.h"
#include "load_credentials.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "safe_lib.h"
#include "snprintf_s.h"

#ifndef asizeof
#define asizeof(x) (sizeof(x) / sizeof(x)[0])
#endif

#define DI_ID_TO_STATE_FN(id) (id - FDO_STATE_DI_APP_START)
#define TO1_ID_TO_STATE_FN(id) (id - FDO_STATE_T01_SND_HELLO_FDO)
#define TO2_ID_TO_STATE_FN(id) (id - FDO_STATE_T02_SND_HELLO_DEVICE)

typedef int (*state_func)(fdo_prot_t *ps);

/*
 * State functions for DI
 */
static state_func di_state_fn[] = {
    msg10, // DI.AppStart
    msg11, // DI.SetCredentials
    msg12, // DI.SetHMAC
    msg13, // DI.Done
};
/*
 * State functions for TO1
 */
static state_func to1_state_fn[] = {
    msg30, // TO1.HelloRV
    msg31, // TO1.HelloRVAck
    msg32, // TO1.ProveToRV
    msg33, // TO1.RVRedirect
};

/*
 * State functions for TO2
 */
static state_func to2_state_fn[] = {
    msg60, // TO2.HelloDevice
    msg61, // TO2.ProveOVHdr
    msg62, // TO2.GetOVNextEntry
    msg63, // TO2.OVNextEntry
    msg64, // TO2.Provedevice
    msg65, // TO2.SetupDevice
    msg66, // TO2.DeviceServiceInfoReady
    msg67, // TO2.OwnerServiceInfoReady
    msg68, // TO2.DeviceServiceInfo
    msg69, // TO2.OwnerServiceInfo
    msg70, // TO2.Done
    msg71, // TO2.Done2
};

/**
 * ps_free() - free all the protocol state
 * ps stores the message data which gets used in the next messages, so,
 * this function needs to be called in:
 * a. Error handling to free all state data
 * b. When the state machine is completed successfully
 */
static void ps_free(fdo_prot_t *ps)
{
	if (ps->nonce_to2proveov) {
		fdo_byte_array_free(ps->nonce_to2proveov);
		ps->nonce_to2proveov = NULL;
	}
	if (ps->nonce_to2proveov_rcv) {
		fdo_byte_array_free(ps->nonce_to2proveov_rcv);
		ps->nonce_to2proveov_rcv = NULL;
	}
	if (ps->new_ov_hdr_hmac) {
		fdo_hash_free(ps->new_ov_hdr_hmac);
		ps->new_ov_hdr_hmac = NULL;
	}
	if (ps->nonce_to2provedv) {
		fdo_byte_array_free(ps->nonce_to2provedv);
		ps->nonce_to2provedv = NULL;
	}
	if (ps->nonce_to2setupdv_rcv) {
		fdo_byte_array_free(ps->nonce_to2setupdv_rcv);
		ps->nonce_to2setupdv_rcv = NULL;
	}
	if (ps->dsi_info) {
		fdo_free(ps->dsi_info);
		ps->dsi_info = NULL;
	}
}

/**
 * Allocate memory for resources required to run DI protocol and set state
 * variables to init state.
 *
 * @param ps
 *        Pointer to the database containtain all protocol state variables.
 * @param dev_cred
 *        Pointer to the database containtain Device credentials.
 * @return ret
 *         None.
 */
void fdo_prot_di_init(fdo_prot_t *ps, fdo_dev_cred_t *dev_cred)
{
	ps->state = FDO_STATE_DI_INIT;
	ps->dev_cred = dev_cred;
	ps->success = false;
}

/**
 * Manage the protocol state machine
 *
 * @param ps
 *        Pointer to the database containtain all protocol state variables.
 * @return
 *        "true" in case of success. "false" if failed.
 */
bool fdo_process_states(fdo_prot_t *ps)
{
	bool status = false;
	int prev_state = 0;
	state_func state_fn = NULL;

	for (;;) {

		/*
		 * Retaining the older logic of state machine. For the states to
		 * process, the message processor has to be update ps->state. In
		 * case the state is not changed and no error has been reported,
		 * it means that the data read from network is pending, so, we
		 * read data and come back here for the same message processing
		 */
		prev_state = ps->state;

		switch (ps->state) {
		// DI states
		case FDO_STATE_DI_APP_START:
		case FDO_STATE_DI_SET_CREDENTIALS:
		case FDO_STATE_DI_SET_HMAC:
		case FDO_STATE_DI_DONE:
			state_fn = di_state_fn[DI_ID_TO_STATE_FN(ps->state)];
			break;
	
		// TO1 states
		case FDO_STATE_T01_SND_HELLO_FDO:
		case FDO_STATE_TO1_RCV_HELLO_FDOACK:
		case FDO_STATE_TO1_SND_PROVE_TO_FDO:
		case FDO_STATE_TO1_RCV_FDO_REDIRECT:
			state_fn = to1_state_fn[TO1_ID_TO_STATE_FN(ps->state)];
			break;

		// TO2 states
		case FDO_STATE_T02_SND_HELLO_DEVICE:
		case FDO_STATE_TO2_RCV_PROVE_OVHDR:
		case FDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY:
		case FDO_STATE_T02_RCV_OP_NEXT_ENTRY:
		case FDO_STATE_TO2_SND_PROVE_DEVICE:
		case FDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO:
		case FDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO:
		case FDO_STATE_TO2_RCV_SETUP_DEVICE:
		case FDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO:
		case FDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO:
		case FDO_STATE_TO2_SND_DONE:
		case FDO_STATE_TO2_RCV_DONE_2:
			state_fn = to2_state_fn[TO2_ID_TO_STATE_FN(ps->state)];
			break;

		case FDO_STATE_ERROR:
		case FDO_STATE_DONE:
		default:
			break;
		}

		/*
		 * FIXME: ps->state cannot start with a junk state. It is for
		 * unit test to pass
		 */
		if (!state_fn) {
			break;
		}

		if (ps->state != FDO_STATE_DONE && state_fn && state_fn(ps)) {
			char err_msg[64];

			(void)snprintf_s_i(err_msg, sizeof(err_msg),
					   "msg%d: message parse error",
					   ps->state);
			ps->state = FDO_STATE_ERROR;
			// clear the block contents to write error message
			fdo_block_reset(&ps->fdow.b);
			if (!fdow_encoder_init(&ps->fdow)) {
				LOG(LOG_ERROR, "Failed to initilize FDOW encoder\n");
				break;
			}
			fdo_send_error_message(&ps->fdow, MESSAGE_BODY_ERROR,
					       ps->state, err_msg, sizeof(err_msg));
			ps_free(ps);
			break;
		}

		/* If we reached with msg71 as ps->state, we are done */
		if (prev_state == FDO_STATE_TO2_RCV_DONE_2 &&
		    ps->state == FDO_STATE_DONE) {
			ps_free(ps);
		}

		/* Break for reading network data */
		if (prev_state == ps->state) {
			status = true;
			break;
		}
	}

	return status;
}

/**
 * Allocate memory for resources required to run TO1 protocol and set state
 * variables to init state.
 *
 * @param ps
 *        Pointer to the database containtain all protocol state variables.
 * @param dev_cred
 *        Pointer to the database containtain Device credentials.
 * @return ret
 *         0 on success and -1 on failure
 */
int32_t fdo_prot_to1_init(fdo_prot_t *ps, fdo_dev_cred_t *dev_cred)
{
	if (!ps || !dev_cred || !dev_cred->owner_blk) {
		return -1;
	}
	ps->state = FDO_STATE_TO1_INIT;
	ps->g2 = dev_cred->owner_blk->guid;
	ps->dev_cred = dev_cred;
	ps->success = false;
	return 0;
}

/**
 * Allocate memory for resources required to run TO2 protocol and set state
 * variables to init state.
 *
 * @param ps
 *        Pointer to the database containtain all protocol state variables.
 * @param si
 *        Pointer to device service info database.
 * @param dev_cred
 *        Pointer to the database containtain Device credentials.
 * @param module_list
 *        Global Module List Head Pointer.
 * @return
 *        true if success, false otherwise.
 *
 */
bool fdo_prot_to2_init(fdo_prot_t *ps, fdo_service_info_t *si,
		       fdo_dev_cred_t *dev_cred,
		       fdo_sdk_service_info_module_list_t *module_list)
{
	ps->state = FDO_STATE_T02_INIT;
	ps->key_encoding = FDO_OWNER_ATTEST_PK_ENC;

	ps->success = false;
	ps->service_info = si;
	ps->dev_cred = dev_cred;
	ps->g2 = dev_cred->owner_blk->guid;
	ps->round_trip_count = 0;

	/* Initialize svinfo related data */
	if (module_list) {
		ps->sv_info_mod_list_head = module_list;
		ps->dsi_info = fdo_alloc(sizeof(fdo_sv_info_dsi_info_t));
		if (!ps->dsi_info) {
			return false;
		}

		ps->dsi_info->list_dsi = ps->sv_info_mod_list_head;
		ps->dsi_info->module_dsi_index = 0;

		/* Execute Sv_info type=START */
		if (!fdo_mod_exec_sv_infotype(ps->sv_info_mod_list_head,
					      FDO_SI_START)) {
			LOG(LOG_ERROR,
			    "Sv_info: One or more module's START failed\n");
			fdo_free(ps->dsi_info);
			return false;
		}
	} else
		LOG(LOG_DEBUG,
		    "Sv_info: no modules are registered to the FDO!\n");

	//	LOG(LOG_DEBUG, "Key Exchange Mode: %s\n", ps->kx->bytes);
	//	LOG(LOG_DEBUG, "Cipher Suite: %s\n", ps->cs->bytes);

	return true;
}

/**
 * Check total number of round trips in TO2 exceeded the limit.
 *
 * @param ps
 *        Pointer to the database containtain all protocol state variables.
 * @return
 *        false if roundtrip limit exceeded, true otherwise.
 */
bool fdo_check_to2_round_trips(fdo_prot_t *ps)
{
	if (ps->round_trip_count > MAX_TO2_ROUND_TRIPS) {
		LOG(LOG_ERROR, "Exceeded maximum number of TO2 rounds\n");
		char err_msg[64];
		(void)snprintf_s_i(err_msg, sizeof(err_msg),
				   "Exceeded max number of rounds",
				   ps->state);
		fdo_send_error_message(&ps->fdow, INTERNAL_SERVER_ERROR,
				       ps->state,
				       "Exceeded max number of rounds", sizeof(err_msg));
		ps->state = FDO_STATE_ERROR;
		return false;
	}
	ps->round_trip_count++;
	return true;
}

/**
 * Check if we have received a REST message.
 *
 * @param fdor
 *        Pointer to received JSON packet.
 * @param fdow
 *        Pointer to outgoing JSON packet which has been composed by Protocol
 * APIs(DI_Run/TO1_Run/TO2_Run).
 * @param prot_name
 *        Name of Protocol(DI/TO1/TO2).
 * @param statep
 *        Current state of Protocol state machine.
 * @return
 *        true in case of new message received. false if no message to read.
 */
bool fdo_prot_rcv_msg(fdor_t *fdor, fdow_t *fdow, char *prot_name, int *statep)
{
	(void)fdow; /* Unused */
	(void)statep;

	if (!fdor->have_block) {
		/*
		* The way this method is used to maintain the state,
		* it's not an error scenario if there's no block to read.
		* have_block false means that the response has not yet come since the
		* requet has not been sent.
		* TO-DO : Investigate for a better approach than this.
		*/
		return false;
	}

	LOG(LOG_DEBUG, "%s: Received message type %" PRIu32 " : %zu bytes\n",
	    prot_name, fdor->msg_type, fdor->b.block_size);

	return true;
}

/**
 * TO-DO : Update to pass EMErrorUuid if needed in future.
 * 
 * Internal API
 */
void fdo_send_error_message(fdow_t *fdow, int ecode, int msgnum,
			    char *errmsg, size_t errmsg_sz)
{
	LOG(LOG_ERROR, "Sending Error Message\n");

	fdow_next_block(fdow, FDO_TYPE_ERROR);
	if (!fdow_start_array(fdow, 5)) {
		LOG(LOG_ERROR, "Error Message: Failed to write start array\n");
		return;
	}
	if (!fdow_signed_int(fdow, ecode)) {
		LOG(LOG_ERROR, "Error Message: Failed to write EMErrorCode\n");
		return;
	}
	if (!fdow_signed_int(fdow, msgnum)) {
		LOG(LOG_ERROR, "Error Message: Failed to write EMPrevMsgID\n");
		return;
	}
	if (!fdow_text_string(fdow, errmsg , errmsg_sz)) {
		LOG(LOG_ERROR, "Error Message: Failed to write EMErrorStr");
		return;
	}
	if (!fdow_signed_int(fdow, (int) time(NULL))) {
		LOG(LOG_ERROR, "Error Message: Failed to write EMErrorTs\n");
		return;
	}
	// writing 0 as correlationId. May be updated in future.
	if (!fdow_signed_int(fdow, 0)) {
		LOG(LOG_ERROR, "Error Message: Failed to write EMErrorUuid\n");
		return;
	}
	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "Error Message: Failed to write end array\n");
		return;
	}
}

#if 0
/**
 * Receive the error message
 * @param fdor - pointer to the input buffer
 * @param ecode - error code
 * @param msgnum - pointer to the FDO message number
 * @param errmsg - pointer to the error message string
 * @param errmsg_sz - size of error message string
 */
void fdo_receive_error_message(fdor_t *fdor, int *ecode, int *msgnum,
			       char *errmsg, int errmsg_sz)
{
	/* Called after FDONext_block... */
	/* FDONext_block(fdor, &mtype, &maj_ver, &min_ver); */
	if (!fdor_begin_object(fdor)) {
		LOG(LOG_ERROR, "Begin Object not found.\n");
		goto fail;
	}
	*ecode = 0;
	*msgnum = 255;
	if (strncpy_s(errmsg, errmsg_sz, "error message parse failed",
		      errmsg_sz) != 0) {
		LOG(LOG_ERROR, "strcpy() failed!\n");
	}
	if (!fdo_read_expected_tag(fdor, "ec")) {
		goto fail;
	}
	*ecode = fdo_read_uint(fdor);
	if (!fdo_read_expected_tag(fdor, "emsg")) {
		goto fail;
	}
	*msgnum = fdo_read_uint(fdor);
	if (!fdo_read_expected_tag(fdor, "em")) {
		goto fail;
	}
	if (!fdo_read_string(fdor, errmsg, errmsg_sz)) {
		LOG(LOG_ERROR, "%s(): fdo_read_string() "
		    "returned NULL!\n", __func__);
		goto fail;
	}
	if (!fdor_end_object(fdor)) {
		LOG(LOG_ERROR, "End Object not found.\n");
		goto fail;
	}
fail:
	fdor_flush(fdor);
}
#endif
