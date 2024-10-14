/*
 * Copyright (C) 2017 GlobalLogic
 *
 * INTEL CONFIDENTIAL
 * Copyright (C) 2024 Intel Corporation
 *
 * This software and the related documents are Intel copyrighted materials,
 * and your use of them is governed by the express license under which
 * they were provided to you ("License"). Unless the License provides otherwise,
 * you may not use, modify, copy, publish, distribute, disclose or transmit
 * this software or the related documents without Intel's prior written permission.
 * This software and the related documents are provided as is,
 * with no express or implied warranties,
 * other than those that are expressly stated in the License.
 */


#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <common.h>

#define TA_UUID TA_KEYMASTER_UUID

#define TA_FLAGS	(TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR | \
			TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION | \
			TA_FLAG_INSTANCE_KEEP_ALIVE)
#define TA_STACK_SIZE	(64 * 1024)
#define TA_DATA_SIZE	(1024 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
	{ "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
		"Keymaster TA" }, \
	{ "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }

#endif /*USER_TA_HEADER_DEFINES_H*/
