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

#include "shift.h"

void TA_short_be_rshift(uint8_t *data,
			const uint32_t data_l,
			const uint32_t shift)
{
	uint8_t prev = 0;
	uint8_t next = 0;
	uint32_t wild_shift = BITS_IN_BYTE - shift;

	if (shift > BITS_IN_BYTE || shift <= 0)
		return;
	for (uint32_t i = 0; i < data_l; i++) {
		next = data[i] << wild_shift;
		data[i] >>= shift;
		data[i] |= prev;
		prev = next;
	}
}
