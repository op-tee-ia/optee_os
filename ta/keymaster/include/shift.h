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


#ifndef ANDROID_OPTEE_SHIFT_H
#define ANDROID_OPTEE_SHIFT_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#define BITS_IN_BYTE 8

/* Right shift of number stored as big endian
 * Short means that max bits to shift is 8
 */
void TA_short_be_rshift(uint8_t *data,
			const uint32_t data_l,
			const uint32_t shift);

#endif/*ANDROID_OPTEE_SHIFT_H*/
