/*
 *
 * Copyright (C) 2017 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <tee_internal_api.h>
#include "failure_record.h"

#define MAX_FAILURE_RECORDS 32
static uint8_t FailureRecordsID[] = {0xe1U, 0x2fU, 0x67U, 0x3aU};
typedef struct {
	uint32_t size;
	failure_record_t records[MAX_FAILURE_RECORDS];
} failure_record_table_t;

static failure_record_table_t failureRecordTable;


TEE_Result InitFailureRecords(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle FailureRecordsObj = TEE_HANDLE_NULL;
	uint32_t actual_read = 0;
	uint32_t failure_records_buf_size = sizeof(failureRecordTable);
	uint8_t failure_records_buf[failure_records_buf_size];

	memset(&failureRecordTable, 0, sizeof(failureRecordTable));

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, FailureRecordsID,
			sizeof(FailureRecordsID), TEE_DATA_FLAG_ACCESS_READ, &FailureRecordsObj);
	if (res != TEE_SUCCESS) {
		if (res == TEE_ERROR_ITEM_NOT_FOUND) {
			DMSG("Failure records not found, create a new object.");
			res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					FailureRecordsID, sizeof(FailureRecordsID),
					TEE_DATA_FLAG_ACCESS_WRITE,
					TEE_HANDLE_NULL, NULL, 0U, &FailureRecordsObj);
			if (res != TEE_SUCCESS) {
				EMSG("Failed to create failure records object, res=%x", res);
				goto error_1;
			}
			DMSG("Create failure records successfully");
			res = TEE_WriteObjectData(FailureRecordsObj, (void *)&failureRecordTable,
					sizeof(failureRecordTable));
			if (res != TEE_SUCCESS) {
				EMSG("Failed to write failure records, res=%x", res);
			} else {
				DMSG("Write failure records successfully");
			}
			goto error_2;
		}
		EMSG("Failed to open failure records, res=%X", res);
		goto error_1;
	} else {
		DMSG("Open failure records succeddfully");
	}

	res = TEE_ReadObjectData(FailureRecordsObj, failure_records_buf,
			failure_records_buf_size, &actual_read);
	if (res != TEE_SUCCESS || actual_read != failure_records_buf_size) {
		EMSG("Failed to read failure records, res=%x", res);
		TEE_CloseObject(FailureRecordsObj);
		goto error_1;
	} else {
		memcpy(&failureRecordTable, failure_records_buf, failure_records_buf_size);
		DMSG("Read failure records successfully");
	}
error_2:
	(res == TEE_SUCCESS) ?
		TEE_CloseObject(FailureRecordsObj) :
		TEE_CloseAndDeletePersistentObject(FailureRecordsObj);

error_1:
	return res;
}


void GetFailureRecord(secure_id_t user_id, failure_record_t *record)
{
	uint32_t i;
	failure_record_t *records = failureRecordTable.records;
	uint32_t tableSize = failureRecordTable.size;

	for (i = 0; i < tableSize; i++) {
		if (records[i].secure_user_id == user_id) {
			*record = records[i];
			return;
		}
	}

	record->secure_user_id = user_id;
	record->failure_counter = 0;
	record->last_checked_timestamp = 0;
}


TEE_Result WriteFailureRecord(const failure_record_t *record)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle FailureRecordsObj = TEE_HANDLE_NULL;
	uint32_t i;
	failure_record_t *records = failureRecordTable.records;

	int min_idx = 0;
	uint64_t min_timestamp = ~0ULL;

	for (i = 0; i < failureRecordTable.size; i++) {
		if (records[i].secure_user_id == record->secure_user_id) {
			break;
		}

		if (records[i].last_checked_timestamp <= min_timestamp) {
			min_timestamp = records[i].last_checked_timestamp;
			min_idx = i;
		}
	}

	if (i >= MAX_FAILURE_RECORDS) {
		// replace the oldest element if all records are in use
		i = min_idx;
	} else if (i == failureRecordTable.size) {
		failureRecordTable.size++;
	}

	records[i] = *record;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, FailureRecordsID,
			sizeof(FailureRecordsID), TEE_DATA_FLAG_ACCESS_WRITE, &FailureRecordsObj);
	if (res != TEE_SUCCESS) {
		if (res == TEE_ERROR_ITEM_NOT_FOUND) {
			DMSG("Failure records not found, create a new object.");
			res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					FailureRecordsID, sizeof(FailureRecordsID),
					TEE_DATA_FLAG_ACCESS_WRITE,
					TEE_HANDLE_NULL, NULL, 0U, &FailureRecordsObj);
			if (res != TEE_SUCCESS) {
				EMSG("Failed to create failure records object, res=%x", res);
				goto error_1;
			}
		} else {
			EMSG("Failed to open failure records, res=%X", res);
			goto error_1;
		}
	} else {
		DMSG("Open failure records successfully");
	}
	res = TEE_WriteObjectData(FailureRecordsObj, (void *)&failureRecordTable,
			sizeof(failureRecordTable));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to write failure records, res=%x", res);
		goto error_2;
	} else {
		DMSG("Write failure records successfully");
	}
error_2:
	(res == TEE_SUCCESS) ?
			TEE_CloseObject(FailureRecordsObj) :
			TEE_CloseAndDeletePersistentObject(FailureRecordsObj);

error_1:
	return res;
}


TEE_Result IncrementFailureRecord(failure_record_t *record, uint64_t timestamp)
{
	TEE_Result res = TEE_SUCCESS;
	record->failure_counter++;
	record->last_checked_timestamp = timestamp;

	res = WriteFailureRecord(record);
	if (res != TEE_SUCCESS) {
		EMSG("WriteFailureRecord failed, res=%x", res);
	}
	return res;
}


TEE_Result ClearFailureRecord(secure_id_t user_id)
{
	TEE_Result res = TEE_SUCCESS;
	failure_record_t record;

	record.secure_user_id = user_id;
	record.last_checked_timestamp = 0;
	record.failure_counter = 0;

	res = WriteFailureRecord(&record);
	if (res != TEE_SUCCESS) {
		EMSG("WriteFailureRecord failed, res=%x", res);
	}
	return res;
}


uint32_t ComputeRetryTimeout(const failure_record_t *record)
{
	static const int FAILURE_TIMEOUT_MS = 30000;
	static const int DAY_IN_MS = 1000 * 60 * 60 * 24;

	uint32_t failure_counter = record->failure_counter;

	if (failure_counter == 0) {
		return 0;
	}

	if (failure_counter > 0 && failure_counter <= 10) {
		if (failure_counter % 5 == 0) {
			return FAILURE_TIMEOUT_MS;
		} else {
			return 0;
		}
	} else if (failure_counter < 30) {
		return FAILURE_TIMEOUT_MS;
	} else if (failure_counter < 140) {
		return FAILURE_TIMEOUT_MS << ((failure_counter - 30)/10);
	}
	return DAY_IN_MS;
}


uint64_t GetTimestamp(void)
{
	TEE_Time secure_time;
	TEE_GetSystemTime(&secure_time);
	return (uint64_t)secure_time.seconds*1000 + secure_time.millis;
}


bool ThrottleRequest(failure_record_t *record, uint64_t timestamp,
		uint32_t *response_timeout)
{
	TEE_Result res = TEE_SUCCESS;
	uint64_t last_checked = record->last_checked_timestamp;
	uint32_t timeout = ComputeRetryTimeout(record);

	if (timeout > 0) {
		// we have a pending timeout
		if (timestamp < last_checked + timeout &&
				timestamp > last_checked) {
			// attempt before timeout expired, return remaining time
			*response_timeout = timeout - (timestamp-last_checked);
			return true;
		} else if (timestamp <= last_checked) {
			// device was rebooted or timer reset, don't count as
			// new failure but reset timeout
			record->last_checked_timestamp = timestamp;
			res = WriteFailureRecord(record);
			if (res != TEE_SUCCESS) {
				EMSG("WriteFailureRecord failed, res=%x", res);
			}
			*response_timeout = timeout;
			return true;
		}
	}

	return false;
}
