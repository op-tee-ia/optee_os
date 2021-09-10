/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018 Intel Corporation
 */
#ifndef __TRACE_CONTROL_BY_SERVICE_H
#define __TRACE_CONTROL_BY_SERVICE_H

/* If line is commented out you won't get traces from that
 * module/service/component
 */
//#define TRACE_SERV_MMU
#define TRACE_SERV_THREAD
#define TRACE_SERV_ENTRY_EXIT
#define TRACE_SERV_TA_LOADING

#endif // __TRACE_CONTROL_BY_SERVICE_H
