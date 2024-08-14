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
#ifndef OPTEE_COSE_H
#define OPTEE_COSE_H

#include "cbor.h"

typedef enum {
        LABEL_ALGORITHM = 1,
        LABEL_KEY_ID_ = 4,
        LABEL_IV = 5,
        LABEL_COSE_KEY = -1,
} label_t;

typedef enum {
        AES_GCM_256 = 3,
        HMAC_256 = 5,
        ES256 = -7,  // ECDSA with SHA-256
        EDDSA = -8,
        ECDH_ES_HKDF_256 = -25,
        ES384 = -35,  // ECDSA with SHA-384
} cosekey_algorithm_t;

typedef enum {
        P256 = 1,
        P384 = 2,
        X25519 = 4,
        ED25519 = 6,
} cosekey_curve_t;

typedef enum {
        OCTET_KEY_PAIR = 1,
        EC2 = 2,
        SYMMETRIC_KEY = 4,
} cosekey_type_t;

typedef enum {
        SIGN = 1,
        VERIFY = 2,
        ENCRYPT = 3,
        DECRYPT = 4,
} cosekey_ops_t;

typedef enum {
        KEY_TYPE = 1,
        KEY_ID = 2,
        ALGORITHM = 3,
        KEY_OPS = 4,
        CURVE = -1,
        PUBKEY_X = -2,
        PUBKEY_Y = -3,
        PRIVATE_KEY = -4,
        TEST_KEY = -70000  // Application-defined
} cosekey_label_t;

#endif /*OPTEE_COSE_H*/
