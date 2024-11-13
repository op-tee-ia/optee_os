// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2023 Intel Corporation
 */

#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <malloc.h>

#include "dice/dice.h"
#include "dice/ops.h"
#include "dice/utils.h"
#include "dice/cose.h"

DiceResult DiceSignCertificate(void *context,
                               mbedtls_pk_context *subject_key_context,
                               mbedtls_pk_context *authority_key_context,
                               const DiceInputValues *input_values,
                               size_t certificate_buffer_size,
                               uint8_t *certificate,
                               size_t *certificate_actual_size)
{
    DiceResult error = kDiceResultOk;
    uint8_t *uds_x_coordinate = NULL;
    uint8_t *uds_y_coordinate = NULL;
    cbor_item_t *uds_public_key_map = NULL;
    uint8_t *x_coordinate = NULL;
    uint8_t *y_coordinate = NULL;
    cbor_item_t *cose_public_key_map = NULL;
    uint8_t *cose_public_key = NULL;
    size_t cose_public_key_size = 0;
    uint8_t *signature = NULL;
    size_t signature_buffer_length = 0;
    size_t actual_signature_length = 0;
    size_t serialize_size = 0;
    bool result = false;
    cbor_item_t *dice_chain_entry_payload = NULL;
    uint8_t *dice_chain_entry_payload_data = NULL;
    size_t dice_chain_entry_payload_size = 0;
    uint8_t key_usage[1] = { 0x20 };
    uint8_t mode_byte = 0;
    cbor_item_t *cose_algorithm_parameter = NULL;
    uint8_t *cose_algorithm_parameter_data = NULL;
    size_t cose_algorithm_parameter_size = 0;
    cbor_item_t *dice_chain_entry_input = NULL;
    uint8_t *dice_chain_entry_input_data = NULL;
    size_t dice_chain_entry_input_size = 0;
    cbor_item_t *dice_chain_entry = NULL;
    uint8_t *signed_data = NULL;
    size_t signed_data_length = 0;
    cbor_item_t *dice_cert_chain = NULL;
    uint8_t *dice_cert_chain_data = NULL;
    size_t dice_cert_chain_size = 0;
    cbor_item_t *config_desc = NULL;
    uint8_t *config_desc_data = NULL;
    size_t config_desc_size = 0;

    DMSG("%s %d", __func__, __LINE__);

    if (subject_key_context == NULL || authority_key_context == NULL || input_values == NULL ||
        certificate_buffer_size == 0 || certificate == NULL || certificate_actual_size == NULL) {
        return kDiceResultInvalidInput;
    }

    if (input_values->config_type != kDiceConfigTypeDescriptor &&
        input_values->config_type != kDiceConfigTypeInline) {
        return kDiceResultInvalidInput;
    }
 
    uds_x_coordinate = malloc(DICE_PRIVATE_KEY_SEED_SIZE);
    uds_y_coordinate = malloc(DICE_PRIVATE_KEY_SEED_SIZE);
    x_coordinate = malloc(DICE_PRIVATE_KEY_SEED_SIZE);
    y_coordinate = malloc(DICE_PRIVATE_KEY_SEED_SIZE);
    signature_buffer_length = MBEDTLS_ECDSA_MAX_LEN;
    signature = malloc(signature_buffer_length);
    if (!uds_x_coordinate || !uds_y_coordinate || !x_coordinate || !y_coordinate || !signature) {
        EMSG("Failed to allocate memory for uds_x_coordinate, uds_y_coordinate, x_coordinate, y_coordinate or signature");
        error = kDiceResultPlatformError;
        goto exit;
    }
    memset(uds_x_coordinate, 0, DICE_PRIVATE_KEY_SEED_SIZE);
    memset(uds_y_coordinate, 0, DICE_PRIVATE_KEY_SEED_SIZE);
    memset(x_coordinate, 0, DICE_PRIVATE_KEY_SEED_SIZE);
    memset(y_coordinate, 0, DICE_PRIVATE_KEY_SEED_SIZE);
    memset(signature, 0, signature_buffer_length);

    error = DiceExportPublicKey(authority_key_context,
                                uds_x_coordinate,
                                DICE_PRIVATE_KEY_SEED_SIZE,
                                uds_y_coordinate,
                                DICE_PRIVATE_KEY_SEED_SIZE);
    if (error != kDiceResultOk) {
        EMSG("Export ECDSA P256 public key failed");
        goto exit;
    }

    uds_public_key_map = cbor_new_definite_map(5);
    if (!uds_public_key_map) {
        EMSG("Failed to allocate memory for uds_public_key_map");
        error = kDiceResultPlatformError;
        goto exit;
    }
    result = cbor_map_add(uds_public_key_map,
                          (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(KEY_TYPE)),
                                              .value = cbor_move(cbor_build_uint8(EC2))});
    result &= cbor_map_add(uds_public_key_map,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(ALGORITHM)),
                                               .value = cbor_move(cbor_build_negint8(abs(ES256) - 1))});
    result &= cbor_map_add(uds_public_key_map,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_negint8(abs(CURVE) - 1)),
                                               .value = cbor_move(cbor_build_uint8(P256))});
    result &= cbor_map_add(uds_public_key_map,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_negint8(abs(PUBKEY_X) - 1)),
                                               .value = cbor_move(cbor_build_bytestring(uds_x_coordinate, DICE_PRIVATE_KEY_SEED_SIZE))});
    result &= cbor_map_add(uds_public_key_map,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_negint8(abs(PUBKEY_Y) - 1)),
                                               .value = cbor_move(cbor_build_bytestring(uds_y_coordinate, DICE_PRIVATE_KEY_SEED_SIZE))});
    if (!result) {
        EMSG("Add ECDSA P256 parameters to cbor map failed, result=%x", result);
        error = kDiceResultPlatformError;
        goto exit;
    }

    error = DiceExportPublicKey(subject_key_context,
                                x_coordinate,
                                DICE_PRIVATE_KEY_SEED_SIZE,
                                y_coordinate,
                                DICE_PRIVATE_KEY_SEED_SIZE);
    if (error != kDiceResultOk) {
        EMSG("Export ECDSA P256 public key failed");
        goto exit;
    }

    cose_public_key_map = cbor_new_definite_map(5);
    if (!cose_public_key_map) {
        EMSG("Failed to allocate memory for cose_public_key_map");
        error = kDiceResultPlatformError;
        goto exit;
    }
    result = cbor_map_add(cose_public_key_map,
                          (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(KEY_TYPE)),
                                              .value = cbor_move(cbor_build_uint8(EC2))});
    result &= cbor_map_add(cose_public_key_map,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(ALGORITHM)),
                                               .value = cbor_move(cbor_build_negint8(abs(ES256) - 1))});
    result &= cbor_map_add(cose_public_key_map,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_negint8(abs(CURVE) - 1)),
                                               .value = cbor_move(cbor_build_uint8(P256))});
    result &= cbor_map_add(cose_public_key_map,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_negint8(abs(PUBKEY_X) - 1)),
                                               .value = cbor_move(cbor_build_bytestring(x_coordinate, DICE_PRIVATE_KEY_SEED_SIZE))});
    result &= cbor_map_add(cose_public_key_map,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_negint8(abs(PUBKEY_Y) - 1)),
                                               .value = cbor_move(cbor_build_bytestring(y_coordinate, DICE_PRIVATE_KEY_SEED_SIZE))});
    if (!result) {
        EMSG("Add ECDSA P256 parameters to cbor map failed, result=%x", result);
        error = kDiceResultPlatformError;
        goto exit;
    }

    serialize_size = cbor_serialize_alloc(cose_public_key_map, &cose_public_key, &cose_public_key_size);

    // Count the number of entries.
    uint32_t map_pairs = 7;

    if (input_values->code_descriptor_size > 0) {
        map_pairs += 1;
    }
    if (input_values->config_type == kDiceConfigTypeDescriptor) {
        map_pairs += 2;
    } else {
        map_pairs += 1;
    }
    if (input_values->authority_descriptor_size > 0) {
        map_pairs += 1;
    }

    dice_chain_entry_payload = cbor_new_definite_map(map_pairs);
    if (!dice_chain_entry_payload) {
        EMSG("Failed to allocate memory for dice_chain_entry_payload");
        error = kDiceResultPlatformError;
        goto exit;
    }
    result = cbor_map_add(dice_chain_entry_payload,
                          (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(1)),
                                              .value = cbor_move(cbor_build_string("Issue"))});
    result &= cbor_map_add(dice_chain_entry_payload,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(2)),
                                               .value = cbor_move(cbor_build_string("Subject"))});
    result &= cbor_map_add(dice_chain_entry_payload,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670545) - 1)),
                                               .value = cbor_move(cbor_build_bytestring(input_values->code_hash, DICE_HASH_SIZE))});
    if (input_values->code_descriptor_size > 0) {
        result &= cbor_map_add(dice_chain_entry_payload,
                               (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670546) - 1)),
                                                   .value = cbor_move(cbor_build_bytestring(input_values->code_descriptor, input_values->code_descriptor_size))});
    }
    if (input_values->config_type == kDiceConfigTypeDescriptor) {
        uint8_t config_descriptor_hash[DICE_HASH_SIZE];
        DiceResult result1 = DiceHash(context, input_values->config_descriptor,
                                     input_values->config_descriptor_size,
                                     config_descriptor_hash);
        if (result1 != kDiceResultOk) {
            goto exit;
        }
        result &= cbor_map_add(dice_chain_entry_payload,
                               (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670548) - 1)),
                                                   .value = cbor_move(cbor_build_bytestring(input_values->config_descriptor, input_values->config_descriptor_size))});
        result &= cbor_map_add(dice_chain_entry_payload,
                               (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670547) - 1)),
                                                   .value = cbor_move(cbor_build_bytestring(config_descriptor_hash, DICE_HASH_SIZE))});
    } else if (input_values->config_type == kDiceConfigTypeInline) {
        config_desc = cbor_new_definite_map(3);
        bool result2 = false;
	result2 = cbor_map_add(config_desc,
                               (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-70002) - 1)),
                                                   .value = cbor_move(cbor_build_string("Dice"))});
        result2 &= cbor_map_add(config_desc,
                                (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-70003) - 1)),
                                                    .value = cbor_move(cbor_build_string("It's version 4"))});
        result2 &= cbor_map_add(config_desc,
                                (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-70004) - 1)),
                                                    .value = cbor_move(cbor_new_null())});
        if (!result2) {
            EMSG("Build configuration descriptor cbor map failed, result=%x", result);
            error = kDiceResultPlatformError;
            goto exit;
        }
        serialize_size = cbor_serialize_alloc(config_desc, &config_desc_data, &config_desc_size);

        result &= cbor_map_add(dice_chain_entry_payload,
                               (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670548) - 1)),
                                                   .value = cbor_move(cbor_build_bytestring(config_desc_data, config_desc_size))});
    }
    result &= cbor_map_add(dice_chain_entry_payload,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670549) - 1)),
                                               .value = cbor_move(cbor_build_bytestring(input_values->authority_hash, DICE_HASH_SIZE))});
    if (input_values->authority_descriptor_size > 0) {
        result &= cbor_map_add(dice_chain_entry_payload,
                               (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670550) - 1)),
                                                   .value = cbor_move(cbor_build_bytestring(input_values->authority_descriptor, input_values->authority_descriptor_size))});
    }
    mode_byte = input_values->mode;
    result &= cbor_map_add(dice_chain_entry_payload,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670551) - 1)),
                                               .value = cbor_move(cbor_build_bytestring(&mode_byte, 1))});
    result &= cbor_map_add(dice_chain_entry_payload,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670552) - 1)),
                                               .value = cbor_move(cbor_build_bytestring(cose_public_key, cose_public_key_size))});
    result &= cbor_map_add(dice_chain_entry_payload,
                           (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670553) - 1)),
                                               .value = cbor_move(cbor_build_bytestring(key_usage, 1))});
    if (!result) {
        EMSG("Build dice chain entry payload cbor map failed, result=%x", result);
        error = kDiceResultPlatformError;
        goto exit;
    }

    serialize_size = cbor_serialize_alloc(dice_chain_entry_payload,
                                          &dice_chain_entry_payload_data,
                                          &dice_chain_entry_payload_size);

    dice_chain_entry_input = cbor_new_definite_array(4);
    if (!dice_chain_entry_input) {
        EMSG("Failed to allocate memory for dice_chain_entry_input");
        error = kDiceResultPlatformError;
        goto exit;
    }
    result = cbor_array_push(dice_chain_entry_input, cbor_move(cbor_build_string("Signature1")));

    cose_algorithm_parameter = cbor_new_definite_map(1);
    if (!cose_algorithm_parameter) {
        MSG("Failed to allocate memory for cose_algorithm_parameter");
        error = kDiceResultPlatformError;
        goto exit;
    }
    cbor_map_add(cose_algorithm_parameter,
                 (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(LABEL_ALGORITHM)),
                                     .value = cbor_move(cbor_build_negint8(abs(ES256) - 1))});
    serialize_size = cbor_serialize_alloc(cose_algorithm_parameter, &cose_algorithm_parameter_data, &cose_algorithm_parameter_size);

    result &= cbor_array_push(dice_chain_entry_input,
                              cbor_move(cbor_build_bytestring(cose_algorithm_parameter_data, cose_algorithm_parameter_size)));
    /*Load an empty byte string */
    result &= cbor_array_push(dice_chain_entry_input,
                              cbor_move(cbor_new_definite_bytestring()));
    result &= cbor_array_push(dice_chain_entry_input,
                              cbor_move(cbor_build_bytestring(dice_chain_entry_payload_data, dice_chain_entry_payload_size)));

    if (!result) {
        EMSG("Build dice chain entry input cbor array failed, result=%x", result);
        error = kDiceResultPlatformError;
        goto exit;
    }
    serialize_size = cbor_serialize_alloc(dice_chain_entry_input,
                                          &dice_chain_entry_input_data,
                                          &dice_chain_entry_input_size);

    dice_chain_entry = cbor_new_definite_array(4);
    if (!dice_chain_entry) {
        EMSG("Failed to allocate memory for dice_chain_entry");
        error = kDiceResultPlatformError;
        goto exit;
    }
    result = cbor_array_push(dice_chain_entry,
                             cbor_move(cbor_build_bytestring(cose_algorithm_parameter_data, cose_algorithm_parameter_size)));
    result &= cbor_array_push(dice_chain_entry, cbor_move(cbor_new_definite_map(0)));
    result &= cbor_array_push(dice_chain_entry,
                              cbor_move(cbor_build_bytestring(dice_chain_entry_payload_data, dice_chain_entry_payload_size)));

    signed_data = malloc(dice_chain_entry_input_size);
    if (!signed_data) {
        EMSG("Failed to allocate memory for signed_data");
        error = kDiceResultPlatformError;
        goto exit;
    }
    memset(signed_data, 0, dice_chain_entry_input_size);
    signed_data_length = dice_chain_entry_input_size;
    memmove(signed_data, dice_chain_entry_input_data, signed_data_length);

    error = DiceSignDataWithEcdsaP256(authority_key_context,
                                      signed_data,
                                      signed_data_length,
                                      signature,
                                      signature_buffer_length,
                                      &actual_signature_length);
    if (error != kDiceResultOk) {
        EMSG("Sign data with ECDSA P256 keypair failed");
        goto exit;
    }

    DMSG("actual_signature_length %ld", actual_signature_length);
    result &= cbor_array_push(dice_chain_entry,
                              cbor_move(cbor_build_bytestring(signature, actual_signature_length)));
    if (!result) {
        EMSG("Build dice chain entry cbor array failed, result=%x", result);
        error = kDiceResultPlatformError;
        goto exit;
    }

    dice_cert_chain = cbor_new_definite_array(2);
    if (!dice_cert_chain) {
        EMSG("Failed to allocate memory for dice_cert_chain");
        error = kDiceResultPlatformError;
        goto exit;
    }
    result = cbor_array_push(dice_cert_chain, cbor_move(uds_public_key_map));
    result &= cbor_array_push(dice_cert_chain, cbor_move(dice_chain_entry));
    if (!result) {
        EMSG("Build dice cert chain cbor array failed, result=%x", result);
        error = kDiceResultPlatformError;
        goto exit;
    }

    serialize_size = cbor_serialize_alloc(dice_cert_chain,
                                          &dice_cert_chain_data,
                                          &dice_cert_chain_size);
    if (dice_cert_chain_size < certificate_buffer_size) {
        memmove(certificate, dice_cert_chain_data, dice_cert_chain_size);
        *certificate_actual_size = dice_cert_chain_size;
    }
exit:
    if (uds_x_coordinate)
        free(uds_x_coordinate);
    if (uds_y_coordinate)
        free(uds_y_coordinate);
    if (uds_public_key_map)
        cbor_decref(&uds_public_key_map);

    if (x_coordinate)
        free(x_coordinate);
    if (y_coordinate)
        free(y_coordinate);

    if (cose_public_key)
       free(cose_public_key);
    if (cose_public_key_map)
        cbor_decref(&cose_public_key_map);

    if (signature)
        free(signature);

    if (config_desc_data)
       free(config_desc_data);
    if (config_desc)
        cbor_decref(&config_desc);

    if (dice_chain_entry_payload_data)
        free(dice_chain_entry_payload_data);
    if (dice_chain_entry_payload)
        cbor_decref(&dice_chain_entry_payload);

    if (cose_algorithm_parameter_data)
        free(cose_algorithm_parameter_data);
    if (cose_algorithm_parameter)
        cbor_decref(&cose_algorithm_parameter);

    if (dice_chain_entry_input_data)
        free(dice_chain_entry_input_data);
    if (dice_chain_entry_input)
        cbor_decref(&dice_chain_entry_input);

    if (signed_data)
       free(signed_data);

    if (dice_chain_entry)
       cbor_decref(&dice_chain_entry);

    if (dice_cert_chain_data)
       free(dice_cert_chain_data);
    if (dice_cert_chain)
       cbor_decref(&dice_cert_chain);
    return error;
}

