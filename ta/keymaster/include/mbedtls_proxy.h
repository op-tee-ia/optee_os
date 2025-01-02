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

#ifndef MBEDTLS_PROXY_H_
#define MBEDTLS_PROXY_H_

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "generator.h"
#include <mbedtls/pk.h>

#define CMD_ASN1_DECODE 0
#define CMD_ASN1_ENCODE_PUBKEY 1
#define CMD_EC_SIGN_ENCODE 2
#define CMD_EC_SIGN_DECODE 3
#define CMD_ASN1_GEN_ROOT_RSA_CERT 4
#define CMD_ASN1_GEN_ROOT_EC_CERT 5
#define CMD_ASN1_GEN_ATT_RSA_CERT 6
#define CMD_ASN1_GEN_ATT_EC_CERT 7
#define CMD_ASN1_GEN_ATT_EXTENSION 8

#define K_MAX_CHALLENGE_SIZE_V2 64
#define K_P256_AFFINE_POINT_SIZE 32

keymaster_error_t mbedTLS_decode_pkcs8(keymaster_blob_t key_data,
				       TEE_Attribute **attrs,
				       uint32_t *attrs_count,
				       const keymaster_algorithm_t algorithm,
				       uint32_t *key_size,
				       uint64_t *rsa_public_exponent,
				       bool *is_ed25519);


keymaster_error_t mbedTLS_decode_raw(keymaster_blob_t key_data,
				     TEE_Attribute **attrs,
				     uint32_t *attrs_count,
				     const keymaster_algorithm_t algorithm,
				     uint32_t *key_size,
				     uint64_t *rsa_public_exponent,
				     bool is_ed25519);

keymaster_error_t mbedTLS_encode_key(keymaster_blob_t *export_data,
                                     const uint32_t type,
                                     const TEE_ObjectHandle *obj_h);

/*
 * Here, we generate an X509 v3 cert using SHA-256 for the message digest.
 * The validity of the cert will be 2 years from the current time.
 * Since the TEE only provides relative time, we need to get the absolute time
 * from the REE (number of seconds since epoch) in order to calculate the
 * proper date string to provide to the MBEDTLS x509 APIs. This isn't fully
 * secure, but this function is only used for development and testing.
 * Platforms should define CFG_ATTESTATION_PROVISIONING and invoke the
 * KM_SET_ATTESTATION_KEY and KM_APPEND_ATTESTATION_CERT_CHAIN commands to
 * send a verified cert (chain) to secure persistent storage during
 * provisioning!
 */
TEE_Result mbedTLS_gen_root_cert_rsa(TEE_ObjectHandle root_rsa_key,
				      keymaster_blob_t *root_cert);

TEE_Result mbedTLS_gen_self_signed_cert_rsa(const keymaster_key_param_set_t *input_set,
				     TEE_ObjectHandle root_rsa_key, keymaster_blob_t *root_cert,
				     uint64_t not_before_val, uint64_t not_after_val);

TEE_Result mbedTLS_gen_root_cert_ecc(TEE_ObjectHandle ecc_root_key,
				     keymaster_blob_t *ecc_root_cert);

TEE_Result mbedTLS_gen_self_signed_cert_ecc(const keymaster_key_param_set_t *input_set,
				     TEE_ObjectHandle ecc_root_key, keymaster_blob_t *ecc_root_cert,
				     uint64_t not_before_val, uint64_t not_after_val);

TEE_Result mbedTLS_gen_attest_key_cert(TEE_ObjectHandle root_key,
				       TEE_ObjectHandle attest_key,
				       keymaster_algorithm_t alg,
				       unsigned int key_usage,
				       keymaster_cert_chain_t *cert_chain,
				       keymaster_blob_t *attest_ext);

TEE_Result mbedTLS_gen_attest_key_cert_with_rootkey(
				       const keymaster_key_param_set_t *input_set,
				       TEE_ObjectHandle root_key,
				       TEE_ObjectHandle attest_key,
				       keymaster_algorithm_t root_alg,
				       keymaster_algorithm_t alg,
				       unsigned int key_usage,
				       keymaster_cert_chain_t *cert_chain,
				       keymaster_blob_t *attest_ext,
				       keymaster_blob_t *cert_issuer,
				       uint64_t not_before_val, uint64_t not_after_val);

keymaster_error_t mbedTLS_encode_ec_sign(uint8_t *out, uint32_t *out_l);

keymaster_error_t mbedTLS_decode_ec_sign(keymaster_blob_t *sig,
					 uint32_t key_size);

keymaster_error_t mbedTLS_decode_ecc_subpubkey(uint8_t *input,
					uint32_t len,
					TEE_Attribute* attrs,
					uint32_t key_size,
					bool is_curve25519);

keymaster_error_t mbedTLS_get_ecdsa256_key_from_cert(const keymaster_blob_t *km_cert,
						     uint8_t *x_coord,
						     size_t x_length,
						     uint8_t *y_coord,
						     size_t y_length);

keymaster_error_t mbedTLS_gen_ecdsa_p256_key_pair(mbedtls_pk_context *context,
                                                  uint8_t *cdi_attest,
                                                  size_t cdi_attest_size);

keymaster_error_t mbedTLS_export_ecdsa_p256_public_key(mbedtls_pk_context *context,
                                                       uint8_t *x_coord,
                                                       size_t x_length,
                                                       uint8_t *y_coord,
                                                       size_t y_length);

keymaster_error_t mbedTLS_sign_data_with_ecdsa_p256(mbedtls_pk_context *context,
                                                    uint8_t *signed_data,
                                                    size_t signed_data_length,
                                                    uint8_t *signature,
                                                    size_t signature_buffer_length,
                                                    size_t *actual_signature_length);

TEE_Result TA_gen_attest_cert(TEE_ObjectHandle attestedKey,
                              keymaster_key_param_set_t *attest_params,
                              keymaster_key_characteristics_t *key_chr,
                              bool includeUniqueID,
                              keymaster_algorithm_t root_alg,
                              keymaster_algorithm_t alg,
                              keymaster_cert_chain_t *cert_chain);

TEE_Result TA_gen_attest_cert_with_rootkey(TEE_ObjectHandle root_key,
                              const keymaster_key_param_set_t *root_params,
                              TEE_ObjectHandle attested_key,
                              keymaster_key_param_set_t *attested_params,
                              keymaster_key_characteristics_t *key_chr,
                              bool includeUniqueID,
                              keymaster_algorithm_t root_alg,
                              keymaster_algorithm_t alg,
                              keymaster_cert_chain_t *cert_chain,
                              keymaster_blob_t *cert_issuer,
                              uint64_t not_before_val, uint64_t not_after_val);

#endif /* MBEDTLS_PROXY_H_ */
