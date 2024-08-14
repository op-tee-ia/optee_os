// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// This is an implementation of DiceGenerateCertificate and the crypto
// operations that uses mbedtls. The algorithms used are SHA512, HKDF-SHA512,
// and deterministic ECDSA-P256-SHA512.

#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <malloc.h>

#include "dice/dice.h"
#include "dice/ops.h"
#include "dice/utils.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "crypto/crypto.h"

#define DICE_MAX_CERTIFICATE_SIZE 2048
#define DICE_MAX_EXTENSION_SIZE 2048
#define DICE_MAX_KEY_ID_SIZE 40

/**
 * \brief    The ECP key-pair structure.
 *
 * A generic key-pair that may be used for ECDSA and fixed ECDH, for example.
 *
 * \note    Members are deliberately in the same order as in the
 *          ::mbedtls_ecdsa_context structure.
 */
static DiceResult SetupKeyPair(
    const uint8_t private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    mbedtls_pk_context* context) {
    if (0 !=
        mbedtls_pk_setup(context, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) {
        return kDiceResultPlatformError;
    }
    // Use the |private_key_seed| directly to seed a PRNG which is then in turn
    // used to generate the private key. This implementation uses HMAC_DRBG in a
    // loop with no reduction, like RFC6979.
    DiceResult result = kDiceResultOk;
    mbedtls_hmac_drbg_context rng_context;
    mbedtls_hmac_drbg_init(&rng_context);
    if (0 != mbedtls_hmac_drbg_seed_buf(
                &rng_context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
                private_key_seed, DICE_PRIVATE_KEY_SEED_SIZE)) {
        result = kDiceResultPlatformError;
        goto out;
    }
    if (0 != mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                                 mbedtls_pk_ec(*context),
                                 mbedtls_hmac_drbg_random, &rng_context)) {
        result = kDiceResultPlatformError;
        goto out;
    }

out:
    mbedtls_hmac_drbg_free(&rng_context);
    return result;
}

static int JacobianCoordinatesToAffineCoordinates(mbedtls_ecp_group *grp, mbedtls_ecp_point *P)
{
    int ret = 0;
    mbedtls_mpi Z_inv, Z_inv_sq, Z_inv_cu;

    mbedtls_mpi_init(&Z_inv);
    mbedtls_mpi_init(&Z_inv_sq);
    mbedtls_mpi_init(&Z_inv_cu);

    /* Calculate Z^-1 */
    if ((ret = mbedtls_mpi_inv_mod(&Z_inv, &P->Z, &grp->P)) != 0) {
        goto out;
    }

    /* Calculate Z^-2 */
    if ((ret = mbedtls_mpi_mul_mpi(&Z_inv_sq, &Z_inv, &Z_inv)) != 0) {
        goto out;
    }
    if ((ret = mbedtls_mpi_mod_mpi(&Z_inv_sq, &Z_inv_sq, &grp->P)) != 0) {
        goto out;
    }

    /* Calculate Z^-3 */
    if ((ret = mbedtls_mpi_mul_mpi(&Z_inv_cu, &Z_inv_sq, &Z_inv)) != 0) {
        goto out;
    }
    if ((ret = mbedtls_mpi_mod_mpi(&Z_inv_cu, &Z_inv_cu, &grp->P)) != 0) {
        goto out;
    }

    /* Calculate affine X = X * Z^-2 */
    if ((ret = mbedtls_mpi_mul_mpi(&P->X, &P->X, &Z_inv_sq)) != 0) {
        goto out;
    }
    if ((ret = mbedtls_mpi_mod_mpi(&P->X, &P->X, &grp->P)) != 0) {
        goto out;
    }
    /* Calculate affine Y = Y * Z^-3 */
    if ((ret = mbedtls_mpi_mul_mpi(&P->Y, &P->Y, &Z_inv_cu)) != 0) {
        goto out;
    }
    if ((ret = mbedtls_mpi_mod_mpi(&P->Y, &P->Y, &grp->P)) != 0) {
        goto out;
    }

    /* Set Z to 1 */
    mbedtls_mpi_lset(&P->Z, 1);

out:
    mbedtls_mpi_free(&Z_inv);
    mbedtls_mpi_free(&Z_inv_sq);
    mbedtls_mpi_free(&Z_inv_cu);

    return ret;
}

static int MbedtlsMpiWriteBinaryPadded(const mbedtls_mpi *X, uint8_t *buf, size_t buflen)
{
    int ret = 0;
    size_t mpi_size = mbedtls_mpi_size(X); /* Get the size of X in bytes */
    size_t padding_len = 0;

    DMSG("mpi_size %ld", mpi_size);

    if (buflen < mpi_size) {
        /* The buffer is too small to hold the value of X */
        return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    }

    padding_len = buflen - mpi_size;
    memset(buf, 0, padding_len); // Pad the buffer with leading zeros

    /* Write X to the buffer right after the padding */
    if ((ret = mbedtls_mpi_write_binary(X, buf + padding_len, mpi_size)) != 0) {
        return ret;
    }

    return 0;
}

DiceResult DiceExportPublicKey(mbedtls_pk_context *context,
                               uint8_t *x_coord,
                               size_t x_length,
                               uint8_t *y_coord,
                               size_t y_length) {
    DiceResult result = kDiceResultOk;
    mbedtls_ecp_keypair *keypair = NULL;
    int mbedtls_ret = 1;
    bool is_jacobian_coordinate = false;

    if (context == NULL || x_coord == NULL || y_coord == NULL) {
        return kDiceResultInvalidInput;
    }

    if (x_length != DICE_PRIVATE_KEY_SEED_SIZE || y_length != DICE_PRIVATE_KEY_SEED_SIZE) {
        return kDiceResultBufferTooSmall;
    }

    keypair = mbedtls_pk_ec(*context);
    mbedtls_ret = mbedtls_mpi_cmp_int(&keypair->Q.Z, 0);
    if (mbedtls_ret == 0) {
        DMSG("Z coordinate value is zero");
        is_jacobian_coordinate = true;
    }

    mbedtls_ret = mbedtls_mpi_cmp_int(&keypair->Q.Z, 1);
    if (mbedtls_ret == 0) {
        DMSG("Z coordinate value is one");
        is_jacobian_coordinate = true;
    }

    if (is_jacobian_coordinate == false) {
        mbedtls_ret = JacobianCoordinatesToAffineCoordinates(&keypair->grp, &keypair->Q);
        if (mbedtls_ret != 0) {
            EMSG("Convert jacobian coordinates to affine coordinates failed returned %d", mbedtls_ret);
            result = kDiceResultPlatformError;
            goto out;
        }
    }

    mbedtls_ret = MbedtlsMpiWriteBinaryPadded(&keypair->Q.X, x_coord, x_length);
    if (mbedtls_ret != 0) {
        EMSG("MbedtlsMpiWriteBinaryPadded returned %d", mbedtls_ret);
        result = kDiceResultPlatformError;
        goto out;
    }

    mbedtls_ret = MbedtlsMpiWriteBinaryPadded(&keypair->Q.Y, y_coord, y_length);
    if (mbedtls_ret != 0) {
        EMSG("MbedtlsMpiWriteBinaryPadded returned %d", mbedtls_ret);
        result = kDiceResultPlatformError;
        goto out;
    }

out:
    return result;
}

static DiceResult Sha256(uint8_t *data, size_t size, uint8_t *digest, size_t digest_length)
{
    mbedtls_sha256_context context;
    int mbedtls_ret = 1;
    DiceResult result = kDiceResultOk;

    if (data == NULL || digest == NULL) {
        return kDiceResultInvalidInput;
    }
    if (digest_length != DICE_PRIVATE_KEY_SEED_SIZE) {
        return kDiceResultBufferTooSmall;
    }

    mbedtls_sha256_init(&context);
    mbedtls_ret = mbedtls_sha256_starts(&context, 0);
    if (mbedtls_ret != 0) {
        EMSG("mbedtls_sha256_starts returned %d",mbedtls_ret);
        result = kDiceResultPlatformError;
        goto out;
    }
    mbedtls_ret = mbedtls_sha256_update(&context, data, size);
    if (mbedtls_ret != 0) {
        EMSG("mbedtls_sha256_update returned %d", mbedtls_ret);
        result = kDiceResultPlatformError;
        goto out;
    }
    mbedtls_ret = mbedtls_sha256_finish(&context, digest);
    if (mbedtls_ret != 0) {
        EMSG("mbedtls_sha256_finish returned %d", mbedtls_ret);
        result = kDiceResultPlatformError;
        goto out;
    }

out:
    mbedtls_sha256_free(&context);
    return result;
}

/* entropy source */
static int f_rng(void *rng __unused, unsigned char *output, size_t output_len) {
    crypto_rng_read(output, output_len);
    return 0;
}

static DiceResult MbedTLSDecodeECSign(uint8_t *data,
                                      size_t *data_length,
                                      uint32_t key_size) {
    DiceResult ret = kDiceResultPlatformError;
    unsigned char *p = (unsigned char *)data;
    const unsigned char *end = data + *data_length;
    size_t len, slen, rlen;
    mbedtls_mpi r, s;

    /* We need key syze in bytes. */
    key_size = (key_size + 7) / 8;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    if (mbedtls_asn1_get_tag(&p, end, &len,
                             MBEDTLS_ASN1_CONSTRUCTED |
                             MBEDTLS_ASN1_SEQUENCE )) {
        EMSG("Failed to get ASN1 tag");
        goto err;
    }

    if (p + len != end) {
        EMSG("Signature decoding failed");
        goto err;
    }

    if(mbedtls_asn1_get_mpi(&p, end, &r) ||
       mbedtls_asn1_get_mpi(&p, end, &s)) {
        EMSG("Failed to get bignums from integers of ec signature");
        goto err;
    }

    /*
     * R and S are expected to be the same size as key (in bytes).
     * Thise numbers are calculated using pseudo-random values (rfc6979),
     * and sometimes it hapens that one of that values have key_szie-1 lengh
     * byte array representation (513 bits, for example). In that case
     * mbedtls returns actual bytes count to represent this value as byte
     * array. (65 instead of expected 66 for 513-bit values). We can not
     * leave it as is, because libtomcrypt crypto_acipher_ecc_verify(..)
     * routine expects that signature is exactly 2x(key_size) bytes length.
     * Otherwise it triggers TEE_Panic(TEE_ERROR_BAD_PARAMETERS).
     */

    rlen = mbedtls_mpi_size(&r);
    if (rlen > key_size) {
        EMSG("R can not be larger than key");
        goto err;
    }

    rlen = key_size;

    slen = mbedtls_mpi_size(&s);
    if (slen > key_size) {
        EMSG("S can not be larger than key");
        goto err;
    }
    slen = key_size;


    if (mbedtls_mpi_write_binary(&r, data, rlen) ||
        mbedtls_mpi_write_binary(&s, data + rlen, slen)) {
        EMSG("Failed to export bignum data to buffer");
        goto err;
    }

    *data_length = rlen + slen;
    ret = kDiceResultOk;
err:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

DiceResult DiceSignDataWithEcdsaP256(mbedtls_pk_context *context,
                                     uint8_t *signed_data,
                                     size_t signed_data_length,
                                     uint8_t *signature,
                                     size_t signature_buffer_length,
                                     size_t *actual_signature_length)
{
    DiceResult result = kDiceResultOk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    uint8_t *digest = NULL;
    size_t signature_length = 0;
    int mbedtls_ret = 1;
    uint32_t key_size = 256; /* ECDSA P256 key size */

    if (context == NULL || signed_data == NULL ||
        signature == NULL || actual_signature_length == NULL) {
        return kDiceResultInvalidInput;
    }

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ret = mbedtls_ctr_drbg_seed(&ctr_drbg, f_rng, &entropy, NULL, 0);
    if (mbedtls_ret != 0) {
        EMSG("mbedtls_ctr_drbg_seed returned %d", mbedtls_ret);
        result = kDiceResultPlatformError;
        goto out;
    }

    digest = malloc(DICE_PRIVATE_KEY_SEED_SIZE);
    if (!digest) {
         EMSG("Failed to allocate memory for digest");
         result = kDiceResultPlatformError;
         goto out;
    }
    memset(digest, 0, DICE_PRIVATE_KEY_SEED_SIZE);

    /* hash the data using SHA-256 */
    result = Sha256(signed_data,
                    signed_data_length,
                    digest,
                    DICE_PRIVATE_KEY_SEED_SIZE);
    if (result != kDiceResultOk) {
        EMSG("Sha256 operation failed");
        goto out;
    }
    /* sign the hashed data */
    mbedtls_ret = mbedtls_pk_sign(context,
                                  MBEDTLS_MD_SHA256,
                                  digest,
                                  DICE_PRIVATE_KEY_SEED_SIZE,
                                  signature,
                                  signature_buffer_length,
                                  &signature_length,
                                  mbedtls_ctr_drbg_random,
                                  &ctr_drbg);
    if (mbedtls_ret != 0) {
        EMSG("mbedtls_pk_sign returned %d", mbedtls_ret);
        result = kDiceResultPlatformError;
        goto out;
    }

    result = MbedTLSDecodeECSign(signature, &signature_length, key_size);
    if (result != kDiceResultOk) {
        EMSG("MbedTLSDecodeECSign %d", result);
        goto out;
    }
    *actual_signature_length = signature_length;
out:
    if (digest)
        free(digest);

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return result;
}

static DiceResult GetIdFromKey(void* context,
                               const mbedtls_pk_context* pk_context,
                               uint8_t id[DICE_ID_SIZE]) {
    uint8_t raw_public_key[33];
    size_t raw_public_key_size = 0;
    mbedtls_ecp_keypair* key = mbedtls_pk_ec(*pk_context);

    if (0 != mbedtls_ecp_point_write_binary(
                 &key->grp, &key->Q, MBEDTLS_ECP_PF_COMPRESSED,
                 &raw_public_key_size, raw_public_key, sizeof(raw_public_key))) {
        return kDiceResultPlatformError;
    }
    return DiceDeriveCdiCertificateId(context, raw_public_key,
                                      raw_public_key_size, id);
}

// 54 byte name is prefix (13), hex id (40), and a null terminator.
static void GetNameFromId(const uint8_t id[DICE_ID_SIZE], char name[54]) {
    strcpy(name, "serialNumber=");
    DiceHexEncode(id, /*num_bytes=*/DICE_ID_SIZE, (uint8_t*)&name[13],
                  /*out_size=*/40);
    name[53] = '\0';
}

static DiceResult GetSubjectKeyIdFromId(const uint8_t id[DICE_ID_SIZE],
                                        size_t buffer_size, uint8_t* buffer,
                                        size_t* actual_size) {
    uint8_t* pos = buffer + buffer_size;
    int length_or_error =
        mbedtls_asn1_write_octet_string(&pos, buffer, id, DICE_ID_SIZE);
    if (length_or_error < 0) {
        return kDiceResultPlatformError;
    }
    *actual_size = length_or_error;
    memmove(buffer, pos, *actual_size);
    return kDiceResultOk;
}

static int AddAuthorityKeyIdEncoding(uint8_t** pos, uint8_t* start,
                                     int length) {
    // From RFC 5280 4.2.1.1.
    const int kKeyIdentifierTag = 0;

    int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
    MBEDTLS_ASN1_CHK_ADD(length, mbedtls_asn1_write_len(pos, start, length));
    MBEDTLS_ASN1_CHK_ADD(
        length,
        mbedtls_asn1_write_tag(
            pos, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | kKeyIdentifierTag));

    MBEDTLS_ASN1_CHK_ADD(length, mbedtls_asn1_write_len(pos, start, length));
    MBEDTLS_ASN1_CHK_ADD(
        length,
        mbedtls_asn1_write_tag(pos, start,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    return length;
}

static DiceResult GetAuthorityKeyIdFromId(const uint8_t id[DICE_ID_SIZE],
                                          size_t buffer_size, uint8_t* buffer,
                                          size_t* actual_size) {
    uint8_t* pos = buffer + buffer_size;
    int length_or_error =
        mbedtls_asn1_write_raw_buffer(&pos, buffer, id, DICE_ID_SIZE);
    if (length_or_error < 0) {
        return kDiceResultPlatformError;
    }
    length_or_error = AddAuthorityKeyIdEncoding(&pos, buffer, length_or_error);
    if (length_or_error < 0) {
        return kDiceResultPlatformError;
    }
    *actual_size = length_or_error;
    memmove(buffer, pos, *actual_size);
    return kDiceResultOk;
}

static uint8_t GetFieldTag(uint8_t tag) {
    return MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag;
}

// Can be used with MBEDTLS_ASN1_CHK_ADD.
static int WriteExplicitModeField(uint8_t tag, int value, uint8_t** pos,
                                  uint8_t* start) {
    // ASN.1 constants not defined by mbedtls.
    const uint8_t kEnumTypeTag = 10;

    int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
    int field_length = 0;
    MBEDTLS_ASN1_CHK_ADD(field_length, mbedtls_asn1_write_int(pos, start, value));
    // Overwrite the 'int' type.
    ++(*pos);
    --field_length;
    MBEDTLS_ASN1_CHK_ADD(field_length,
                         mbedtls_asn1_write_tag(pos, start, kEnumTypeTag));

    // Explicitly tagged, so add the field tag too.
    MBEDTLS_ASN1_CHK_ADD(field_length,
                         mbedtls_asn1_write_len(pos, start, field_length));
    MBEDTLS_ASN1_CHK_ADD(field_length,
                         mbedtls_asn1_write_tag(pos, start, GetFieldTag(tag)));
    return field_length;
}

// Can be used with MBEDTLS_ASN1_CHK_ADD.
static int WriteExplicitUtf8StringField(uint8_t tag, const void* value,
                                        size_t value_size, uint8_t** pos,
                                        uint8_t* start) {
    int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
    int field_length = 0;
    MBEDTLS_ASN1_CHK_ADD(field_length, mbedtls_asn1_write_utf8_string(
                                           pos, start, value, value_size));
    // Explicitly tagged, so add the field tag too.
    MBEDTLS_ASN1_CHK_ADD(field_length,
                         mbedtls_asn1_write_len(pos, start, field_length));
    MBEDTLS_ASN1_CHK_ADD(field_length,
                         mbedtls_asn1_write_tag(pos, start, GetFieldTag(tag)));
    return field_length;
}

// Can be used with MBEDTLS_ASN1_CHK_ADD.
static int WriteExplicitOctetStringField(uint8_t tag, const uint8_t* value,
                                         size_t value_size, uint8_t** pos,
                                         uint8_t* start) {
    int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
    int field_length = 0;
    MBEDTLS_ASN1_CHK_ADD(field_length, mbedtls_asn1_write_octet_string(
                                           pos, start, value, value_size));
    // Explicitly tagged, so add the field tag too.
    MBEDTLS_ASN1_CHK_ADD(field_length,
                         mbedtls_asn1_write_len(pos, start, field_length));
    MBEDTLS_ASN1_CHK_ADD(field_length,
                         mbedtls_asn1_write_tag(pos, start, GetFieldTag(tag)));
    return field_length;
}

static int GetDiceExtensionDataHelper(const DiceInputValues* input_values,
                                      uint8_t** pos, uint8_t* start) {
    // ASN.1 tags for extension fields.
    const uint8_t kDiceFieldCodeHash = 0;
    const uint8_t kDiceFieldCodeDescriptor = 1;
    const uint8_t kDiceFieldConfigHash = 2;
    const uint8_t kDiceFieldConfigDescriptor = 3;
    const uint8_t kDiceFieldAuthorityHash = 4;
    const uint8_t kDiceFieldAuthorityDescriptor = 5;
    const uint8_t kDiceFieldMode = 6;
    const uint8_t kDiceFieldProfileName = 7;

    // Build up the extension ASN.1 in reverse order.
    int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
    int length = 0;

    // Add the profile name field.
    if (DICE_PROFILE_NAME) {
        MBEDTLS_ASN1_CHK_ADD(length, WriteExplicitUtf8StringField(
                                         kDiceFieldProfileName, DICE_PROFILE_NAME,
                                         strlen(DICE_PROFILE_NAME), pos, start));
    }

    // Add the mode field.
    MBEDTLS_ASN1_CHK_ADD(
        length,
        WriteExplicitModeField(kDiceFieldMode, input_values->mode, pos, start));

    // Add the authorityDescriptor field, if applicable.
    if (input_values->authority_descriptor_size > 0) {
        MBEDTLS_ASN1_CHK_ADD(
            length,
        WriteExplicitOctetStringField(
            kDiceFieldAuthorityDescriptor, input_values->authority_descriptor,
            input_values->authority_descriptor_size, pos, start));
    }

    // Add the authorityHash field.
    MBEDTLS_ASN1_CHK_ADD(
        length, WriteExplicitOctetStringField(kDiceFieldAuthorityHash,
                                              input_values->authority_hash,
                                              DICE_HASH_SIZE, pos, start));

    // Add the configurationDescriptor field (and configurationHash field, if
    // applicable).
    if (input_values->config_type == kDiceConfigTypeDescriptor) {
        uint8_t hash[DICE_HASH_SIZE];
        int result = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
                                input_values->config_descriptor,
                                input_values->config_descriptor_size, hash);
    if (result) {
        return result;
    }
    MBEDTLS_ASN1_CHK_ADD(
        length, WriteExplicitOctetStringField(
                    kDiceFieldConfigDescriptor, input_values->config_descriptor,
                    input_values->config_descriptor_size, pos, start));
    MBEDTLS_ASN1_CHK_ADD(
        length, WriteExplicitOctetStringField(kDiceFieldConfigHash, hash,
                                              DICE_HASH_SIZE, pos, start));
    } else if (input_values->config_type == kDiceConfigTypeInline) {
        MBEDTLS_ASN1_CHK_ADD(
            length, WriteExplicitOctetStringField(
                        kDiceFieldConfigDescriptor, input_values->config_value,
                        DICE_INLINE_CONFIG_SIZE, pos, start));
    }

    // Add the code descriptor field, if applicable.
    if (input_values->code_descriptor_size > 0) {
        MBEDTLS_ASN1_CHK_ADD(
            length, WriteExplicitOctetStringField(
                        kDiceFieldCodeDescriptor, input_values->code_descriptor,
                        input_values->code_descriptor_size, pos, start));
    }

    // Add the code hash field.
    MBEDTLS_ASN1_CHK_ADD(length, WriteExplicitOctetStringField(
                                     kDiceFieldCodeHash, input_values->code_hash,
                                     DICE_HASH_SIZE, pos, start));

    // Add the sequence length and tag.
    MBEDTLS_ASN1_CHK_ADD(length, mbedtls_asn1_write_len(pos, start, length));
    MBEDTLS_ASN1_CHK_ADD(
        length,
        mbedtls_asn1_write_tag(pos, start,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    return length;
}

static DiceResult GetDiceExtensionData(const DiceInputValues* input_values,
                                       size_t buffer_size, uint8_t* buffer,
                                       size_t* actual_size) {
    uint8_t* pos = buffer + buffer_size;
    int length_or_error = GetDiceExtensionDataHelper(input_values, &pos, buffer);
    if (length_or_error == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
        return kDiceResultBufferTooSmall;
    } else if (length_or_error < 0) {
        return kDiceResultPlatformError;
    }
    *actual_size = length_or_error;
    memmove(buffer, pos, *actual_size);
    return kDiceResultOk;
}

DiceResult DiceHash(void* context_not_used, const uint8_t* input,
                    size_t input_size, uint8_t output[DICE_HASH_SIZE]) {
    (void)context_not_used;
    if (0 != mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), input,
                        input_size, output)) {
        return kDiceResultPlatformError;
    }
    return kDiceResultOk;
}

DiceResult DiceKdf(void* context_not_used, size_t length, const uint8_t* ikm,
                   size_t ikm_size, const uint8_t* salt, size_t salt_size,
                   const uint8_t* info, size_t info_size, uint8_t* output) {
    (void)context_not_used;
    if (0 != mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), salt,
                          salt_size, ikm, ikm_size, info, info_size, output,
                          length)) {
        return kDiceResultPlatformError;
    }
    return kDiceResultOk;
}

DiceResult DiceGenerateCertificate(
    void* context,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size) {

    // 1.3.6.1.4.1.11129.2.1.24
    // iso.org.dod.internet.private.enterprise.
    //   google.googleSecurity.certificateExtensions.diceAttestationData
    const char* kDiceExtensionOid =
        MBEDTLS_OID_ISO_IDENTIFIED_ORG MBEDTLS_OID_ORG_DOD
        "\x01\x04\x01\xd6\x79\x02\x01\x18";
    const size_t kDiceExtensionOidLength = 10;

    DiceResult result = kDiceResultOk;
    // Initialize variables cleaned up on 'goto out'.
    mbedtls_pk_context authority_key_context;
    mbedtls_pk_init(&authority_key_context);
    mbedtls_pk_context subject_key_context;
    mbedtls_pk_init(&subject_key_context);
    mbedtls_x509write_cert cert_context;
    mbedtls_x509write_crt_init(&cert_context);
    mbedtls_mpi serial_number;
    mbedtls_mpi_init(&serial_number);
    // Derive key pairs and IDs.
    result = SetupKeyPair(authority_private_key_seed, &authority_key_context);
    if (result != kDiceResultOk) {
        goto out;
    }
    uint8_t authority_id[DICE_ID_SIZE];
    result = GetIdFromKey(context, &authority_key_context, authority_id);
    if (result != kDiceResultOk) {
        goto out;
    }
    char authority_name[54];
    GetNameFromId(authority_id, authority_name);

    uint8_t authority_key_id[DICE_MAX_KEY_ID_SIZE];
    size_t authority_key_id_size = 0;
    result = GetAuthorityKeyIdFromId(authority_id, sizeof(authority_key_id),
                                     authority_key_id, &authority_key_id_size);
    if (result != kDiceResultOk) {
        goto out;
    }
    result = SetupKeyPair(subject_private_key_seed, &subject_key_context);
    if (result != kDiceResultOk) {
        goto out;
    }
    uint8_t subject_id[DICE_ID_SIZE];
    result = GetIdFromKey(context, &subject_key_context, subject_id);
    if (result != kDiceResultOk) {
        goto out;
    }

    char subject_name[54];
    GetNameFromId(subject_id, subject_name);
    uint8_t subject_key_id[DICE_MAX_KEY_ID_SIZE];
    size_t subject_key_id_size = 0;
    result = GetSubjectKeyIdFromId(subject_id, sizeof(subject_key_id),
                                   subject_key_id, &subject_key_id_size);
    if (result != kDiceResultOk) {
        goto out;
    }
    uint8_t dice_extension[DICE_MAX_EXTENSION_SIZE];
    size_t dice_extension_size = 0;
    result = GetDiceExtensionData(input_values, sizeof(dice_extension),
                                  dice_extension, &dice_extension_size);
    if (result != kDiceResultOk) {
        goto out;
    }

    // Construct the certificate.
    mbedtls_x509write_crt_set_version(&cert_context, MBEDTLS_X509_CRT_VERSION_3);
    if (0 !=
        mbedtls_mpi_read_binary(&serial_number, subject_id, sizeof(subject_id))) {
        result = kDiceResultPlatformError;
        goto out;
    }
    if (0 != mbedtls_x509write_crt_set_serial(&cert_context, &serial_number)) {
        result = kDiceResultPlatformError;
        goto out;
    }

    // '20180322235959' is the date of publication of the DICE specification. Here
    // it's used as a somewhat arbitrary backstop. '99991231235959' is suggested
    // by RFC 5280 in cases where expiry is not meaningful. Basically, the
    // certificate never expires.
    if (0 != mbedtls_x509write_crt_set_validity(&cert_context, "20180322235959",
                                                "99991231235959")) {
        result = kDiceResultPlatformError;
        goto out;
    }
    if (0 !=
        mbedtls_x509write_crt_set_issuer_name(&cert_context, authority_name)) {
        result = kDiceResultPlatformError;
        goto out;
    }
    if (0 !=
        mbedtls_x509write_crt_set_subject_name(&cert_context, subject_name)) {
        result = kDiceResultPlatformError;
        goto out;
    }

    mbedtls_x509write_crt_set_subject_key(&cert_context, &subject_key_context);
    mbedtls_x509write_crt_set_issuer_key(&cert_context, &authority_key_context);
    mbedtls_x509write_crt_set_md_alg(&cert_context, MBEDTLS_MD_SHA512);
    if (0 != mbedtls_x509write_crt_set_extension(
                 &cert_context, MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER,
                 MBEDTLS_OID_SIZE(MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER),
                 /*critical=*/0, authority_key_id, authority_key_id_size)) {
        result = kDiceResultPlatformError;
        goto out;
    }

    if (0 != mbedtls_x509write_crt_set_extension(
                 &cert_context, MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER,
                 MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER),
                 /*critical=*/0, subject_key_id, subject_key_id_size)) {
        result = kDiceResultPlatformError;
        goto out;
    }

    if (0 != mbedtls_x509write_crt_set_key_usage(&cert_context,
                                                 MBEDTLS_X509_KU_KEY_CERT_SIGN)) {
        result = kDiceResultPlatformError;
        goto out;
    }

    if (0 != mbedtls_x509write_crt_set_basic_constraints(&cert_context,
                                                         /*is_ca=*/1,
                                                         /*max_pathlen=*/-1)) {
        result = kDiceResultPlatformError;
        goto out;
    }

    if (0 != mbedtls_x509write_crt_set_extension(
                 &cert_context, kDiceExtensionOid, kDiceExtensionOidLength,
                 /*critical=*/1, dice_extension, dice_extension_size)) {
        result = kDiceResultPlatformError;
        goto out;
    }

    // This implementation is deterministic and assumes entropy is not available.
    // If this code is run where entropy is available, however, f_rng and p_rng
    // should be set to use that entropy. As is, we'll provide a DRBG for blinding
    // but it will be ineffective.
    mbedtls_hmac_drbg_context drbg;
    mbedtls_hmac_drbg_init(&drbg);
    mbedtls_hmac_drbg_seed_buf(&drbg,
                               mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
                               subject_key_id, subject_key_id_size);

    uint8_t tmp_buffer[DICE_MAX_CERTIFICATE_SIZE];
    int length_or_error =
        mbedtls_x509write_crt_der(&cert_context, tmp_buffer, sizeof(tmp_buffer),
                                  mbedtls_hmac_drbg_random, &drbg);

    mbedtls_hmac_drbg_free(&drbg);
    if (length_or_error < 0) {
        result = kDiceResultPlatformError;
        goto out;
    }

    *certificate_actual_size = length_or_error;
    if (*certificate_actual_size > certificate_buffer_size) {
        result = kDiceResultBufferTooSmall;
        goto out;
    }
    // The certificate has been written to the end of tmp_buffer. Skip unused
    // buffer when copying.
    memcpy(certificate,
           &tmp_buffer[sizeof(tmp_buffer) - *certificate_actual_size],
           *certificate_actual_size);

out:
    mbedtls_mpi_free(&serial_number);
    mbedtls_x509write_crt_free(&cert_context);
    mbedtls_pk_free(&authority_key_context);
    mbedtls_pk_free(&subject_key_context);
    return result;
}

DiceResult DiceGenerateCertificateCbor(
    void* context,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues *input_values, size_t certificate_buffer_size,
    uint8_t *certificate, size_t *certificate_actual_size) {

    DiceResult result = kDiceResultOk;
    // Initialize variables cleaned up on 'goto out'.
    mbedtls_pk_context authority_key_context;
    mbedtls_pk_init(&authority_key_context);
    mbedtls_pk_context subject_key_context;
    mbedtls_pk_init(&subject_key_context);
    
    // Derive key pairs.
    result = SetupKeyPair(authority_private_key_seed, &authority_key_context);
    if (result != kDiceResultOk) {
        goto out;
    }

    result = SetupKeyPair(subject_private_key_seed, &subject_key_context);
    if (result != kDiceResultOk) {
        goto out;
    }

    result = DiceSignCertificate(context, &subject_key_context, &authority_key_context, input_values,
                                 certificate_buffer_size, certificate, certificate_actual_size);
    if (result != kDiceResultOk) {
        goto out;
    }

out:
    mbedtls_pk_free(&authority_key_context);
    mbedtls_pk_free(&subject_key_context);
    return result;
}
