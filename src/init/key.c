// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "key.h"
#include "ec.h"
#include "quote.h"
#include "report.h"
#include "types.h"
#include "utils.h"
#include <errno.h>
#include <mbedtls/bignum.h>
#include <mbedtls/cipher.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/x509_crt.h>
#include <sgx_quote_3.h>
#include <sgx_report.h>
#include <sgx_report2.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <tdx_attest.h>
#include <unistd.h>

#define PORT 24516

struct ecc_context {
	mbedtls_ecp_group grp;
	mbedtls_ctr_drbg_context drbg;
};

static int init_ecc_context(struct ecc_context *ctx, int (*f_entropy)(void *, uint8_t *, size_t)) {
	int err = 0;
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	{
		mbedtls_ecp_group_init(&ctx->grp);
		mbedtls_ctr_drbg_init(&ctx->drbg);

		err = mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP256K1);
		if (err) {
			trace("mbedtls_ecp_group_load failed: %d\n", err);
			goto cleanup;
		}
		const uint8_t pers[] = "quex_init";
		err = mbedtls_ctr_drbg_seed(&ctx->drbg, f_entropy, &entropy, pers, sizeof pers);
		if (err) {
			trace("mbedtls_ctr_drbg_seed failed: %d\n", err);
			goto cleanup;
		}
	}
cleanup:
	mbedtls_entropy_free(&entropy);
	return err;
}

static void free_ecc_context(struct ecc_context *ctx) {
	mbedtls_ctr_drbg_free(&ctx->drbg);
	mbedtls_ecp_group_free(&ctx->grp);
}

static int gen_report_data(struct ecc_context *ctx, mbedtls_mpi *out_ephemeral_sk,
                           tdx_report_data_t *out_report_data) {
	mbedtls_ecp_point ephemeral_pk;
	mbedtls_ecp_point_init(&ephemeral_pk);
	int err = mbedtls_ecp_gen_keypair(&ctx->grp, out_ephemeral_sk, &ephemeral_pk,
	                                  mbedtls_ctr_drbg_random, &ctx->drbg);
	if (err) {
		trace("mbedtls_ecp_gen_keypair failed: %d\n", err);
		goto cleanup;
	}

	err = write_raw_pk(&ctx->grp, &ephemeral_pk, out_report_data->d);
	if (err) {
		trace("mbedtls_ecp_point_write_binary failed: %d\n", err);
		goto cleanup;
	}

cleanup:
	mbedtls_ecp_point_free(&ephemeral_pk);
	return err;
}

static int get_pk(struct ecc_context *ctx, const uint8_t raw_sk[32], uint8_t out_pk[64]) {
	mbedtls_mpi sk;
	mbedtls_ecp_point pk;
	mbedtls_mpi_init(&sk);
	mbedtls_ecp_point_init(&pk);

	int err = read_raw_sk(raw_sk, &sk);
	if (err) {
		trace("read_raw_sk failed: %d\n", err);
		goto cleanup;
	}

	err =
	    mbedtls_ecp_mul(&ctx->grp, &pk, &sk, &ctx->grp.G, mbedtls_ctr_drbg_random, &ctx->drbg);
	if (err) {
		trace("mbedtls_ecp_mul failed: %d\n", err);
		goto cleanup;
	}

	err = write_raw_pk(&ctx->grp, &pk, out_pk);
	if (err) {
		trace("write_raw_pk failed: %d\n", err);
		goto cleanup;
	}

cleanup:
	mbedtls_ecp_point_free(&pk);
	mbedtls_mpi_free(&sk);
	return err;
}

static int decrypt_sk(struct ecc_context *ctx, const mbedtls_mpi *ephemeral_sk,
                      const uint8_t ciphertext[QUEX_CT_LEN], uint8_t out_sk[32]) {
	uint8_t ikm[130] = {0};
	uint8_t symmetric_key[32] = {0};
	const uint8_t salt[] = "quex_salt";
	mbedtls_ecp_point ephemeral_pk;
	mbedtls_ecp_point dh;
	mbedtls_gcm_context gcm;

	mbedtls_ecp_point_init(&ephemeral_pk);
	mbedtls_ecp_point_init(&dh);
	mbedtls_gcm_init(&gcm);

	bool success = true;

	int err = read_raw_pk(&ctx->grp, ciphertext, &ephemeral_pk);
	if (err) {
		trace("read_raw_pk failed: %d\n", err);
		success = false;
	}

	err = mbedtls_ecp_mul(&ctx->grp, &dh, ephemeral_sk, &ephemeral_pk, mbedtls_ctr_drbg_random,
	                      &ctx->drbg);
	if (err) {
		trace("mbedtls_ecp_mul failed: %d\n", err);
		success = false;
	}

	size_t olen;
	err = mbedtls_ecp_point_write_binary(&ctx->grp, &ephemeral_pk, MBEDTLS_ECP_PF_UNCOMPRESSED,
	                                     &olen, ikm, sizeof ikm);
	if (err) {
		trace("mbedtls_ecp_point_write_binary(ephemeral_pk) failed: %d\n", err);
		success = false;
	}

	err = mbedtls_ecp_point_write_binary(&ctx->grp, &dh, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
	                                     ikm + olen, sizeof ikm - olen);
	if (err) {
		trace("mbedtls_ecp_point_write_binary(dh) failed: %d\n", err);
		success = false;
	}

	err = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt,
	                   9,                // salt
	                   ikm, sizeof ikm,  // ikm
	                   NULL, 0,          // info
	                   symmetric_key, 32 // okm
	);
	if (err) {
		trace("mbedtls_hkdf failed: %d\n", err);
		success = false;
	}

	err = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, symmetric_key, 128);
	if (err) {
		trace("mbedtls_gcm_setkey failed: %d\n", err);
		success = false;
	}

	err = mbedtls_gcm_auth_decrypt(&gcm, 32, ciphertext + 64, 12, NULL, 0, ciphertext + 80, 16,
	                               ciphertext + 96, out_sk);
	if (err) {
		trace("mbedtls_gcm_auth_decrypt failed: %d\n", err);
		success = false;
	}

	mbedtls_platform_zeroize(ikm, sizeof ikm);
	mbedtls_platform_zeroize(symmetric_key, sizeof symmetric_key);
	mbedtls_gcm_free(&gcm);
	mbedtls_ecp_point_free(&ephemeral_pk);
	mbedtls_ecp_point_free(&dh);

	return success ? 0 : -1;
}

static int recv_response(int client, struct td_response_msg *out_msg, sgx_quote3_t **out_quote,
                         size_t *out_quote_len) {
	ssize_t received = recv(client, out_msg, sizeof *out_msg, MSG_WAITALL);
	if (received != sizeof *out_msg) {
#ifdef ENABLE_TRACE
		if (received < 0) {
			trace("Could not recv td_response_msg: %s\n", strerror(errno));
		} else {
			trace("Could not recv td_response_msg: expected %zu, got %zd\n",
			      sizeof *out_msg, received);
		}
#endif
		return -1;
	}

	sgx_quote3_t quote_header = {0};
	received = recv(client, &quote_header, sizeof quote_header, MSG_WAITALL);
	if (received != sizeof quote_header) {
#ifdef ENABLE_TRACE
		if (received < 0) {
			trace("Could not recv sgx_quote3_t header: %s\n", strerror(errno));
		} else {
			trace("Could not recv sgx_quote3_t header: expected %zu, got %zd\n",
			      sizeof quote_header, received);
		}
#endif
		return -1;
	}

	if (!is_quote_header_well_formed(&quote_header)) {
		trace("Quote header is ill-formed\n");
		return -1;
	}

	trace("Got quote version %d\n", quote_header.header.version);

	size_t quote_len = sizeof quote_header + quote_header.signature_data_len;
	sgx_quote3_t *quote = (sgx_quote3_t *)malloc(quote_len);

	if (!quote) {
		trace("Could not malloc for sgx_quote3_t\n");
		return -1;
	}

	memcpy(quote, &quote_header, sizeof quote_header);

	trace("Receiving %d bytes of quote signature...\n", quote_header.signature_data_len);
	received = recv(client, (uint8_t *)quote + sizeof quote_header,
	                quote_header.signature_data_len, MSG_WAITALL);
	if (received != quote_header.signature_data_len) {
#ifdef ENABLE_TRACE
		if (received < 0) {
			trace("Could not recv quote signature: %s\n", strerror(errno));
		} else {
			trace("Could not recv quote signature: expected %u, got %zd\n",
			      quote_header.signature_data_len, received);
		}
#endif
		free(quote);
		return -1;
	}

	trace("Received %d bytes of quote signature\n", quote_header.signature_data_len);

	*out_quote = quote;
	*out_quote_len = quote_len;

	return 0;
}

static int compare_masked(const sgx_report2_t *first, const sgx_report2_t *second,
                          const struct td_key_request_mask *mask) {
	sgx_report2_t first_masked;
	sgx_report2_t second_masked;
	memcpy(&first_masked, first, sizeof first_masked);
	memcpy(&second_masked, second, sizeof second_masked);
	apply_mask(&first_masked, mask);
	apply_mask(&second_masked, mask);
	return mbedtls_ct_memcmp(&first_masked, &second_masked, sizeof first_masked);
}

int get_keys(const char *key_request_mask_hex, const char *vault_mr_enclave_hex,
             const char *root_pem_path, int (*f_entropy)(void *, uint8_t *, size_t),
             uint8_t out_sk[32], uint8_t out_pk[64]) {
	int sock = -1;
	int err = 0;
	struct ecc_context ctx;
	mbedtls_x509_crt root_crt;
	mbedtls_x509_crt_init(&root_crt);
	{
		err = init_ecc_context(&ctx, f_entropy);
		if (err) {
			trace("init_ecc_context failed: %d\n", err);
			goto cleanup;
		}

		struct td_key_request key_request;
		err = read_hex(key_request_mask_hex, (uint8_t *)&key_request.mask,
		               sizeof key_request.mask);
		if (err) {
			trace("Could not read key request mask %s: %d\n", key_request_mask_hex,
			      err);
			goto cleanup;
		}

		sgx_measurement_t mr_enclave;
		err = read_hex(vault_mr_enclave_hex, (uint8_t *)&mr_enclave, sizeof mr_enclave);
		if (err) {
			trace("Could not read vault mr_enclave %s: %d\n", vault_mr_enclave_hex,
			      err);
			goto cleanup;
		}

		err = mbedtls_x509_crt_parse_file(&root_crt, root_pem_path);
		if (err) {
			trace("Could not load root certificate %s: %d\n", root_pem_path, err);
			goto cleanup;
		}

		sock = init_socket(PORT);
		if (sock < 0) {
			err = -1;
			trace("init_socket(%d) failed: %d\n", PORT, sock);
			goto cleanup;
		}

		bool got_sk = false;
		while (!got_sk && !err) {
			int iter_err = 0;

			trace("Waiting for a connection...\n");
			int client = accept(sock, NULL, NULL);
			if (client < 0) {
				int accept_err = errno;
				trace("accept failed: %s\n", strerror(accept_err));
				if (accept_err == EINVAL || accept_err == EBADF) {
					err = -1;
				}
				continue;
			}

			mbedtls_mpi ephemeral_sk;
			mbedtls_mpi_init(&ephemeral_sk);
			sgx_quote3_t *quote = NULL;
			{
				tdx_report_data_t report_data = {0};
				iter_err = gen_report_data(&ctx, &ephemeral_sk, &report_data);
				if (iter_err) {
					trace("gen_report_data failed: %d\n", iter_err);
					goto cleanup_iteration;
				}

				tdx_report_t report = {0};
				tdx_attest_error_t attest_err =
				    tdx_att_get_report(&report_data, &report);
				if (attest_err != TDX_ATTEST_SUCCESS) {
					trace("tdx_att_get_report failed: %d\n", attest_err);
					goto cleanup_iteration;
				}

				memcpy(&key_request.tdreport, &report, sizeof report);

				trace("Sending key request...\n");
				send(client, &key_request, sizeof key_request, MSG_NOSIGNAL);

				struct td_response_msg msg = {0};

				size_t quote_len = 0;
				iter_err = recv_response(client, &msg, &quote, &quote_len);
				if (iter_err) {
					trace("recv_response failed\n");
					goto cleanup_iteration;
				}

				got_sk = true;

				if (mbedtls_ct_memcmp(&msg.mask, &key_request.mask,
				                      sizeof key_request.mask) != 0) {
					trace("Masks do not match\n");
					got_sk = false;
				}

				if (compare_masked(&msg.tdreport, &key_request.tdreport,
				                   &key_request.mask) != 0) {
					trace("Masked reports do not match\n");
					got_sk = false;
				}

				if (mbedtls_ct_memcmp(&quote->report_body.mr_enclave, &mr_enclave,
				                      sizeof mr_enclave) != 0) {
					trace("Wrong mr_enclave\n");
					got_sk = false;
				}

				iter_err = verify_quote(quote, quote_len, &root_crt);
				if (iter_err) {
					trace("Invalid quote: %d\n", iter_err);
					got_sk = false;
				}

				uint8_t msg_hash[32] = {0};
				iter_err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
				                      (uint8_t *)&msg, sizeof msg, msg_hash);
				if (iter_err) {
					trace("mbedtls_md failed: %d\n", iter_err);
					got_sk = false;
				}

				if (mbedtls_ct_memcmp(&quote->report_body.report_data, msg_hash,
				                      sizeof msg_hash) != 0) {
					trace("Quote report data does not contain message hash\n");
					got_sk = false;
				}

				iter_err = decrypt_sk(&ctx, &ephemeral_sk, msg.ciphertext, out_sk);
				if (iter_err) {
					trace("decrypt_sk failed: %d\n", iter_err);
					got_sk = false;
				}

				trace("Successfully got the secret key: %d\n", got_sk);
			}
		cleanup_iteration:
			mbedtls_mpi_free(&ephemeral_sk);
			free(quote);
			close(client);
		}

		if (err) {
			goto cleanup;
		}

		err = get_pk(&ctx, out_sk, out_pk);
		if (err) {
			trace("get_pk failed: %d\n", err);
			goto cleanup;
		}
	}
cleanup:
	if (sock >= 0) {
		close(sock);
	}
	mbedtls_x509_crt_free(&root_crt);
	free_ecc_context(&ctx);
	return err;
}
