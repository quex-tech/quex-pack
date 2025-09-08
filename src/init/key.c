// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "ec.h"
#include "quote.h"
#include "report.h"
#include "types.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/hkdf.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <tdx_attest.h>
#include <unistd.h>

#ifdef SKIP_KEY
int get_sk(uint8_t sk[32]) {
	memset(sk, 1, 32);
	return 0;
}
#else

#define PORT 24516
#define ROOT_PEM_PATH "/etc/root.pem"
#define ROOT_PEM_SIZE 964

typedef struct _ecc_context {
	mbedtls_ecp_group grp;
	mbedtls_ctr_drbg_context drbg;
} ecc_context;

static int init_ecc_context(ecc_context *ctx) {
	mbedtls_entropy_context entropy;
	int ret = -1;

	mbedtls_ecp_group_init(&(ctx->grp));
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&(ctx->drbg));

	if (mbedtls_ecp_group_load(&(ctx->grp), MBEDTLS_ECP_DP_SECP256K1) != 0) {
		trace("mbedtls_ecp_group_load failed\n");
		goto cleanup;
	}
	const unsigned char pers[] = "quex_init";
	if (mbedtls_ctr_drbg_seed(&(ctx->drbg), mbedtls_entropy_func, &entropy, pers,
	                          sizeof(pers)) != 0) {
		trace("mbedtls_ctr_drbg_seed failed\n");
		goto cleanup;
	}
	ret = 0;
cleanup:
	mbedtls_entropy_free(&entropy);
	return ret;
}

static void free_ecc_context(ecc_context *ctx) {
	mbedtls_ctr_drbg_free(&(ctx->drbg));
	mbedtls_ecp_group_free(&(ctx->grp));
}

static int gen_report_data(ecc_context *ctx, mbedtls_mpi *ephemeral_sk,
                           tdx_report_data_t *report_data) {
	mbedtls_ecp_point ephemeral_pk;
	int ret = -1;
	mbedtls_ecp_point_init(&ephemeral_pk);
	if ((ret = mbedtls_ecp_gen_keypair(&(ctx->grp), ephemeral_sk, &ephemeral_pk,
	                                   mbedtls_ctr_drbg_random, &(ctx->drbg))) != 0) {
		trace("mbedtls_ecp_gen_keypair failed: %d\n", ret);
		goto cleanup;
	}

	if ((ret = write_raw_pk(&(ctx->grp), &ephemeral_pk, report_data->d)) != 0) {
		trace("mbedtls_ecp_point_write_binary failed: %d\n", ret);
		goto cleanup;
	}

	ret = 0;
cleanup:
	mbedtls_ecp_point_free(&ephemeral_pk);
	return ret;
}

static int mk_report_data(ecc_context *ctx, const uint8_t raw_sk[32],
                          tdx_report_data_t *report_data) {
	mbedtls_mpi sk;
	mbedtls_ecp_point pk;
	int ret = -1;
	mbedtls_mpi_init(&sk);
	mbedtls_ecp_point_init(&pk);

	if ((ret = read_raw_sk(raw_sk, &sk)) != 0) {
		trace("read_raw_sk failed: %d\n", ret);
		goto cleanup;
	}

	if ((ret = mbedtls_ecp_mul(&(ctx->grp), &pk, &sk, &ctx->grp.G, mbedtls_ctr_drbg_random,
	                           &(ctx->drbg))) != 0) {
		trace("mbedtls_ecp_mul failed: %d\n", ret);
		goto cleanup;
	}

	if ((ret = write_raw_pk(&(ctx->grp), &pk, report_data->d)) != 0) {
		trace("mbedtls_ecp_point_write_binary failed: %d\n", ret);
		goto cleanup;
	}

	ret = 0;
cleanup:
	mbedtls_ecp_point_free(&pk);
	mbedtls_mpi_free(&sk);
	return ret;
}

static int decrypt_sk(ecc_context *ctx, mbedtls_mpi *ephemeral_sk, uint8_t ciphertext[QUEX_CT_LEN],
                      uint8_t sk[32]) {
	int ret = -1;
	uint8_t ikm[130];
	uint8_t symmetric_key[32];
	const unsigned char salt[] = "quex_salt";
	mbedtls_ecp_point ephemeral_pk;
	mbedtls_ecp_point dh;
	mbedtls_gcm_context gcm;

	mbedtls_ecp_point_init(&ephemeral_pk);
	mbedtls_ecp_point_init(&dh);
	mbedtls_gcm_init(&gcm);

	if ((ret = read_raw_pk(&(ctx->grp), ciphertext, &ephemeral_pk)) != 0) {
		trace("read_raw_pk failed: %d", ret);
		goto cleanup;
	}

	if ((ret = mbedtls_ecp_mul(&(ctx->grp), &dh, ephemeral_sk, &ephemeral_pk,
	                           mbedtls_ctr_drbg_random, &(ctx->drbg))) != 0) {
		trace("mbedtls_ecp_mul failed: %d", ret);
		goto cleanup;
	}

	size_t olen;
	if ((ret = mbedtls_ecp_point_write_binary(&(ctx->grp), &ephemeral_pk,
	                                          MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, ikm,
	                                          sizeof(ikm))) != 0) {
		trace("mbedtls_ecp_point_write_binary(ephemeral_pk) failed: %d", ret);
		goto cleanup;
	}
	if ((ret = mbedtls_ecp_point_write_binary(&(ctx->grp), &dh, MBEDTLS_ECP_PF_UNCOMPRESSED,
	                                          &olen, ikm + olen, sizeof(ikm) - olen)) != 0) {
		trace("mbedtls_ecp_point_write_binary(dh) failed: %d", ret);
		goto cleanup;
	}

	if ((ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt,
	                        9,                // salt
	                        ikm, sizeof(ikm), // ikm
	                        NULL, 0,          // info
	                        symmetric_key, 32 // okm
	                        )) != 0) {
		trace("mbedtls_hkdf failed: %d", ret);
		goto cleanup;
	}

	if ((ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, symmetric_key, 128)) != 0) {
		trace("mbedtls_gcm_setkey failed: %d", ret);
		goto cleanup;
	}

	if ((ret = mbedtls_gcm_auth_decrypt(&gcm, 32, ciphertext + 64, 12, NULL, 0, ciphertext + 80,
	                                    16, ciphertext + 96, sk)) != 0) {
		trace("mbedtls_gcm_auth_decrypt failed: %d", ret);
		goto cleanup;
	}

	ret = 0;
cleanup:
	mbedtls_platform_zeroize(ikm, sizeof(ikm));
	mbedtls_platform_zeroize(symmetric_key, sizeof(symmetric_key));
	mbedtls_gcm_free(&gcm);
	mbedtls_ecp_point_free(&ephemeral_pk);
	mbedtls_ecp_point_free(&dh);
	return ret;
}

static quoted_td_key_response_t *recv_response(int client) {
	quoted_td_key_response_t response_part;
	if (recv(client, &response_part, sizeof(quoted_td_key_response_t), MSG_WAITALL) !=
	    sizeof(quoted_td_key_response_t)) {
		trace("Could not recv quoted_td_key_response: %s\n", strerror(errno));
		return NULL;
	}

	if (!is_quote_well_formed(&response_part.quote)) {
		trace("Quote is ill-formed\n");
		return NULL;
	}

	trace("Got quote version %d\n", response_part.quote.header.version);

	quoted_td_key_response_t *response =
	    malloc(sizeof(quoted_td_key_response_t) + response_part.quote.signature_data_len);

	if (!response) {
		trace("Could not malloc for quoted_td_key_response\n");
		return NULL;
	}

	memcpy(response, &response_part, sizeof(quoted_td_key_response_t));

	trace("Receiving %d bytes of quote signature...\n", response_part.quote.signature_data_len);
	if (recv(client, (uint8_t *)response + sizeof(quoted_td_key_response_t),
	         response_part.quote.signature_data_len,
	         MSG_WAITALL) != response_part.quote.signature_data_len) {
		trace("Could not recv quote signature: %s\n", strerror(errno));
		free(response);
		return NULL;
	}

	trace("Received %d bytes of quote signature\n", response_part.quote.signature_data_len);

	return response;
}

static int compare_masked(sgx_report2_t *first, sgx_report2_t *second,
                          td_key_request_mask_t *mask) {
	sgx_report2_t first_masked;
	sgx_report2_t second_masked;
	memcpy(&first_masked, first, sizeof(sgx_report2_t));
	memcpy(&second_masked, second, sizeof(sgx_report2_t));
	apply_mask(&first_masked, mask);
	apply_mask(&second_masked, mask);
	return memcmp(&first_masked, &second_masked, sizeof(sgx_report2_t));
}

int get_sk(uint8_t sk[32], const char *key_request_mask_hex, const char *vault_mrenclave_hex) {
	int ret = -1;
	int sock = -1;

	ecc_context ctx;
	if ((ret = init_ecc_context(&ctx)) != 0) {
		trace("init_ecc_context failed: %d\n", ret);
		goto cleanup;
	}

	td_key_request_t key_request;
	if ((ret = read_hex(key_request_mask_hex, (uint8_t *)&key_request.mask,
	                    sizeof(td_key_request_mask_t))) != 0) {
		trace("Could not read key request mask %s: %d\n", key_request_mask_hex, ret);
		goto cleanup;
	}

	sgx_measurement_t mr_enclave;
	if ((ret = read_hex(vault_mrenclave_hex, (uint8_t *)&mr_enclave,
	                    sizeof(sgx_measurement_t))) != 0) {
		trace("Could not read vault mr_enclave %s: %d\n", vault_mrenclave_hex, ret);
		goto cleanup;
	}

	mbedtls_x509_crt root_crt;
	mbedtls_x509_crt_init(&root_crt);
	if ((ret = mbedtls_x509_crt_parse_file(&root_crt, ROOT_PEM_PATH)) != 0) {
		trace("Could not load root certificate %s: %d\n", ROOT_PEM_PATH, ret);
		goto cleanup;
	}

	sock = init_socket(PORT);
	if (sock < 0) {
		trace("init_socket(%d) failed: %d\n", PORT, sock);
		goto cleanup;
	}

	bool got_sk = false;
	while (!got_sk) {
		trace("Waiting for a connection...\n");
		int client = accept(sock, NULL, NULL);
		if (client < 0) {
			trace("accept failed: %d\n", client);
			continue;
		}

		mbedtls_mpi ephemeral_sk;
		quoted_td_key_response_t *response = NULL;

		mbedtls_mpi_init(&ephemeral_sk);

		tdx_report_data_t report_data = {0};
		if ((ret = gen_report_data(&ctx, &ephemeral_sk, &report_data)) != 0) {
			trace("gen_report_data failed: %d\n", ret);
			goto cleanup_iteration;
		}

		if ((ret =
		         tdx_att_get_report(&report_data, (tdx_report_t *)&key_request.tdreport)) !=
		    TDX_ATTEST_SUCCESS) {
			trace("tdx_att_get_report failed: %d\n", ret);
			goto cleanup_iteration;
		}

		trace("Sending key request...\n");
		send(client, &key_request, sizeof(td_key_request_t), MSG_NOSIGNAL);

		response = recv_response(client);
		if (!response) {
			trace("recv_response failed\n");
			goto cleanup_iteration;
		}

		if (memcmp(&(response->msg.mask), &key_request.mask,
		           sizeof(td_key_request_mask_t)) != 0) {
			trace("Masks do not match\n");
			goto cleanup_iteration;
		}

		if (compare_masked(&(response->msg.tdreport), &key_request.tdreport,
		                   &key_request.mask) != 0) {
			trace("Masked reports do not match\n");
			goto cleanup_iteration;
		}

		if (memcmp(&(response->quote.report_body.mr_enclave), &mr_enclave,
		           sizeof(sgx_measurement_t)) != 0) {
			trace("Wrong mr_enclave\n");
			goto cleanup_iteration;
		}

		if ((ret = verify_quote(&(response->quote), &root_crt)) != 0) {
			trace("Invalid quote: %d\n", ret);
			goto cleanup_iteration;
		}

		unsigned char msg_hash[32];
		if ((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		                      (const unsigned char *)&(response->msg),
		                      sizeof(response->msg), msg_hash)) != 0) {
			trace("mbedtls_md failed: %d\n", ret);
			goto cleanup_iteration;
		}

		if (memcmp(&(response->quote.report_body.report_data), msg_hash,
		           sizeof(msg_hash)) != 0) {
			trace("Quote report data does not contain message hash\n");
			goto cleanup_iteration;
		}

		if ((ret = decrypt_sk(&ctx, &ephemeral_sk, response->msg.ciphertext, sk)) != 0) {
			trace("decrypt_sk failed: %d\n", ret);
			goto cleanup_iteration;
		}

		got_sk = true;
		trace("Successfully got the secret key\n");

	cleanup_iteration:
		mbedtls_mpi_free(&ephemeral_sk);
		if (response) {
			free(response);
		}
		close(client);
	}

	tdx_report_data_t report_data = {0};
	if ((ret = mk_report_data(&ctx, sk, &report_data)) != 0) {
		trace("mk_report_data failed: %d\n", ret);
		goto cleanup;
	}

	if ((ret = tdx_att_get_report(&report_data, (tdx_report_t *)&key_request.tdreport)) !=
	    TDX_ATTEST_SUCCESS) {
		trace("tdx_att_get_report failed: %d\n", ret);
		goto cleanup;
	}

	tdx_uuid_t selected_att_key_id = {0};
	uint8_t *p_quote_buf = NULL;
	uint32_t quote_size = 0;
	if ((ret = tdx_att_get_quote(&report_data, NULL, 0, &selected_att_key_id, &p_quote_buf,
	                             &quote_size, 0)) != TDX_ATTEST_SUCCESS) {
		trace("tdx_att_get_quote failed: %d\n", ret);
		goto cleanup;
	}

	if ((ret = write_hex_to_file("/var/data/quote.txt", p_quote_buf, quote_size))) {
		trace("write_hex_to_file failed: %d\n", ret);
		goto cleanup;
	}

	ret = 0;
cleanup:
	if (sock >= 0) {
		close(sock);
	}
	mbedtls_x509_crt_free(&root_crt);
	free_ecc_context(&ctx);
	return ret;
}

#endif
