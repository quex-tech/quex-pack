#include "types.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <tdx_attest.h>
#include <unistd.h>

#define PORT 24516
#define MASK_PATH "/etc/key_request_mask.bin"
#define VAULT_MRENCLAVE_PATH "/etc/vault_mrenclave.bin"

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

static int gen_td_report(ecc_context *ctx, mbedtls_mpi *ephemeral_sk, sgx_report2_t *report) {
	mbedtls_ecp_point ephemeral_pk;
	int ret = -1;
	mbedtls_ecp_point_init(&ephemeral_pk);
	if (mbedtls_ecp_gen_keypair(&(ctx->grp), ephemeral_sk, &ephemeral_pk,
	                            mbedtls_ctr_drbg_random, &(ctx->drbg)) != 0) {
		trace("mbedtls_ecp_gen_keypair failed\n");
		goto cleanup;
	}

	tdx_report_data_t report_data = {0};
	tdx_report_t tdx_report = {{0}};

	uint8_t ecp_point_binary[65];
	size_t olen;
	if ((ret = mbedtls_ecp_point_write_binary(
	         &(ctx->grp), &ephemeral_pk, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, ecp_point_binary,
	         sizeof(ecp_point_binary))) != 0) {
		trace("mbedtls_ecp_point_write_binary failed\n");
		goto cleanup;
	}

	memcpy(report_data.d, ecp_point_binary + 1, 64);
	if (tdx_att_get_report(&report_data, &tdx_report) != TDX_ATTEST_SUCCESS) {
		trace("tdx_att_get_report failed\n");
		goto cleanup;
	}
	memcpy(report, tdx_report.d, TDX_REPORT_SIZE);
	ret = 0;
cleanup:
	mbedtls_ecp_point_free(&ephemeral_pk);
	return ret;
}

static int decrypt_sk(ecc_context *ctx, mbedtls_mpi *ephemeral_sk, uint8_t ciphertext[QUEX_CT_LEN],
                      uint8_t sk[32]) {
	int ret = -1;
	uint8_t ephemeral_pk_bytes[65] = {0x04};
	uint8_t ikm[130];
	uint8_t symmetric_key[32];
	const unsigned char salt[] = "quex_salt";
	mbedtls_ecp_point ephemeral_pk;
	mbedtls_ecp_point dh;
	mbedtls_gcm_context gcm;

	mbedtls_ecp_point_init(&ephemeral_pk);
	mbedtls_ecp_point_init(&dh);
	mbedtls_gcm_init(&gcm);

	memcpy(ephemeral_pk_bytes + 1, ciphertext, 64);

	if ((ret = mbedtls_ecp_point_read_binary(&(ctx->grp), &ephemeral_pk, ephemeral_pk_bytes,
	                                         sizeof(ephemeral_pk_bytes))) != 0) {
		goto cleanup;
	}

	if ((ret = mbedtls_ecp_mul(&(ctx->grp), &dh, ephemeral_sk, &ephemeral_pk,
	                           mbedtls_ctr_drbg_random, &(ctx->drbg))) != 0) {
		goto cleanup;
	}

	size_t olen;
	if ((ret = mbedtls_ecp_point_write_binary(&(ctx->grp), &ephemeral_pk,
	                                          MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, ikm,
	                                          sizeof(ikm))) != 0) {
		goto cleanup;
	}
	if ((ret = mbedtls_ecp_point_write_binary(&(ctx->grp), &dh, MBEDTLS_ECP_PF_UNCOMPRESSED,
	                                          &olen, ikm + olen, sizeof(ikm) - olen)) != 0) {
		goto cleanup;
	}

	if ((ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt,
	                        9,                // salt
	                        ikm, sizeof(ikm), // ikm
	                        NULL, 0,          // info
	                        symmetric_key, 32 // okm
	                        )) != 0) {
		goto cleanup;
	}

	if ((ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, symmetric_key, 128)) != 0) {
		goto cleanup;
	}

	if ((ret = mbedtls_gcm_auth_decrypt(&gcm, 32, ciphertext + 64, 12, NULL, 0, ciphertext + 80,
	                                    16, ciphertext + 96, sk)) != 0) {
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

static bool is_sgx_quote_well_formed(sgx_quote3_t *quote) {
	if (quote->header.version != 3) {
		trace("Unsupported quote version %d\n", quote->header.version);
		return false;
	}

	if (quote->header.att_key_type != 2) {
		trace("Unsupported quote attestation key type %d\n", quote->header.att_key_type);
		return false;
	}

	if (quote->header.att_key_data_0 != 0) {
		trace("Unsupported quote attestation key data %x\n", quote->header.att_key_type);
		return false;
	}

	if (memcmp(quote->header.vendor_id,
	           (const uint8_t[]){0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A,
	                             0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07},
	           16) != 0) {
		trace("Unsupported quote vendor\n");
		return false;
	}

	if (quote->signature_data_len > 16384) {
		trace("Quote signature data length %d is too big\n", quote->signature_data_len);
		return false;
	}

	return true;
}

static quoted_td_key_response_t *recv_response(int client) {
	quoted_td_key_response_t response_part;
	if (recv(client, &response_part, sizeof(quoted_td_key_response_t), MSG_WAITALL) !=
	    sizeof(quoted_td_key_response_t)) {
		trace("Could not recv quoted_td_key_response: %s\n", strerror(errno));
		return NULL;
	}

	if (!is_sgx_quote_well_formed(&response_part.quote)) {
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

static void apply_mask(sgx_report2_t *report, td_key_request_mask_t *mask) {
	if (!(mask->reportmacstruct_mask & 1)) {
		memset(&(report->report_mac_struct.report_type), 0, 4);
	}
	if (!(mask->reportmacstruct_mask & (1 << 1))) {
		memset(&(report->report_mac_struct.reserved1), 0, 12);
	}
	if (!(mask->reportmacstruct_mask & (1 << 2))) {
		memset(&(report->report_mac_struct.cpu_svn), 0, 16);
	}
	if (!(mask->reportmacstruct_mask & (1 << 3))) {
		memset(&(report->report_mac_struct.tee_tcb_info_hash), 0, 48);
	}
	if (!(mask->reportmacstruct_mask & (1 << 4))) {
		memset(&(report->report_mac_struct.tee_info_hash), 0, 48);
	}
	if (!(mask->reportmacstruct_mask & (1 << 5))) {
		memset(&(report->report_mac_struct.report_data), 0, 64);
	}
	if (!(mask->reportmacstruct_mask & (1 << 6))) {
		memset(&(report->report_mac_struct.reserved2), 0, 32);
	}
	if (!(mask->reportmacstruct_mask & (1 << 7))) {
		memset(&(report->report_mac_struct.mac), 0, 32);
	}

	if (!(mask->tee_tcb_info_mask & 1)) {
		memset(&(report->tee_tcb_info), 0, 8);
	}
	if (!((mask->tee_tcb_info_mask >> 1) & 1)) {
		memset(&(report->tee_tcb_info), 8, 16);
	}
	if (!((mask->tee_tcb_info_mask >> 2) & 1)) {
		memset(&(report->tee_tcb_info), 24, 48);
	}
	if (!((mask->tee_tcb_info_mask >> 3) & 1)) {
		memset(&(report->tee_tcb_info), 72, 48);
	}
	if (!((mask->tee_tcb_info_mask >> 4) & 1)) {
		memset(&(report->tee_tcb_info), 120, 8);
	}
	if (!((mask->tee_tcb_info_mask >> 5) & 1)) {
		memset(&(report->tee_tcb_info), 128, 1);
	}
	if (!((mask->tee_tcb_info_mask >> 6) & 1)) {
		memset(&(report->tee_tcb_info), 129, 1);
	}
	if (!((mask->tee_tcb_info_mask >> 7) & 1)) {
		memset(&(report->tee_tcb_info), 130, 1);
	}
	if (!((mask->tee_tcb_info_mask >> 8) & 1)) {
		memset(&(report->tee_tcb_info), 131, 13);
	}
	if (!((mask->tee_tcb_info_mask >> 9) & 1)) {
		memset(&(report->tee_tcb_info), 144, 95);
	}

	if (!(mask->reserved_mask & 1)) {
		memset(&(report->reserved), 0, SGX_REPORT2_RESERVED_BYTES);
	}

	if (!(mask->tdinfo_base_mask & 1)) {
		memset(&(report->tee_info), 0, 8);
	}
	if (!((mask->tdinfo_base_mask >> 1) & 1)) {
		memset(&(report->tee_info), 8, 8);
	}
	if (!((mask->tdinfo_base_mask >> 2) & 1)) {
		memset(&(report->tee_info), 16, 48);
	}
	if (!((mask->tdinfo_base_mask >> 3) & 1)) {
		memset(&(report->tee_info), 64, 48);
	}
	if (!((mask->tdinfo_base_mask >> 4) & 1)) {
		memset(&(report->tee_info), 112, 48);
	}
	if (!((mask->tdinfo_base_mask >> 5) & 1)) {
		memset(&(report->tee_info), 160, 48);
	}
	if (!((mask->tdinfo_base_mask >> 6) & 1)) {
		memset(&(report->tee_info), 208, 48);
	}
	if (!((mask->tdinfo_base_mask >> 7) & 1)) {
		memset(&(report->tee_info), 256, 48);
	}
	if (!((mask->tdinfo_base_mask >> 8) & 1)) {
		memset(&(report->tee_info), 304, 48);
	}
	if (!((mask->tdinfo_base_mask >> 9) & 1)) {
		memset(&(report->tee_info), 352, 48);
	}
	if (!((mask->tdinfo_base_mask >> 10) & 1)) {
		memset(&(report->tee_info), 400, 48);
	}
	if (!(mask->tdinfo_extension_mask & 1)) {
		memset(&(report->tee_info), 448, 64);
	}
}

int compare_masked(sgx_report2_t *first, sgx_report2_t *second, td_key_request_mask_t *mask) {
	sgx_report2_t first_masked;
	sgx_report2_t second_masked;
	memcpy(&first_masked, first, sizeof(sgx_report2_t));
	memcpy(&second_masked, second, sizeof(sgx_report2_t));
	apply_mask(&first_masked, mask);
	apply_mask(&second_masked, mask);
	return memcmp(&first_masked, &second_masked, sizeof(sgx_report2_t));
}

static int get_sk(uint8_t sk[32]) {
	int ret = -1;
	int sock = -1;

	ecc_context ctx;
	if (init_ecc_context(&ctx) != 0) {
		trace("init_ecc_context failed\n");
		goto cleanup;
	}

	td_key_request_t key_request;
	if (load_binary(MASK_PATH, &key_request.mask, sizeof(td_key_request_mask_t)) != 0) {
		trace("Could not load %s\n", MASK_PATH);
		goto cleanup;
	}

	sgx_measurement_t mr_enclave;
	if (load_binary(VAULT_MRENCLAVE_PATH, &mr_enclave, sizeof(sgx_measurement_t)) != 0) {
		trace("Could not load %s\n", VAULT_MRENCLAVE_PATH);
		goto cleanup;
	}

	sock = init_socket(PORT);
	if (sock < 0) {
		trace("init_socket(%d) failed\n", PORT);
		goto cleanup;
	}

	bool got_sk = false;
	while (!got_sk) {
		trace("Waiting for a connection...\n");
		int client = accept(sock, NULL, NULL);
		if (client < 0) {
			trace("accept failed\n");
			continue;
		}

		mbedtls_mpi ephemeral_sk;
		mbedtls_mpi_init(&ephemeral_sk);
		quoted_td_key_response_t *response = NULL;

		if (gen_td_report(&ctx, &ephemeral_sk, &key_request.tdreport) != 0) {
			trace("gen_td_report failed\n");
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

		// todo verify SGX quote and report data

		if (decrypt_sk(&ctx, &ephemeral_sk, response->msg.ciphertext, sk) != 0) {
			trace("decrypt_sk failed\n");
			goto cleanup_iteration;
		}
		got_sk = true;
		trace("Successfully got the private key\n");

	cleanup_iteration:
		mbedtls_mpi_free(&ephemeral_sk);
		if (response) {
			free(response);
		}
		close(client);
	}

	ret = 0;
cleanup:
	if (sock >= 0) {
		close(sock);
	}
	free_ecc_context(&ctx);
	return ret;
}

int main(void) {
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mount("none", "/proc", "proc", 0, NULL);
	mount("none", "/sys", "sysfs", 0, NULL);
	mount("none", "/sys/kernel/config", "configfs", 0, NULL);

	uint8_t sk[32];
	if (get_sk(sk) != 0) {
		exit(EXIT_FAILURE);
	}

	while (1) {
		pause();
	}

	return 0;
}
