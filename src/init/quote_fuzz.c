#include "quote.h"
#include <sgx_quote_3.h>
#include <stdlib.h>
#include <string.h>

// cppcheck-suppress unusedFunction
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
	if (len < sizeof(sgx_quote3_t)) {
		return 0;
	}

	mbedtls_x509_crt root_crt;
	mbedtls_x509_crt_init(&root_crt);

	const uint8_t root_crt_pem[] =
	    "-----BEGIN CERTIFICATE-----\n"
	    "MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw"
	    "aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv"
	    "cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ"
	    "BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG"
	    "A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0"
	    "aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT"
	    "AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7"
	    "1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB"
	    "uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ"
	    "MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50"
	    "ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV"
	    "Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI"
	    "KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg"
	    "AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n"
	    "-----END CERTIFICATE-----";

	int err = mbedtls_x509_crt_parse(&root_crt, root_crt_pem, sizeof root_crt_pem);
	if (err) {
		return 0;
	}

	sgx_quote3_t *quote = malloc(len);
	if (!quote) {
		return 0;
	}
	memcpy(quote, data, len);

	verify_quote(quote, len, &root_crt);
	free(quote);
	mbedtls_x509_crt_free(&root_crt);
	return 0;
}
