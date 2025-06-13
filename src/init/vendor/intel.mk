INTEL_DEB_BASE_URL := https://ppa.launchpadcontent.net/kobuk-team/tdx-attestation-release/ubuntu/pool/main

INTEL_DEB_URLS := \
  $(INTEL_DEB_BASE_URL)/l/linux-sgx/sgx-sdk_2.23.100.2-0ubuntu2.0_amd64.deb \
  $(INTEL_DEB_BASE_URL)/s/sgx-dcap/libtdx-attest-dev_1.21-0ubuntu3.1_amd64.deb \
  $(INTEL_DEB_BASE_URL)/s/sgx-dcap/libtdx-attest1_1.21-0ubuntu3.1_amd64.deb

INTEL_DEB_FILES := $(notdir $(INTEL_DEB_URLS))
INTEL_DEB_PATHS := $(addprefix $(VENDOR_DOWNLOADS_DIR)/,$(INTEL_DEB_FILES))

INTEL_STAMP := $(VENDOR_DIR)/.intel-built-stamp

.PHONY: intel
intel: $(INTEL_STAMP)

$(INTEL_STAMP): $(INTEL_DEB_PATHS)
	@mkdir -p $(VENDOR_OUT_DIR)
	@for deb in $^; do \
		dpkg-deb -x $$deb $(VENDOR_OUT_DIR); \
	done
	@touch $@

$(foreach url,$(INTEL_DEB_URLS),$(eval $(call make-download-rule,$(url))))
