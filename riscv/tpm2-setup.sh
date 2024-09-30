#!/usr/bin/bash

# install tpm2_tools and tpm2_tss
# TODO

sudo tpm2_getcap properties-variable
sudo tpm2_getcap properties-fixed | grep -A11 TPM2_PT_VENDOR_STRING_1


