## TPM_FAIL

> Test on Kernel v6.8

```bash
cd x86 # or cd riscv
./tpm2-setup.sh
cd kernel
# for crb
sudo cat /proc/kallsyms | grep crb_send
vim tpmttlcrb.c # change the pcrb_send address
make
# for tis
sudo cat /proc/kallsyms | grep tpm_tcg_write_bytes
vim tpmttltis.c # change the ptpm_tcg_write_bytes address
make
# build client
cd ../client && make
cd ../workspace && chmod +x setup-kernel.sh && ./setup-kernel.sh
cd ECDSATPMKey && chmod +x gen_tpm.sh && ./gen_tpm.sh
# or
cd ECDSATPMKey && chmod +x gen_openssl.sh && ./gen_openssl.sh
chmod +x run.sh
seq 10000 | xargs -I -- ./run.sh
cat result.csv
```
