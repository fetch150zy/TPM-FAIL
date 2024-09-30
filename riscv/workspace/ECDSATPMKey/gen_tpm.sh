#!/usr/bin/bash

rm -rf *.ctx
# 刷新所有的瞬态对象
sudo tpm2_flushcontext --transient-object
# 创建主密钥
sudo tpm2_createprimary -C o -G ecc -c prim.ctx
# 创建子密钥
sudo tpm2_create -C prim.ctx -G ecc256 -u ecdsa.pub -r ecdsa.priv 
# 再次刷新所有的瞬态对象
sudo tpm2_flushcontext --transient-object
# 加载密钥
sudo tpm2_load -C prim.ctx -u ecdsa.pub -r ecdsa.priv -c key.ctx
# 准备待签名的数据
echo "data to sign" > data.in.raw
# 计算数据摘要并创建digest结构
sha256sum data.in.raw | awk '{ print "000000 " $1 }' | xxd -r -c 32 > data.in.digest
# 再次刷新所有的瞬态对象
sudo tpm2_flushcontext --transient-object
# 使用TPM签名数据
sudo tpm2_sign -Q -c key.ctx -g sha256 -d data.in.digest -f plain -o data.out.signed
# 导出公钥
sudo tpm2_readpublic -c key.ctx -f pem -o ecdsa.pub.pem
# 使用OpenSSL验证签名
openssl dgst -verify ecdsa.pub.pem -keyform pem -sha256 -signature data.out.signed data.in.raw
