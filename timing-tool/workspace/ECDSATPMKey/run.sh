#!/usr/bin/bash

# 刷新所有的瞬态对象
sudo tpm2_flushcontext --transient-object
# 读取记录到时间数据
sudo ../../client/tpmttl 3 >> /dev/null
# 签名
sudo tpm2_sign -Q -c key.ctx -g sha256 -d data.in.digest -f plain -o data.out.signed >> /dev/null
# 验证签名
openssl dgst -verify ecdsa.pub.pem -keyform pem -sha256 -signature data.out.signed data.in.raw | tr "\n" , >> result.csv
# 解析并提取签名的ASN.1信息
openssl asn1parse -dump -inform der -in data.out.signed  | tail -n 2 | awk -F ":" '{print $NF}' | tr '\n' , >> result.csv
# 读取记录到时间数据
sudo ../../client/tpmttl 3 >> result.csv
