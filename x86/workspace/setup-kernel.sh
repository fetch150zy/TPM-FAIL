#!/usr/bin/bash

sudo insmod ../kernel/tpmttlcrb.ko
sudo insmod ../kernel/tpmttltis.ko
sudo ../client/tpmttl 2
sudo ../client/tpmttl 3 >> /dev/null

