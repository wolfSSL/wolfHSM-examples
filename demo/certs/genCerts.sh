#!/bin/bash

# ECC Keys
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out alice-ecc256-key.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out bob-ecc256-key.pem
openssl ec -in alice-ecc256-key.pem -outform DER -out alice-ecc256-key.der
openssl ec -in bob-ecc256-key.pem -outform DER -out bob-ecc256-key.der

# RSA Key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-2048-key.pem
openssl rsa -in rsa-2048-key.pem -outform DER -out rsa-2048-key.der

