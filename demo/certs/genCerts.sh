#!/bin/bash

# ECC Keys
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out alice-ecc256-key.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out bob-ecc256-key.pem
openssl ec -in alice-ecc256-key.pem -outform DER -out alice-ecc256-key.der
openssl ec -in bob-ecc256-key.pem -outform DER -out bob-ecc256-key.der


