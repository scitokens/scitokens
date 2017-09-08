#!/bin/sh

# Simple way to generate a new EC keypair if you aren't using python.

openssl ecparam -name prime256v1 -genkey -noout -out $1
openssl ec -in sample_ecdsa_keypair.pem -pubout >> $1

