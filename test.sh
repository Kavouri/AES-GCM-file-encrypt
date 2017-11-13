#!/bin/bash

# Simple test for fcrypt (CS 4740/6740: Network Security)
# Amirali Sanatinia (amirali@ccs.neu.edu)

python fcrypt.py -e dest.pub sender.pem input_plaintext_file ciphertext_file
python fcrypt.py -d dest.pem sender.pub ciphertext_file output_plaintext_file

if ! diff -q input_plaintext_file output_plaintext_file > /dev/null ; then
  echo "FAIL"
  else echo "PASS!"
fi


