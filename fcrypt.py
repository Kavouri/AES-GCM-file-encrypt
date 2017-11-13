import json
import argparse
from base64 import b64encode 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms 
from cryptography.hazmat.primitives.ciphers import modes
from sys import argv
from os import urandom

ENCRYPT = 'encrypt'
DECRYPT = 'decrypt'
cipher = None
public_key = None
private_key = None
receiver_private = None
input_file = None
output_file = None
mode = None

def load_private_key(path):
  try: 
    with open(path) as key_file:
      return serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
      )
  except:
    print 'invalid private key, unable to read from file'
    exit(1)

def load_public_key(path):
  try:
    with open(path) as key_file:
      return serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
      )
  except:
    print 'invalid public key, unable to read from file'
    exit(1)

def encrypt_symmetric_key(key):
   return public_key.encrypt(
    key,
    padding.OAEP(
      mgf=padding.MGF1(hashes.SHA1()),
      algorithm=hashes.SHA1(),
      label=None
    )
  )

def decrypt_symmetric_key(encrypted_key):
  return private_key.decrypt(encrypted_key,
      padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
      )
    )


def generate_signature(data):
  return private_key.sign(
    data,
    padding.PSS(
      mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
  )

def verify_signature(signature, data):
  try:
    public_key.verify(
      signature,
      data,
      padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
      ),
      hashes.SHA256()
    )
  except:
    print 'unable to verify rsa signature'
    exit(1)

def generate_symmetric_cipher(key=None, iv=None):
  key = key or urandom(32)
  iv = iv or urandom(16)
  encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
  return {
     'key': key,
      'iv': iv,
      'encryptor': encryptor
  }

def encrypt():
  global output_file
  cipher = generate_symmetric_cipher()
  encryptor = cipher['encryptor']
  key = cipher['key']
  iv = cipher['iv']
  signature = generate_signature(input_file)
  encrypted_key = encrypt_symmetric_key(key)
  ciphertext = encryptor.update(input_file) + encryptor.finalize()
  to_write = {
    'encrypted_key': encrypted_key.encode('base64'),
    'signature': signature.encode('base64'),
    'iv': iv.encode('base64'),
    'tag': encryptor.tag.encode('base64'),
    'encrypted_data': ciphertext.encode('base64')
  }
  output_file.write(json.dumps(to_write))

def decrypt():
  data = json.loads(input_file)
  data = {k : v.decode('base64') for k,v in data.items()}
  decrypted_key = decrypt_symmetric_key(data['encrypted_key'])
  
  decryptor = Cipher(
      algorithms.AES(decrypted_key),
      modes.GCM(data['iv'], data['tag']),
      backend=default_backend()
  ).decryptor()
  
  #decrypt using the symmetric decryptor
  try:
    decrypted_data = decryptor.update(data['encrypted_data']) + decryptor.finalize()
  except:
    print 'Failed to decrypt data. Authenticity check failed'
    exit(1)

  verify_signature(data['signature'], decrypted_data)

  output_file.write(decrypted_data)

def handle_args():
  global mode
  assert argv[1] in ['-e', '-d'], "Invalid command line arguments. Muss specify either -e or -d flags"
  assert len(argv) == 6, "Must supply encrypt/decrypt, public key, private key, input file and output file"
  mode = ENCRYPT if argv[1] == '-e' else DECRYPT

if __name__ == '__main__':
  handle_args()
  #open & read input, open output file
  input_file = open(argv[4], 'rb').read()
  output_file = open(argv[5], 'wb')
  
  #handles different cases depending on -e or -d
  if mode == ENCRYPT:
    public_key = load_public_key(argv[2])
    private_key = load_private_key(argv[3])
    encrypt()
  else:
    public_key = load_public_key(argv[3])
    private_key = load_private_key(argv[2])
    decrypt()
    
