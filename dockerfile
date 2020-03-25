from gcc:4.9

RUN apt-get update && apt-get install vim -y && apt-get install nmap -y

copy crypto_aead  /crypto_aead
copy crypto_hash  /crypto_hash

copy aes_aead  /aes_aead

workdir crypto_aead
