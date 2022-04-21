#ifndef _SCANNER_H
#define _SCANNER_H

#include <ESP8266WiFi.h>
#include "types.h"
#include "bearssl_tools.h"

static void
vblob_append(void *cc, const void *data, size_t len);

void
free_pem_object_contents(pem_object *po);

pem_object *
decode_pem(const void *src, size_t len, size_t *num);

chunked_cart_t*
chunk_cart(cart_t* cart);

int
decrypt_cart(chunked_cart_t* out, enc_cart_t* cart, br_rsa_private_key* pkey);

unsigned int
encrypt_cart(enc_cart_t* out, chunked_cart_t* in, br_rsa_public_key* pub, unsigned int chunk_number);

size_t
read_encrypted_cart(char* filename, enc_cart_t* cart_p);

size_t
write_encrypted_cart(char* filename, enc_cart_t* cart_p);

static void
dn_append(void *ctx, const void *buf, size_t len);

void
print_hex(void* data, unsigned int n);

#endif /* _SCANNER_H */
