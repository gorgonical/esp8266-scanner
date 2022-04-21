#ifndef _TYPES_H
#define _TYPES_H

#define CART_SIZE 98
#define BYTES_PER_CART ( sizeof(unsigned int) * CART_SIZE )
#define CHUNK_SIZE_BYTES 100

typedef struct cart {
    unsigned int       user_id;
    unsigned int       security_policy;
    unsigned int       code[CART_SIZE];
} cart_t;

#define CHUNKS_PER_CART ( ( sizeof(cart_t) / CHUNK_SIZE_BYTES) )

typedef struct cart_chunk {
    unsigned char buf[CHUNK_SIZE_BYTES];
} cart_chunk_t;

typedef struct chunked_cart {
    cart_chunk_t chunks[CHUNKS_PER_CART];
} chunked_cart_t;

typedef struct chunk {
    unsigned char buf[128];
} encrypted_chunk_t;



typedef struct encrypted_cart {
    encrypted_chunk_t chunks[CHUNKS_PER_CART];
} enc_cart_t;

#endif /* _TYPES_H */
