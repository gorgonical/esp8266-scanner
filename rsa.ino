#include <stdio.h>
// #include <bearssl.h>
// #include <bearssl_rsa.h>
// #include <bearssl_x509.h>

#include "types.h"
#include "bearssl_tools.h"

br_rsa_public pub;
br_rsa_private priv;
br_pem_decoder_context pem_decoder;

static void
vblob_append(void *cc, const void *data, size_t len)
{
    bvector *bv;

    bv = (bvector*)cc;
    VEC_ADDMANY(*bv, (unsigned char*)data, len);
}

/* see brssl.h */
void
free_pem_object_contents(pem_object *po)
{
    if (po != NULL) {
        xfree(po->name);
        xfree(po->data);
    }
}


pem_object *
decode_pem(const void *src, size_t len, size_t *num)
{
    VECTOR(pem_object) pem_list = VEC_INIT;
    br_pem_decoder_context pc;
    pem_object po, *pos;
    const unsigned char *buf;
    bvector bv = VEC_INIT;
    int inobj;
    int extra_nl;

    *num = 0;
    br_pem_decoder_init(&pc);
    buf = (unsigned char*)src;
    inobj = 0;
    po.name = NULL;
    po.data = NULL;
    po.data_len = 0;
    extra_nl = 1;
    while (len > 0) {
        size_t tlen;

        tlen = br_pem_decoder_push(&pc, buf, len);
        buf += tlen;
        len -= tlen;
        switch (br_pem_decoder_event(&pc)) {

        case BR_PEM_BEGIN_OBJ:
            po.name = xstrdup(br_pem_decoder_name(&pc));
            br_pem_decoder_setdest(&pc, vblob_append, &bv);
            inobj = 1;
            break;

        case BR_PEM_END_OBJ:
            if (inobj) {
                po.data = (unsigned char*)VEC_TOARRAY(bv);
                po.data_len = VEC_LEN(bv);
                VEC_ADD(pem_list, po);
                VEC_CLEAR(bv);
                po.name = NULL;
                po.data = NULL;
                po.data_len = 0;
                inobj = 0;
            }
            break;

        case BR_PEM_ERROR:
            xfree(po.name);
            VEC_CLEAR(bv);
            fprintf(stderr,
                    "ERROR: invalid PEM encoding\n");
            VEC_CLEAREXT(pem_list, &free_pem_object_contents);
            return NULL;
        }

        /*
         * We add an extra newline at the end, in order to
         * support PEM files that lack the newline on their last
         * line (this is somwehat invalid, but PEM format is not
         * standardised and such files do exist in the wild, so
         * we'd better accept them).
         */
        if (len == 0 && extra_nl) {
            extra_nl = 0;
            buf = (const unsigned char *)"\n";
            len = 1;
        }
    }
    if (inobj) {
        fprintf(stderr, "ERROR: unfinished PEM object\n");
        xfree(po.name);
        VEC_CLEAR(bv);
        VEC_CLEAREXT(pem_list, &free_pem_object_contents);
        return NULL;
    }

    *num = VEC_LEN(pem_list);
    VEC_ADD(pem_list, po);
    pos = VEC_TOARRAY(pem_list);
    VEC_CLEAR(pem_list);
    return pos;
}

chunked_cart_t*
chunk_cart(cart_t* cart)
{
    return (chunked_cart_t*)cart;
}

unsigned int
encrypt_cart(enc_cart_t* out, chunked_cart_t* in, br_rsa_public_key* pubkey)
{
    unsigned int ret = 0;
    unsigned int i   = 0;
    /* Encrypt cart */
    for (i = 0; i < CHUNKS_PER_CART; i++)
    {
        cart_chunk_t*      raw_chunk = &(in->chunks[i]);
        encrypted_chunk_t* enc_chunk = &(out->chunks[i]);

        memcpy(enc_chunk, raw_chunk, sizeof(cart_chunk_t));

        if (!pub((unsigned char*)&(enc_chunk->buf), 128, pubkey))
        {
            printf("Could not encrypt chunk #%u\n", i);
            ret |= 1;
        }
    }

    return ret;
}

int
decrypt_cart(chunked_cart_t* out, enc_cart_t* cart, br_rsa_private_key* pkey)
{
    unsigned int ret = 0;
    unsigned int i = 0;
    unsigned char buf[128];
    for (i = 0; i < CHUNKS_PER_CART; i++)
    {
        memcpy(buf, &cart->chunks[i], sizeof(encrypted_chunk_t));
        if (!priv(buf, pkey))
        {
            printf("Could not decrypt chunk #%u\n", i);
            ret = 1;
        }
        else
        {
            memcpy(&out->chunks[i], buf, sizeof(cart_chunk_t));
        }
    }
    return ret;
}

/* Does not allocate memory */
size_t
read_encrypted_cart(char* filename, enc_cart_t* cart_p)
{
    FILE* fptr = NULL;
    size_t read = 0;

    fptr = fopen(filename, "r");

    read = fread((unsigned char*)cart_p, 1, sizeof(enc_cart_t), fptr);
    printf("Bytes read: %u\n", read);

    fclose(fptr);

    return read;
}

size_t
write_encrypted_cart(char* filename, enc_cart_t* cart_p)
{
    FILE* fptr;
    size_t written = 0;

    fptr = fopen(filename, "w");

    written = fwrite((unsigned char*)cart_p, 1, sizeof(enc_cart_t), fptr);

    printf("Bytes written: %u\n", written);

    fclose(fptr);

    return written;
}

void
print_chunk(encrypted_chunk_t* chunk, unsigned int n)
{
    unsigned int i = 0;
    unsigned char* byte = (unsigned char*)chunk;
    for (i = 0; i < n; i++, byte++)
    {
        if (i != 0 && i % 16 == 0)
        {
            printf("\n");
        }
        printf("%02X", *byte);
    }
    printf("\n\n");
}

void
print_hex(void* data, unsigned int n)
{
    unsigned int i = 0;
    unsigned char* byte = data;
    for (i = 0; i < n; i++, byte++)
    {
        if (i != 0 && i % 16 == 0)
        {
            printf("\n");
        }
        printf("%02X", *byte);
    }
    printf("\n\n");
}

static void
dn_append(void *ctx, const void *buf, size_t len)
{
    VEC_ADDMANY(*(bvector *)ctx, buf, len);
}

// int
// main(int argc, char** argv)
// {

//     br_x509_pkey *pk = NULL;
//     cart_t  cart;
//     cart_t* file_cart;
//     chunked_cart_t* chunked = NULL;
//     chunked_cart_t  file_chunked_cart;
//     unsigned int i;

//     char * filename = "/home/nmg/testfile";

//     enc_cart_t encrypted_cart;
//     enc_cart_t file_encrypted_cart;

//     pem_object* pems = NULL;
//     size_t num_pems  = 0;

//     pems = decode_pem(cert2, strlen(cert2), &num_pems);
//     for (i = 0; i < num_pems; i++)
//     {
//         printf("PEM: Name %s\n", pems[i].name);
//         br_x509_certificate     cert;
//         br_x509_decoder_context dc;
//         bvector                 vdn = VEC_INIT;

//         cert.data     = pems[i].data;
//         cert.data_len = pems[i].data_len;

//         br_x509_decoder_init(&dc, dn_append, &vdn);
//         br_x509_decoder_push(&dc, cert.data, cert.data_len);

//         pk = br_x509_decoder_get_pkey(&dc);
//     }

//     memset(&file_encrypted_cart, 0, sizeof(enc_cart_t));
//     memset(&encrypted_cart, 0, sizeof(enc_cart_t));

//     pub = &br_rsa_i31_public;
//     priv = &br_rsa_i31_private;

//     read_encrypted_cart(filename, &file_encrypted_cart);
//     decrypt_cart(&file_chunked_cart, &file_encrypted_cart);

//     file_cart = (cart_t*)&file_chunked_cart;

//     printf("Populating cart...\n");
//     cart.user_id         = 8642;
//     cart.security_policy = 10000;
//     for (i = 0; i < CART_SIZE; i++)
//     {
//         cart.code[i] = 128 * (i+1);
//         printf("Code #%u: Old: %u\t\t%u\n", i, file_cart->code[i], cart.code[i]);
//     }

//     chunked = chunk_cart(&cart);
//     printf("cart size chunked size %u %u\n", sizeof(cart_t), sizeof(chunked_cart_t));
//     printf("chunks per cart %u\n", CHUNKS_PER_CART);



//     for (i = 0; i < CHUNKS_PER_CART; i++)
//     {
//         printf("Chunk #%u\n", i);
//         printf("Clear\n");
//         print_hex(&chunked->chunks[i], 100);
//         printf("File clear\n");
//         print_hex(&file_chunked_cart.chunks[i], 100);
//         printf("Just encrypted\n");
//         print_hex(&encrypted_cart.chunks[i], 128);
//         printf("File encrypted\n");
//         print_hex(&file_encrypted_cart.chunks[i], 128);
//         if (memcmp(&encrypted_cart.chunks[i], &file_encrypted_cart.chunks[i], sizeof(encrypted_chunk_t)))
//         {
//             printf("Encrypted chunks #%u are not the same\n", i);
//         }
//     }

//     if (memcmp(&encrypted_cart, &file_encrypted_cart, sizeof(enc_cart_t)))
//     {
//         printf("Carts are not the same\n");
//     }

//     write_encrypted_cart("/home/nmg/testfile", &encrypted_cart);

//     return 0;
// }


