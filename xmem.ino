/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "bearssl_tools.h"

/* see brssl.h */
void *
xmalloc(size_t len)
{
	void *buf;

	if (len == 0) {
		return NULL;
	}
	buf = malloc(len);
	if (buf == NULL) {
		fprintf(stderr, "ERROR: could not allocate %lu byte(s)\n",
			(unsigned long)len);
		exit(EXIT_FAILURE);
	}
	return buf;
}

/* see brssl.h */
void
xfree(void *buf)
{
	if (buf != NULL) {
		free(buf);
	}
}

/* see brssl.h */
void *
xblobdup(const void *src, size_t len)
{
	void *buf;

	buf = xmalloc(len);
	memcpy(buf, src, len);
	return buf;
}

/* see brssl.h */
char *
xstrdup(const void *src)
{
    return (char*)xblobdup(src, strlen((const char*)src) + 1);
}

/* see brssl.h */
br_x509_pkey *
xpkeydup(const br_x509_pkey *pk)
{
	br_x509_pkey *pk2;

	pk2 = (br_x509_pkey*)xmalloc(sizeof *pk2);
	pk2->key_type = pk->key_type;
	switch (pk->key_type) {
	case BR_KEYTYPE_RSA:
      pk2->key.rsa.n = (unsigned char*)xblobdup(pk->key.rsa.n, pk->key.rsa.nlen);
		pk2->key.rsa.nlen = pk->key.rsa.nlen;
		pk2->key.rsa.e = (unsigned char*)xblobdup(pk->key.rsa.e, pk->key.rsa.elen);
		pk2->key.rsa.elen = pk->key.rsa.elen;
		break;
	case BR_KEYTYPE_EC:
		pk2->key.ec.curve = pk->key.ec.curve;
		pk2->key.ec.q = (unsigned char*)xblobdup(pk->key.ec.q, pk->key.ec.qlen);
		pk2->key.ec.qlen = pk->key.ec.qlen;
		break;
	default:
		fprintf(stderr, "Unknown public key type: %u\n",
			(unsigned)pk->key_type);
		exit(EXIT_FAILURE);
	}
	return pk2;
}

/* see brssl.h */
void
xfreepkey(br_x509_pkey *pk)
{
	if (pk != NULL) {
		switch (pk->key_type) {
		case BR_KEYTYPE_RSA:
			xfree(pk->key.rsa.n);
			xfree(pk->key.rsa.e);
			break;
		case BR_KEYTYPE_EC:
			xfree(pk->key.ec.q);
			break;
		default:
			fprintf(stderr, "Unknown public key type: %u\n",
				(unsigned)pk->key_type);
			exit(EXIT_FAILURE);
		}
		xfree(pk);
	}
}
