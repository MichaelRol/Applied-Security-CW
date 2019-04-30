/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#ifndef __TARGET_H
#define __TARGET_H

#include <scale/scale.h>

#define COMMAND_INSPECT ( 0x00 )
#define COMMAND_ENCRYPT ( 0x01 )

#define SIZEOF_BLK      (   16 )
#define SIZEOF_KEY      (   16 )
#define SIZEOF_RND      (    0 )

typedef uint8_t aes_gf28_t;
typedef uint8_t gf28_k;

aes_gf28_t xtime(aes_gf28_t a);
aes_gf28_t sbox( aes_gf28_t a );
aes_gf28_t aes_gf28_inv ( aes_gf28_t a );
aes_gf28_t aes_gf28_mul ( aes_gf28_t a, aes_gf28_t b );
aes_gf28_t aes_gf28_add ( aes_gf28_t a, aes_gf28_t b );
void aes_enc_keyexp_step ( aes_gf28_t* r, const aes_gf28_t* rk , aes_gf28_t rc );
void aes_enc_rnd_key( aes_gf28_t* s, aes_gf28_t* rk );
void aes_enc_rnd_sub( aes_gf28_t* s );
void aes_enc_rnd_mix( aes_gf28_t* m );
void aes_enc_rnd_row( aes_gf28_t* m );
void aes     ( uint8_t* c, const uint8_t* m, const uint8_t* k, const uint8_t* r );

#endif
