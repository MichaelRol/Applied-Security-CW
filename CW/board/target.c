/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "target.h"
uint8_t AsciiToHex(uint8_t char){
  switch(char){
    case '0': {
      return 0x00;
    }
    case '1': {
      return 0x01;
    }
    case '2': {
      return 0x02;
    }
    case '3': {
      return 0x03;
    }
    case '4': {
      return 0x04;
    }
    case '5': {
      return 0x05;
    }
    case '6': {
      return 0x06;
    }
    case '7': {
      return 0x07;
    }
    case '8': {
      return 0x08;
    }
    case '9': {
      return 0x09;
    }
    case 'A': {
      return 0x0A;
    }
    case 'a': {
      return 0x0A;
    }
    case 'B': {
      return 0x0B;
    }
    case 'b': {
      return 0x0B;
    }
    case 'C': {
      return 0x0C;
    }
    case 'c': {
      return 0x0C;
    }
    case 'D': {
      return 0x0D;
    }
    case 'd': {
      return 0x0D;
    }
    case 'E': {
      return 0x0E;
    }
    case 'e': {
      return 0x0E;
    }
    case 'F': {
      return 0x0F;
    }
    case 'f': {
      return 0x0F;
    }
    default: {
      return 0x00;
    }
  }
}

uint8_t HexToAscii(uint8_t hex){
  switch(hex){
    case 0x00: {
      return '0';
    }
    case 0x01: {
      return '1';
    }
    case 0x02: {
      return '2';
    }
    case 0x03: {
      return '3';
    }
    case 0x04: {
      return '4';
    }
    case 0x05: {
      return '5';
    }
    case 0x06: {
      return '6';
    }
    case 0x07: {
      return '7';
    }
    case 0x08: {
      return '8';
    }
    case 0x09: {
      return '9';
    }
    case 0x0A: {
      return 'A';
    }
    case 0x0B: {
      return 'B';
    }
    case 0x0C: {
      return 'C';
    }
    case 0x0D: {
      return 'D';
    }
    case 0x0E: {
      return 'E';
    }
    case 0x0F: {
      return 'F';
    }
    default: {
      return 'N';
    }
  }
}
/** Read  an octet string (or sequence of bytes) from the UART, using a simple
  * len-prefixed, little-endian hexadecimal format.
  *
  * \param[out] r the destination octet string read
  * \return       the number of octets read
  */

int  octetstr_rd(       uint8_t* r, int n_r ) {
  uint8_t char1 =  scale_uart_rd( SCALE_UART_MODE_BLOCKING );
  uint8_t char2 =  scale_uart_rd( SCALE_UART_MODE_BLOCKING );

  uint8_t len = AsciiToHex(char1)<<4 ^ AsciiToHex(char2);
  if(len > n_r) {
    return -1;
  }

  uint8_t colon =  scale_uart_rd( SCALE_UART_MODE_BLOCKING );
  if(colon != 0x3A) {
    return -1;
  }

  for(int i = 0; i < len; ++i){
    uint8_t first =  scale_uart_rd( SCALE_UART_MODE_BLOCKING );
    uint8_t second =  scale_uart_rd( SCALE_UART_MODE_BLOCKING );

    r[i] = AsciiToHex(first) << 4 ^ AsciiToHex(second);
  }
  scale_uart_rd( SCALE_UART_MODE_BLOCKING );

  return len;
}

/** Write an octet string (or sequence of bytes) to   the UART, using a simple
  * len-prefixed, little-endian hexadecimal format.
  *
  * \param[in]  r the source      octet string written
  * \param[in]  n the number of octets written
  */

void octetstr_wr( const uint8_t* x, int n_x ) {
  uint8_t len1 = HexToAscii((n_x >> 4) & 0x0F);
  uint8_t len2 = HexToAscii(n_x & 0x0F);
  scale_uart_wr( SCALE_UART_MODE_BLOCKING, len1 );
  scale_uart_wr( SCALE_UART_MODE_BLOCKING, len2 );
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, 0x3A );

  for(int i = 0; i<n_x; ++i){
    uint8_t char1 = HexToAscii((x[i]>>4)&0x0F);
    uint8_t char2 = HexToAscii(x[i]&0x0F);
    scale_uart_wr( SCALE_UART_MODE_BLOCKING, char1 );
    scale_uart_wr( SCALE_UART_MODE_BLOCKING, char2 );
  }
  scale_uart_wr( SCALE_UART_MODE_BLOCKING, 0x0D );
  scale_uart_wr( SCALE_UART_MODE_BLOCKING, 0x0A );

  return;
}


/** Initialise an AES-128 encryption, e.g., expand the cipher key k into round
  * keys, or perform randomised pre-computation in support of a countermeasure;
  * this can be left blank if no such initialisation is required, because the
  * same k and r will be passed as input to the encryption itself.
  *
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes_init(                               const uint8_t* k, const uint8_t* r ) {
  return;
}

/** Perform    an AES-128 encryption of a plaintext m under a cipher key k, to
  * yield the corresponding ciphertext c.
  *
  * \param[out] c   an   AES-128 ciphertext
  * \param[in]  m   an   AES-128 plaintext
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes     ( uint8_t* c, const uint8_t* m, const uint8_t* k, const uint8_t* r ) {

  aes_gf28_t* rkp = k;

  const aes_gf28_t RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
  memcpy(c, m, 16);
  aes_enc_rnd_key(c, k);
  for (int i = 1; i <= 9; i++) {
    aes_enc_rnd_sub( c );
    aes_enc_rnd_row( c );
    aes_enc_rnd_mix(c);
    aes_enc_keyexp_step ( rkp , rkp , RC[i-1] );
    aes_enc_rnd_key(c, rkp);
  }
  aes_enc_rnd_sub( c );
  aes_enc_rnd_row( c );
  aes_enc_keyexp_step ( rkp , rkp , RC[9] );
  aes_enc_rnd_key(c, rkp);

  return;
}

/** Initialise the SCALE development board, then loop indefinitely, reading a
  * command then processing it:
  *
  * 1. If command is inspect, then
  *
  *    - write the SIZEOF_BLK parameter,
  *      i.e., number of bytes in an  AES-128 plaintext  m, or ciphertext c,
  *      to the UART,
  *    - write the SIZEOF_KEY parameter,
  *      i.e., number of bytes in an  AES-128 cipher key k,
  *      to the UART,
  *    - write the SIZEOF_RND parameter,
  *      i.e., number of bytes in the         randomness r.
  *      to the UART.
  *
  * 2. If command is encrypt, then
  *
  *    - read  an   AES-128 plaintext  m from the UART,
  *    - read  some         randomness r from the UART,
  *    - initalise the encryption,
  *    - set the trigger signal to 1,
  *    - execute   the encryption, producing the ciphertext
  *
  *      c = AES-128.Enc( m, k )
  *
  *      using the hard-coded cipher key k plus randomness r if/when need be,
  *    - set the trigger signal to 0,
  *    - write an   AES-128 ciphertext c to   the UART.
  */

int main( int argc, char* argv[] ) {
  if( !scale_init( &SCALE_CONF ) ) {
    return -1;
  }

  uint8_t cmd[ 1 ], c[ SIZEOF_BLK ], m[ SIZEOF_BLK ], k[ SIZEOF_KEY ] = { 0x4B, 0x3A, 0xAA, 0xC9, 0x9B, 0xA4, 0x7C, 0x34, 0xA5, 0x0B, 0x99, 0xB5, 0xC8, 0x75, 0xDB, 0x94 }, r[ SIZEOF_RND ];

  while( true ) {
    if( 1 != octetstr_rd( cmd, 1 ) ) {
      break;
    }

    switch( cmd[ 0 ] ) {
      case COMMAND_INSPECT : {
        uint8_t t = SIZEOF_BLK;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_KEY;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_RND;
                    octetstr_wr( &t, 1 );

        break;
      }
      case COMMAND_ENCRYPT : {
        if( SIZEOF_BLK != octetstr_rd( m, SIZEOF_BLK ) ) {
          break;
        }
        if( SIZEOF_RND != octetstr_rd( r, SIZEOF_RND ) ) {
          break;
        }

        aes_init(       k, r );

        scale_gpio_wr( SCALE_GPIO_PIN_TRG,  true );
        aes     ( c, m, k, r );
        scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );

                          octetstr_wr( c, SIZEOF_BLK );

        break;
      }
      default : {
        break;
      }
    }
  }

  return 0;
}


void aes_enc_rnd_row( aes_gf28_t* m ) {

  aes_gf28_t hold[16];
  memcpy(hold, m, 16);
  m[1] = hold[5];
  m[5] = hold[9];
  m[9] = hold[13];
  m[13] = hold[1];

  m[2] = hold[10];
  m[6] = hold[14];
  m[10] = hold[2];
  m[14] = hold[6];

  m[3] = hold[15];
  m[7] = hold[3];
  m[11] = hold[7];
  m[15] = hold[11];

}

void aes_enc_rnd_mix( aes_gf28_t* m ) {

   aes_gf28_t s[16];
   memcpy(s, m, 16);
   for(int x = 0; x < 4; x++) {
     m[x*4] = s[x*4 + 3] ^ s[x*4 + 2] ^ xtime(s[x*4]) ^ s[x*4 + 1] ^ xtime(s[x*4 + 1]);
     m[x*4 + 1] = s[x*4 + 3] ^ s[x*4] ^ xtime(s[x*4 +  1]) ^ s[x*4 + 2] ^ xtime(s[x*4 + 2]);
     m[x*4 + 2] = s[x*4] ^ s[x*4 + 1] ^ xtime(s[x*4 + 2]) ^ s[x*4 + 3] ^ xtime(s[x*4 + 3]);
     m[x*4 + 3] = s[x*4 + 1]  ^ s[x*4 + 2] ^ xtime(s[x*4 + 3]) ^ s[x*4] ^ xtime(s[x*4]);
   }

}

void aes_enc_rnd_sub( aes_gf28_t* s ) {
  for (int x = 0; x < 16; x++) {
    s[x] = sbox(s[x]);
  }
}

void aes_enc_rnd_key( aes_gf28_t* s, aes_gf28_t* rk ) {
  for (int x = 0; x < 16; x++){
    s[x] = s[x] ^ rk[x];
  }
}

void aes_enc_keyexp_step ( aes_gf28_t* r, const aes_gf28_t* rk , aes_gf28_t rc ) {
  r[ 0 ] = rc ^ sbox ( rk[ 13 ] ) ^ rk[ 0 ];
  r[ 1 ] = sbox ( rk[ 14 ] ) ^ rk[ 1 ];
  r[ 2 ] = sbox ( rk[ 15 ] ) ^ rk[ 2 ];
  r[ 3 ] = sbox ( rk[ 12 ] ) ^ rk[ 3 ];
  r[ 4 ] = r[ 0 ] ^ rk[ 4 ];
  r[ 5 ] = r[ 1 ] ^ rk[ 5 ];
  r[ 6 ] = r[ 2 ] ^ rk[ 6 ];
  r[ 7 ] = r[ 3 ] ^ rk[ 7 ];

  r[ 8 ] = r[ 4 ] ^ rk[ 8 ];
  r[ 9 ] = r[ 5 ] ^ rk[ 9 ];
  r[ 10 ] = r[ 6 ] ^ rk[ 10 ];
  r[ 11 ] = r[ 7 ] ^ rk[ 11 ];

  r[ 12 ] = r[ 8 ] ^ rk[ 12 ];
  r[ 13 ] = r[ 9 ] ^ rk[ 13 ];
  r[ 14 ] = r[ 10 ] ^ rk[ 14 ];
  r[ 15 ] = r[ 11 ] ^ rk[ 15 ];
}

aes_gf28_t aes_gf28_add ( aes_gf28_t a, aes_gf28_t b ) {
  return a ^ b;
}

aes_gf28_t aes_gf28_mul ( aes_gf28_t a, aes_gf28_t b ) {
  aes_gf28_t t = 0;

  for (int i = 7; i >= 0; i--) {
    t = xtime(t);

    if (( b >> i ) & 1) {
      t ^= a;
    }
  }

  return t;
}
aes_gf28_t aes_gf28_inv ( aes_gf28_t a ) {
  aes_gf28_t t_0 = aes_gf28_mul ( a, a ); // a^2
  aes_gf28_t t_1 = aes_gf28_mul ( t_0 , a ); // a^3
             t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^4
             t_1 = aes_gf28_mul ( t_1 , t_0 ); // a^7
             t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^8
             t_0 = aes_gf28_mul ( t_1 , t_0 ); // a^15
             t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^30
             t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^60
             t_1 = aes_gf28_mul ( t_1 , t_0 ); // a^67
             t_0 = aes_gf28_mul ( t_0 , t_1 ); // a^127
             t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^254
  return t_0;
}

aes_gf28_t sbox( aes_gf28_t a ) {
  unsigned char s[256] =
 {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
 };
  aes_gf28_t x = a >> 4;
  aes_gf28_t y = 0x0F & a;
  // a = aes_gf28_inv(a);
  // a = ( 0x63 ) ^ // 0 1 1 0 0 0 1 1
  //   ( a ) ^ // a_7 a_6 a_5 a_4 a_3 a_2 a_1 a_0
  //   ( a << 1 ) ^ // a_6 a_5 a_4 a_3 a_2 a_1 a_0 0
  //   ( a << 2 ) ^ // a_5 a_4 a_3 a_2 a_1 a_0 0 0
  //   ( a << 3 ) ^ // a_4 a_3 a_2 a_1 a_0 0 0 0
  //   ( a << 4 ) ^ // a_3 a_2 a_1 a_0 0 0 0 0
  //   ( a >> 7 ) ^ // 0 0 0 0 0 0 0 a_7
  //   ( a >> 6 ) ^ // 0 0 0 0 0 0 a_7 a_6
  //   ( a >> 5 ) ^ // 0 0 0 0 0 a_7 a_6 a_5
  //   ( a >> 4 ) ; // 0 0 0 0 a_7 a_6 a_5 a_4

  return s[y + 16*x];
}

aes_gf28_t xtime( aes_gf28_t a ) {
  if ((a & 0x80) == 0x80) {
    return 0x1B ^ ( a << 1 );
  } else {
    return (a << 1);
  }
}
