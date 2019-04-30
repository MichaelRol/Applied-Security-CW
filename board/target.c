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
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[out] r the destination octet string read
  * \return       the number of octets read
  */

int  _octetstr_rd(       uint8_t* r, int n_r, char* x ) {

  uint8_t len = AsciiToHex(x[0]) << 4 ^ AsciiToHex(x[1]);
  if(len > n_r) {
    return -1;
  }

  uint8_t colon =  x[2];
  if(colon != 0x3A) {
    return -1;
  }

  for(int i = 0; i < len; ++i){
    r[i] = AsciiToHex(x[i+3]) << 4 ^ AsciiToHex(x[i+4]);
  }

  return len;
}

int  octetstr_rd( uint8_t* r, int n_r          ) {
  char x[ 2 + 1 + 2 * ( n_r ) + 1 ]; // 2-char length, 1-char colon, 2*n_r-char data, 1-char terminator

  for( int i = 0; true; i++ ) {
    x[ i ] = scale_uart_rd( SCALE_UART_MODE_BLOCKING );

    if( x[ i ] == '\x0D' ) {
      x[ i ] = '\x00'; break;
    }
  }

  return _octetstr_rd( r, n_r, x );
}
/** Write an octet string (or sequence of bytes) to   the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[in]  r the source      octet string written
  * \param[in]  n the number of octets written
  */
void octetstr_wr( const uint8_t* x, int n_x ) {
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
