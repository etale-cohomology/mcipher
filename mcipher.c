/*
gcc-8 mcipher.c -o mcipher          &&  ./mcipher
gcc-8 mcipher.c -o mcipher  -Ofast  &&  ./mcipher
objdump mcipher -d -M intel
*/
#include <stdio.h>
#include <alloca.h>
#include <string.h>
#include <time.h>

// ----------------------------------------------------------------------------------------------------------------------------#  @blk1  libtype
#include <stdint.h>  // sexy types!
typedef int8_t    i8;
typedef int16_t   i16;
typedef int32_t   i32;
typedef int64_t   i64;

typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;

// ----------------------------------------------------------------------------------------------------------------------------# @blk1
#define m_fori(IDX, IDX_INI,IDX_END)  for(i32 (IDX)=(IDX_INI); (IDX)<(IDX_END); ++(IDX))  // Fastest `for` loop: signed yields a faster loop than unsigned because there's no need for overflow checks (or something), and i32 is faster than i64!
#define u4_to_asciihex(BIN)({         u8 _bin=BIN&0b1111;  (_bin<0xa) ? _bin+0x30 : _bin+0x57;  })  // Map: a  4-bit    uint  TO an asciihex digit
#define m_min(    A, B)               ({  typeof(A) _a=(A);  typeof(B) _b=(B);  _a<_b ?  _a : _b;  })  // @typeof() is useful w/ `statement expressions`. Here's how they can be used to define a safe macro which operates on any arithmetic type and `evaluates each of its arguments exactly once`
#define fmtu32hbe( _X)({              u32 _x=(u32) (_X); i32 _n=8*sizeof(u32)/4;  char* _d=alloca(_n);  m_fori(i, 0,_n)  _d[i]=u4_to_asciihex(_x>>(8*sizeof(u32) -4*(i+1)));  _d[_n]=0x00;  _d;  })  /*map a u32  asciihexbe (to ascii hex,  most-significant bit first)*/
#define m_array_idim(ARR)             (sizeof((ARR)) / sizeof((*(ARR))))

// ----------------------------------------------------------------------------------------------------------------------------# @blk1
#if 1
#define ADD(a,b)  ((a)+(b))                           // add  (out of place)
#define XOR(a,b)  ((a)^(b))                           // xor  (out of place)
#define RL( x,r)  (((x)<<(r)) | ((x)>>(32-(r))))      // rotl (out of place)
#define MOD(x,n)  (0<=(x) ? (x)%(n) : (n)+((x)%(n)))  // mod with number-theoretic wraparound (out of place)

// mcipher-08 (ie. based off a 0x08 x 0x08 u32 matrix)
// mcipher-10 (ie. based off a 0x10 x 0x10 u32 matrix)
// mcipher-20 (ie. based off a 0x20 x 0x20 u32 matrix)
// mcipher-40 (ie. based off a 0x40 x 0x40 u32 matrix)
#define N                0x20  // 0x04 0x08 0x10 0x20 0x40
#define MC_NROUNDS       0x400
#define MC_C_POS         0
#define MC_SK_POS        N
#define MC_NONCE_POS     N + N*N/2
#define MC_COUNTER_POS   N + N*N/2 + (N*N - N*N/2 - N)/2
#define MC_C_IDIM        N
#define MC_SK_IDIM       N*N/2
#define MC_NONCE_IDIM    (N*N - N*N/2 - N)/2
#define MC_COUNTER_IDIM  (N*N - N*N/2 - N)/2
char MC_CONSTANTS[512] = "In the beginning was the Word, and the Word was with God, and the Word was God. The same was in the beginning with God. All things were made by him; and without him was not any thing made that was made. In him was life; and the life was the light of men. And the light shineth in darkness; and the darkness comprehended it not. There was a man sent from God, whose name was John. The same came for a witness, to bear witness of the Light, that all men through him might believe. He was not that Light, but was se";

#define COLP(l)  MOD(l-N,N*N)                // prev col, @l is the LINEAR index (ie. RCOLS*row + col)
#define COLN(l)  MOD(l+N,N*N)                // next col, @l is the LINEAR index (ie. RCOLS*row + col)
#define ROWP(l)  (MOD(l-1,N) + (N*((l)/N)))  // prev row, @l is the LINEAR index (ie. RCOLS*row + col)
#define ROWN(l)  (MOD(l+1,N) + (N*((l)/N)))  // next row, @l is the LINEAR index (ie. RCOLS*row + col)
#define TR(l)    (N*((l)%N) + ((l)/N))       // transpose l-index. Eg. for N==4 and the (i,j) n-index (1,3), the transpose is n-index (3,1), so its l-index 4*1+3 gets mapped to 4*3+1

#define QC(x, l,rot)  x[COLN(l)] = XOR(x[COLN(l)], RL(ADD(x[l],x[COLP(l)]), rot))  // quarterround, column-major (in place)
#define QR(x, l,rot)  x[ROWN(l)] = XOR(x[ROWN(l)], RL(ADD(x[l],x[ROWP(l)]), rot))  // quarterround, row   -major (in place)

void mc_show(u32 x[16], char* msg){
  if(msg)  printf("\x1b[92m%s\x1b[91m:\x1b[0m\n", msg);
  m_fori(i, 0,N){
    m_fori(j, 0,N)
      printf(" %s", fmtu32hbe(x[N*i+j]));
    putchar(0x0a);
  }
}

void mc04_blk(u32 in[N*N], u32 out[N*N]){
  u32 x[N*N];
  for(int i=0; i<N*N; ++i)  x[i] = in[i];

  for(int i=0; i<0x14; i+=2){
    for(int j=0; j<N; ++j)  QC(x,    (N*0x00 + j*(N+1)) % (N*N),  (0x07+0)%0x20);  // row0
    for(int j=0; j<N; ++j)  QC(x,    (N*0x01 + j*(N+1)) % (N*N),  (0x09+0)%0x20);  // row1
    for(int j=0; j<N; ++j)  QC(x,    (N*0x02 + j*(N+1)) % (N*N),  (0x0d+0)%0x20);  // row2
    for(int j=0; j<N; ++j)  QC(x,    (N*0x03 + j*(N+1)) % (N*N),  (0x12+0)%0x20);  // row3

    for(int j=0; j<N; ++j)  QR(x, TR((N*0x00 + j*(N+1)) % (N*N)), (0x07+0)%0x20);  // col0
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x01 + j*(N+1)) % (N*N)), (0x09+0)%0x20);  // col1
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x02 + j*(N+1)) % (N*N)), (0x0d+0)%0x20);  // col2
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x03 + j*(N+1)) % (N*N)), (0x12+0)%0x20);  // col3
  }
  for(int i=0; i<N*N; ++i)  out[i] = in[i] + x[i];
}

void mc08_blk(u32 in[N*N], u32 out[N*N]){
  u32 x[N*N];
  for(int i=0; i<N*N; ++i)  x[i] = in[i];

  for(int i=0; i<MC_NROUNDS; i+=2){
    for(int j=0; j<N; ++j)  QC(x,    (N*0x00 + j*(N+1)) % (N*N),  (0x07+0)%0x20);  // row0
    for(int j=0; j<N; ++j)  QC(x,    (N*0x01 + j*(N+1)) % (N*N),  (0x09+0)%0x20);  // row1
    for(int j=0; j<N; ++j)  QC(x,    (N*0x02 + j*(N+1)) % (N*N),  (0x0d+0)%0x20);  // row2
    for(int j=0; j<N; ++j)  QC(x,    (N*0x03 + j*(N+1)) % (N*N),  (0x12+0)%0x20);  // row3
    for(int j=0; j<N; ++j)  QC(x,    (N*0x04 + j*(N+1)) % (N*N),  (0x07+1)%0x20);  // row4
    for(int j=0; j<N; ++j)  QC(x,    (N*0x05 + j*(N+1)) % (N*N),  (0x09+1)%0x20);  // row5
    for(int j=0; j<N; ++j)  QC(x,    (N*0x06 + j*(N+1)) % (N*N),  (0x0d+1)%0x20);  // row6
    for(int j=0; j<N; ++j)  QC(x,    (N*0x07 + j*(N+1)) % (N*N),  (0x12+1)%0x20);  // row7

    for(int j=0; j<N; ++j)  QR(x, TR((N*0x00 + j*(N+1)) % (N*N)), (0x07+0)%0x20);  // col0
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x01 + j*(N+1)) % (N*N)), (0x09+0)%0x20);  // col1
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x02 + j*(N+1)) % (N*N)), (0x0d+0)%0x20);  // col2
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x03 + j*(N+1)) % (N*N)), (0x12+0)%0x20);  // col3
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x04 + j*(N+1)) % (N*N)), (0x07+1)%0x20);  // col4
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x05 + j*(N+1)) % (N*N)), (0x09+1)%0x20);  // col5
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x06 + j*(N+1)) % (N*N)), (0x0d+1)%0x20);  // col6
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x07 + j*(N+1)) % (N*N)), (0x12+1)%0x20);  // col7
  }
  for(int i=0; i<N*N; ++i)  out[i] = in[i] + x[i];
}

void mc10_blk(u32 in[N*N], u32 out[N*N]){
  u32 x[N*N];
  for(int i=0; i<N*N; ++i)  x[i] = in[i];

  for(int i=0; i<MC_NROUNDS; i+=2){
    for(int j=0; j<N; ++j)  QC(x,    (N*0x00 + j*(N+1)) % (N*N),  (0x07+0)%0x20);  // row0  7  8  9 10
    for(int j=0; j<N; ++j)  QC(x,    (N*0x01 + j*(N+1)) % (N*N),  (0x09+0)%0x20);  // row1  9 10 11 12
    for(int j=0; j<N; ++j)  QC(x,    (N*0x02 + j*(N+1)) % (N*N),  (0x0d+0)%0x20);  // row2 13 14 15 16
    for(int j=0; j<N; ++j)  QC(x,    (N*0x03 + j*(N+1)) % (N*N),  (0x12+0)%0x20);  // row3 18 19 20 21
    for(int j=0; j<N; ++j)  QC(x,    (N*0x04 + j*(N+1)) % (N*N),  (0x07+1)%0x20);  // row4
    for(int j=0; j<N; ++j)  QC(x,    (N*0x05 + j*(N+1)) % (N*N),  (0x09+1)%0x20);  // row5
    for(int j=0; j<N; ++j)  QC(x,    (N*0x06 + j*(N+1)) % (N*N),  (0x0d+1)%0x20);  // row6
    for(int j=0; j<N; ++j)  QC(x,    (N*0x07 + j*(N+1)) % (N*N),  (0x12+1)%0x20);  // row7
    for(int j=0; j<N; ++j)  QC(x,    (N*0x08 + j*(N+1)) % (N*N),  (0x07+2)%0x20);  // row8
    for(int j=0; j<N; ++j)  QC(x,    (N*0x09 + j*(N+1)) % (N*N),  (0x09+2)%0x20);  // row9
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0a + j*(N+1)) % (N*N),  (0x0d+2)%0x20);  // rowa
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0b + j*(N+1)) % (N*N),  (0x12+2)%0x20);  // rowb
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0c + j*(N+1)) % (N*N),  (0x07+3)%0x20);  // rowc
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0d + j*(N+1)) % (N*N),  (0x09+3)%0x20);  // rowd
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0e + j*(N+1)) % (N*N),  (0x0d+3)%0x20);  // rowe
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0f + j*(N+1)) % (N*N),  (0x12+3)%0x20);  // rowf

    for(int j=0; j<N; ++j)  QR(x, TR((N*0x00 + j*(N+1)) % (N*N)), (0x07+0)%0x20);  // col0
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x01 + j*(N+1)) % (N*N)), (0x09+0)%0x20);  // col1
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x02 + j*(N+1)) % (N*N)), (0x0d+0)%0x20);  // col2
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x03 + j*(N+1)) % (N*N)), (0x12+0)%0x20);  // col3
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x04 + j*(N+1)) % (N*N)), (0x07+1)%0x20);  // col4
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x05 + j*(N+1)) % (N*N)), (0x09+1)%0x20);  // col5
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x06 + j*(N+1)) % (N*N)), (0x0d+1)%0x20);  // col6
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x07 + j*(N+1)) % (N*N)), (0x12+1)%0x20);  // col7
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x08 + j*(N+1)) % (N*N)), (0x07+2)%0x20);  // col8
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x09 + j*(N+1)) % (N*N)), (0x09+2)%0x20);  // col9
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0a + j*(N+1)) % (N*N)), (0x0d+2)%0x20);  // cola
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0b + j*(N+1)) % (N*N)), (0x12+2)%0x20);  // colb
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0c + j*(N+1)) % (N*N)), (0x07+3)%0x20);  // colc
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0d + j*(N+1)) % (N*N)), (0x09+3)%0x20);  // cold
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0e + j*(N+1)) % (N*N)), (0x0d+3)%0x20);  // cole
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0f + j*(N+1)) % (N*N)), (0x12+3)%0x20);  // colf
  }

  for(int i=0; i<N*N; ++i)  out[i] = in[i] + x[i];
}

void mc20_blk(u32 in[N*N], u32 out[N*N]){
  u32 x[N*N];
  for(int i=0; i<N*N; ++i)  x[i] = in[i];

  for(int i=0; i<MC_NROUNDS; i+=2){
    for(int j=0; j<N; ++j)  QC(x,    (N*0x00 + j*(N+1)) % (N*N),  (0x07+0x00/4)%0x20);  // row00  7  8  9 10
    for(int j=0; j<N; ++j)  QC(x,    (N*0x01 + j*(N+1)) % (N*N),  (0x09+0x01/4)%0x20);  // row01  9 10 11 12
    for(int j=0; j<N; ++j)  QC(x,    (N*0x02 + j*(N+1)) % (N*N),  (0x0d+0x02/4)%0x20);  // row02 13 14 15 16
    for(int j=0; j<N; ++j)  QC(x,    (N*0x03 + j*(N+1)) % (N*N),  (0x12+0x03/4)%0x20);  // row03 18 19 20 21
    for(int j=0; j<N; ++j)  QC(x,    (N*0x04 + j*(N+1)) % (N*N),  (0x07+0x04/4)%0x20);  // row04
    for(int j=0; j<N; ++j)  QC(x,    (N*0x05 + j*(N+1)) % (N*N),  (0x09+0x05/4)%0x20);  // row05
    for(int j=0; j<N; ++j)  QC(x,    (N*0x06 + j*(N+1)) % (N*N),  (0x0d+0x06/4)%0x20);  // row06
    for(int j=0; j<N; ++j)  QC(x,    (N*0x07 + j*(N+1)) % (N*N),  (0x12+0x07/4)%0x20);  // row07
    for(int j=0; j<N; ++j)  QC(x,    (N*0x08 + j*(N+1)) % (N*N),  (0x07+0x08/4)%0x20);  // row08
    for(int j=0; j<N; ++j)  QC(x,    (N*0x09 + j*(N+1)) % (N*N),  (0x09+0x09/4)%0x20);  // row09
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0a + j*(N+1)) % (N*N),  (0x0d+0x0a/4)%0x20);  // row0a
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0b + j*(N+1)) % (N*N),  (0x12+0x0b/4)%0x20);  // row0b
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0c + j*(N+1)) % (N*N),  (0x07+0x0c/4)%0x20);  // row0c
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0d + j*(N+1)) % (N*N),  (0x09+0x0d/4)%0x20);  // row0d
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0e + j*(N+1)) % (N*N),  (0x0d+0x0e/4)%0x20);  // row0e
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0f + j*(N+1)) % (N*N),  (0x12+0x0f/4)%0x20);  // row0f
    for(int j=0; j<N; ++j)  QC(x,    (N*0x10 + j*(N+1)) % (N*N),  (0x07+0x10/4)%0x20);  // row10
    for(int j=0; j<N; ++j)  QC(x,    (N*0x11 + j*(N+1)) % (N*N),  (0x09+0x11/4)%0x20);  // row11
    for(int j=0; j<N; ++j)  QC(x,    (N*0x12 + j*(N+1)) % (N*N),  (0x0d+0x12/4)%0x20);  // row12
    for(int j=0; j<N; ++j)  QC(x,    (N*0x13 + j*(N+1)) % (N*N),  (0x12+0x13/4)%0x20);  // row13
    for(int j=0; j<N; ++j)  QC(x,    (N*0x14 + j*(N+1)) % (N*N),  (0x07+0x14/4)%0x20);  // row14
    for(int j=0; j<N; ++j)  QC(x,    (N*0x15 + j*(N+1)) % (N*N),  (0x09+0x15/4)%0x20);  // row15
    for(int j=0; j<N; ++j)  QC(x,    (N*0x16 + j*(N+1)) % (N*N),  (0x0d+0x16/4)%0x20);  // row16
    for(int j=0; j<N; ++j)  QC(x,    (N*0x17 + j*(N+1)) % (N*N),  (0x12+0x17/4)%0x20);  // row17
    for(int j=0; j<N; ++j)  QC(x,    (N*0x18 + j*(N+1)) % (N*N),  (0x07+0x18/4)%0x20);  // row18
    for(int j=0; j<N; ++j)  QC(x,    (N*0x19 + j*(N+1)) % (N*N),  (0x09+0x19/4)%0x20);  // row19
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1a + j*(N+1)) % (N*N),  (0x0d+0x1a/4)%0x20);  // row1a
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1b + j*(N+1)) % (N*N),  (0x12+0x1b/4)%0x20);  // row1b
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1c + j*(N+1)) % (N*N),  (0x07+0x1c/4)%0x20);  // row1c
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1d + j*(N+1)) % (N*N),  (0x09+0x1d/4)%0x20);  // row1d
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1e + j*(N+1)) % (N*N),  (0x0d+0x1e/4)%0x20);  // row1e
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1f + j*(N+1)) % (N*N),  (0x12+0x1f/4)%0x20);  // row1f

    for(int j=0; j<N; ++j)  QR(x, TR((N*0x00 + j*(N+1)) % (N*N)), (0x07+0x00/4)%0x20);  // col00
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x01 + j*(N+1)) % (N*N)), (0x09+0x01/4)%0x20);  // col01
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x02 + j*(N+1)) % (N*N)), (0x0d+0x02/4)%0x20);  // col02
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x03 + j*(N+1)) % (N*N)), (0x12+0x03/4)%0x20);  // col03
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x04 + j*(N+1)) % (N*N)), (0x07+0x04/4)%0x20);  // col04
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x05 + j*(N+1)) % (N*N)), (0x09+0x05/4)%0x20);  // col05
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x06 + j*(N+1)) % (N*N)), (0x0d+0x06/4)%0x20);  // col06
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x07 + j*(N+1)) % (N*N)), (0x12+0x07/4)%0x20);  // col07
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x08 + j*(N+1)) % (N*N)), (0x07+0x08/4)%0x20);  // col08
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x09 + j*(N+1)) % (N*N)), (0x09+0x09/4)%0x20);  // col09
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0a + j*(N+1)) % (N*N)), (0x0d+0x0a/4)%0x20);  // col0a
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0b + j*(N+1)) % (N*N)), (0x12+0x0b/4)%0x20);  // col0b
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0c + j*(N+1)) % (N*N)), (0x07+0x0c/4)%0x20);  // col0c
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0d + j*(N+1)) % (N*N)), (0x09+0x0d/4)%0x20);  // col0d
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0e + j*(N+1)) % (N*N)), (0x0d+0x0e/4)%0x20);  // col0e
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0f + j*(N+1)) % (N*N)), (0x12+0x0f/4)%0x20);  // col0f
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x10 + j*(N+1)) % (N*N)), (0x07+0x10/4)%0x20);  // col10
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x11 + j*(N+1)) % (N*N)), (0x09+0x11/4)%0x20);  // col11
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x12 + j*(N+1)) % (N*N)), (0x0d+0x12/4)%0x20);  // col12
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x13 + j*(N+1)) % (N*N)), (0x12+0x13/4)%0x20);  // col13
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x14 + j*(N+1)) % (N*N)), (0x07+0x14/4)%0x20);  // col14
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x15 + j*(N+1)) % (N*N)), (0x09+0x15/4)%0x20);  // col15
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x16 + j*(N+1)) % (N*N)), (0x0d+0x16/4)%0x20);  // col16
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x17 + j*(N+1)) % (N*N)), (0x12+0x17/4)%0x20);  // col17
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x18 + j*(N+1)) % (N*N)), (0x07+0x18/4)%0x20);  // col18
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x19 + j*(N+1)) % (N*N)), (0x09+0x19/4)%0x20);  // col19
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1a + j*(N+1)) % (N*N)), (0x0d+0x1a/4)%0x20);  // col1a
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1b + j*(N+1)) % (N*N)), (0x12+0x1b/4)%0x20);  // col1b
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1c + j*(N+1)) % (N*N)), (0x07+0x1c/4)%0x20);  // col1c
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1d + j*(N+1)) % (N*N)), (0x09+0x1d/4)%0x20);  // col1d
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1e + j*(N+1)) % (N*N)), (0x0d+0x1e/4)%0x20);  // col1e
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1f + j*(N+1)) % (N*N)), (0x12+0x1f/4)%0x20);  // col1f
  }

  for(int i=0; i<N*N; ++i)  out[i] = in[i] + x[i];
}

#if 0  // BUG! not working
void mc40_blk(u32 in[N*N], u32 out[N*N]){
  u32 x[N*N];
  for(int i=0; i<N*N; ++i)  x[i] = in[i];

  for(int i=0; i<MC_NROUNDS; i+=2){
    for(int j=0; j<N; ++j)  QC(x,    (N*0x00 + j*(N+1)) % (N*N),  (0x07+0x00/4)%0x20);  // row00  7  8  9 10
    for(int j=0; j<N; ++j)  QC(x,    (N*0x01 + j*(N+1)) % (N*N),  (0x09+0x01/4)%0x20);  // row01  9 10 11 12
    for(int j=0; j<N; ++j)  QC(x,    (N*0x02 + j*(N+1)) % (N*N),  (0x0d+0x02/4)%0x20);  // row02 13 14 15 16
    for(int j=0; j<N; ++j)  QC(x,    (N*0x03 + j*(N+1)) % (N*N),  (0x12+0x03/4)%0x20);  // row03 18 19 20 21
    for(int j=0; j<N; ++j)  QC(x,    (N*0x04 + j*(N+1)) % (N*N),  (0x07+0x04/4)%0x20);  // row04
    for(int j=0; j<N; ++j)  QC(x,    (N*0x05 + j*(N+1)) % (N*N),  (0x09+0x05/4)%0x20);  // row05
    for(int j=0; j<N; ++j)  QC(x,    (N*0x06 + j*(N+1)) % (N*N),  (0x0d+0x06/4)%0x20);  // row06
    for(int j=0; j<N; ++j)  QC(x,    (N*0x07 + j*(N+1)) % (N*N),  (0x12+0x07/4)%0x20);  // row07
    for(int j=0; j<N; ++j)  QC(x,    (N*0x08 + j*(N+1)) % (N*N),  (0x07+0x08/4)%0x20);  // row08
    for(int j=0; j<N; ++j)  QC(x,    (N*0x09 + j*(N+1)) % (N*N),  (0x09+0x09/4)%0x20);  // row09
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0a + j*(N+1)) % (N*N),  (0x0d+0x0a/4)%0x20);  // row0a
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0b + j*(N+1)) % (N*N),  (0x12+0x0b/4)%0x20);  // row0b
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0c + j*(N+1)) % (N*N),  (0x07+0x0c/4)%0x20);  // row0c
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0d + j*(N+1)) % (N*N),  (0x09+0x0d/4)%0x20);  // row0d
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0e + j*(N+1)) % (N*N),  (0x0d+0x0e/4)%0x20);  // row0e
    for(int j=0; j<N; ++j)  QC(x,    (N*0x0f + j*(N+1)) % (N*N),  (0x12+0x0f/4)%0x20);  // row0f
    for(int j=0; j<N; ++j)  QC(x,    (N*0x10 + j*(N+1)) % (N*N),  (0x07+0x10/4)%0x20);  // row10
    for(int j=0; j<N; ++j)  QC(x,    (N*0x11 + j*(N+1)) % (N*N),  (0x09+0x11/4)%0x20);  // row11
    for(int j=0; j<N; ++j)  QC(x,    (N*0x12 + j*(N+1)) % (N*N),  (0x0d+0x12/4)%0x20);  // row12
    for(int j=0; j<N; ++j)  QC(x,    (N*0x13 + j*(N+1)) % (N*N),  (0x12+0x13/4)%0x20);  // row13
    for(int j=0; j<N; ++j)  QC(x,    (N*0x14 + j*(N+1)) % (N*N),  (0x07+0x14/4)%0x20);  // row14
    for(int j=0; j<N; ++j)  QC(x,    (N*0x15 + j*(N+1)) % (N*N),  (0x09+0x15/4)%0x20);  // row15
    for(int j=0; j<N; ++j)  QC(x,    (N*0x16 + j*(N+1)) % (N*N),  (0x0d+0x16/4)%0x20);  // row16
    for(int j=0; j<N; ++j)  QC(x,    (N*0x17 + j*(N+1)) % (N*N),  (0x12+0x17/4)%0x20);  // row17
    for(int j=0; j<N; ++j)  QC(x,    (N*0x18 + j*(N+1)) % (N*N),  (0x07+0x18/4)%0x20);  // row18
    for(int j=0; j<N; ++j)  QC(x,    (N*0x19 + j*(N+1)) % (N*N),  (0x09+0x19/4)%0x20);  // row19
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1a + j*(N+1)) % (N*N),  (0x0d+0x1a/4)%0x20);  // row1a
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1b + j*(N+1)) % (N*N),  (0x12+0x1b/4)%0x20);  // row1b
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1c + j*(N+1)) % (N*N),  (0x07+0x1c/4)%0x20);  // row1c
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1d + j*(N+1)) % (N*N),  (0x09+0x1d/4)%0x20);  // row1d
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1e + j*(N+1)) % (N*N),  (0x0d+0x1e/4)%0x20);  // row1e
    for(int j=0; j<N; ++j)  QC(x,    (N*0x1f + j*(N+1)) % (N*N),  (0x12+0x1f/4)%0x20);  // row1f
    for(int j=0; j<N; ++j)  QC(x,    (N*0x20 + j*(N+1)) % (N*N),  (0x07+0x20/4)%0x20);  // row20
    for(int j=0; j<N; ++j)  QC(x,    (N*0x21 + j*(N+1)) % (N*N),  (0x09+0x21/4)%0x20);  // row21
    for(int j=0; j<N; ++j)  QC(x,    (N*0x22 + j*(N+1)) % (N*N),  (0x0d+0x22/4)%0x20);  // row22
    for(int j=0; j<N; ++j)  QC(x,    (N*0x23 + j*(N+1)) % (N*N),  (0x12+0x23/4)%0x20);  // row23
    for(int j=0; j<N; ++j)  QC(x,    (N*0x24 + j*(N+1)) % (N*N),  (0x07+0x24/4)%0x20);  // row24
    for(int j=0; j<N; ++j)  QC(x,    (N*0x25 + j*(N+1)) % (N*N),  (0x09+0x25/4)%0x20);  // row25
    for(int j=0; j<N; ++j)  QC(x,    (N*0x26 + j*(N+1)) % (N*N),  (0x0d+0x26/4)%0x20);  // row26
    for(int j=0; j<N; ++j)  QC(x,    (N*0x27 + j*(N+1)) % (N*N),  (0x12+0x27/4)%0x20);  // row27
    for(int j=0; j<N; ++j)  QC(x,    (N*0x28 + j*(N+1)) % (N*N),  (0x07+0x28/4)%0x20);  // row28
    for(int j=0; j<N; ++j)  QC(x,    (N*0x29 + j*(N+1)) % (N*N),  (0x09+0x29/4)%0x20);  // row29
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2a + j*(N+1)) % (N*N),  (0x0d+0x2a/4)%0x20);  // row2a
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2b + j*(N+1)) % (N*N),  (0x12+0x2b/4)%0x20);  // row2b
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2c + j*(N+1)) % (N*N),  (0x07+0x2c/4)%0x20);  // row2c
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2d + j*(N+1)) % (N*N),  (0x09+0x2d/4)%0x20);  // row2d
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2e + j*(N+1)) % (N*N),  (0x0d+0x2e/4)%0x20);  // row2e
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2f + j*(N+1)) % (N*N),  (0x12+0x2f/4)%0x20);  // row2f
    for(int j=0; j<N; ++j)  QC(x,    (N*0x20 + j*(N+1)) % (N*N),  (0x07+0x20/4)%0x20);  // row20
    for(int j=0; j<N; ++j)  QC(x,    (N*0x21 + j*(N+1)) % (N*N),  (0x09+0x21/4)%0x20);  // row21
    for(int j=0; j<N; ++j)  QC(x,    (N*0x22 + j*(N+1)) % (N*N),  (0x0d+0x22/4)%0x20);  // row22
    for(int j=0; j<N; ++j)  QC(x,    (N*0x23 + j*(N+1)) % (N*N),  (0x12+0x23/4)%0x20);  // row23
    for(int j=0; j<N; ++j)  QC(x,    (N*0x24 + j*(N+1)) % (N*N),  (0x07+0x24/4)%0x20);  // row24
    for(int j=0; j<N; ++j)  QC(x,    (N*0x25 + j*(N+1)) % (N*N),  (0x09+0x25/4)%0x20);  // row25
    for(int j=0; j<N; ++j)  QC(x,    (N*0x26 + j*(N+1)) % (N*N),  (0x0d+0x26/4)%0x20);  // row26
    for(int j=0; j<N; ++j)  QC(x,    (N*0x27 + j*(N+1)) % (N*N),  (0x12+0x27/4)%0x20);  // row27
    for(int j=0; j<N; ++j)  QC(x,    (N*0x28 + j*(N+1)) % (N*N),  (0x07+0x28/4)%0x20);  // row28
    for(int j=0; j<N; ++j)  QC(x,    (N*0x29 + j*(N+1)) % (N*N),  (0x09+0x29/4)%0x20);  // row29
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2a + j*(N+1)) % (N*N),  (0x0d+0x2a/4)%0x20);  // row2a
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2b + j*(N+1)) % (N*N),  (0x12+0x2b/4)%0x20);  // row2b
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2c + j*(N+1)) % (N*N),  (0x07+0x2c/4)%0x20);  // row2c
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2d + j*(N+1)) % (N*N),  (0x09+0x2d/4)%0x20);  // row2d
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2e + j*(N+1)) % (N*N),  (0x0d+0x2e/4)%0x20);  // row2e
    for(int j=0; j<N; ++j)  QC(x,    (N*0x2f + j*(N+1)) % (N*N),  (0x12+0x2f/4)%0x20);  // row2f

    for(int j=0; j<N; ++j)  QR(x, TR((N*0x00 + j*(N+1)) % (N*N)), (0x07+0x00/4)%0x20);  // col00
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x01 + j*(N+1)) % (N*N)), (0x09+0x01/4)%0x20);  // col01
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x02 + j*(N+1)) % (N*N)), (0x0d+0x02/4)%0x20);  // col02
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x03 + j*(N+1)) % (N*N)), (0x12+0x03/4)%0x20);  // col03
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x04 + j*(N+1)) % (N*N)), (0x07+0x04/4)%0x20);  // col04
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x05 + j*(N+1)) % (N*N)), (0x09+0x05/4)%0x20);  // col05
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x06 + j*(N+1)) % (N*N)), (0x0d+0x06/4)%0x20);  // col06
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x07 + j*(N+1)) % (N*N)), (0x12+0x07/4)%0x20);  // col07
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x08 + j*(N+1)) % (N*N)), (0x07+0x08/4)%0x20);  // col08
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x09 + j*(N+1)) % (N*N)), (0x09+0x09/4)%0x20);  // col09
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0a + j*(N+1)) % (N*N)), (0x0d+0x0a/4)%0x20);  // col0a
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0b + j*(N+1)) % (N*N)), (0x12+0x0b/4)%0x20);  // col0b
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0c + j*(N+1)) % (N*N)), (0x07+0x0c/4)%0x20);  // col0c
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0d + j*(N+1)) % (N*N)), (0x09+0x0d/4)%0x20);  // col0d
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0e + j*(N+1)) % (N*N)), (0x0d+0x0e/4)%0x20);  // col0e
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x0f + j*(N+1)) % (N*N)), (0x12+0x0f/4)%0x20);  // col0f
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x10 + j*(N+1)) % (N*N)), (0x07+0x10/4)%0x20);  // col10
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x11 + j*(N+1)) % (N*N)), (0x09+0x11/4)%0x20);  // col11
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x12 + j*(N+1)) % (N*N)), (0x0d+0x12/4)%0x20);  // col12
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x13 + j*(N+1)) % (N*N)), (0x12+0x13/4)%0x20);  // col13
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x14 + j*(N+1)) % (N*N)), (0x07+0x14/4)%0x20);  // col14
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x15 + j*(N+1)) % (N*N)), (0x09+0x15/4)%0x20);  // col15
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x16 + j*(N+1)) % (N*N)), (0x0d+0x16/4)%0x20);  // col16
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x17 + j*(N+1)) % (N*N)), (0x12+0x17/4)%0x20);  // col17
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x18 + j*(N+1)) % (N*N)), (0x07+0x18/4)%0x20);  // col18
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x19 + j*(N+1)) % (N*N)), (0x09+0x19/4)%0x20);  // col19
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1a + j*(N+1)) % (N*N)), (0x0d+0x1a/4)%0x20);  // col1a
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1b + j*(N+1)) % (N*N)), (0x12+0x1b/4)%0x20);  // col1b
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1c + j*(N+1)) % (N*N)), (0x07+0x1c/4)%0x20);  // col1c
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1d + j*(N+1)) % (N*N)), (0x09+0x1d/4)%0x20);  // col1d
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1e + j*(N+1)) % (N*N)), (0x0d+0x1e/4)%0x20);  // col1e
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x1f + j*(N+1)) % (N*N)), (0x12+0x1f/4)%0x20);  // col1f
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x20 + j*(N+1)) % (N*N)), (0x07+0x20/4)%0x20);  // col20
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x21 + j*(N+1)) % (N*N)), (0x09+0x21/4)%0x20);  // col21
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x22 + j*(N+1)) % (N*N)), (0x0d+0x22/4)%0x20);  // col22
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x23 + j*(N+1)) % (N*N)), (0x12+0x23/4)%0x20);  // col23
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x24 + j*(N+1)) % (N*N)), (0x07+0x24/4)%0x20);  // col24
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x25 + j*(N+1)) % (N*N)), (0x09+0x25/4)%0x20);  // col25
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x26 + j*(N+1)) % (N*N)), (0x0d+0x26/4)%0x20);  // col26
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x27 + j*(N+1)) % (N*N)), (0x12+0x27/4)%0x20);  // col27
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x28 + j*(N+1)) % (N*N)), (0x07+0x28/4)%0x20);  // col28
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x29 + j*(N+1)) % (N*N)), (0x09+0x29/4)%0x20);  // col29
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2a + j*(N+1)) % (N*N)), (0x0d+0x2a/4)%0x20);  // col2a
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2b + j*(N+1)) % (N*N)), (0x12+0x2b/4)%0x20);  // col2b
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2c + j*(N+1)) % (N*N)), (0x07+0x2c/4)%0x20);  // col2c
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2d + j*(N+1)) % (N*N)), (0x09+0x2d/4)%0x20);  // col2d
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2e + j*(N+1)) % (N*N)), (0x0d+0x2e/4)%0x20);  // col2e
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2f + j*(N+1)) % (N*N)), (0x12+0x2f/4)%0x20);  // col2f
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x20 + j*(N+1)) % (N*N)), (0x07+0x20/4)%0x20);  // col20
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x21 + j*(N+1)) % (N*N)), (0x09+0x21/4)%0x20);  // col21
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x22 + j*(N+1)) % (N*N)), (0x0d+0x22/4)%0x20);  // col22
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x23 + j*(N+1)) % (N*N)), (0x12+0x23/4)%0x20);  // col23
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x24 + j*(N+1)) % (N*N)), (0x07+0x24/4)%0x20);  // col24
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x25 + j*(N+1)) % (N*N)), (0x09+0x25/4)%0x20);  // col25
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x26 + j*(N+1)) % (N*N)), (0x0d+0x26/4)%0x20);  // col26
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x27 + j*(N+1)) % (N*N)), (0x12+0x27/4)%0x20);  // col27
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x28 + j*(N+1)) % (N*N)), (0x07+0x28/4)%0x20);  // col28
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x29 + j*(N+1)) % (N*N)), (0x09+0x29/4)%0x20);  // col29
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2a + j*(N+1)) % (N*N)), (0x0d+0x2a/4)%0x20);  // col2a
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2b + j*(N+1)) % (N*N)), (0x12+0x2b/4)%0x20);  // col2b
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2c + j*(N+1)) % (N*N)), (0x07+0x2c/4)%0x20);  // col2c
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2d + j*(N+1)) % (N*N)), (0x09+0x2d/4)%0x20);  // col2d
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2e + j*(N+1)) % (N*N)), (0x0d+0x2e/4)%0x20);  // col2e
    for(int j=0; j<N; ++j)  QR(x, TR((N*0x2f + j*(N+1)) % (N*N)), (0x12+0x2f/4)%0x20);  // col2f
  }

  for(int i=0; i<N*N; ++i)  out[i] = in[i] + x[i];
}
#endif

void mc_encrypt(u32 sk[N*N/2],u32 nonce[MC_NONCE_IDIM], i64 bdim,void* ptxt, void* ctxt){  // @sk: 32-byte secret key, @ptxt: data to be encrypted (plaintext), @ctxt: encrypted data (ciphertext, up to 2**70 bytes, I think)
  u32 in[N*N] = {0x00};
  u32 counter[(N*N - N*N/2 - N)/2];  memset(counter,0x00,sizeof(counter));

  // 0) ini the s20 64-byte blk
  for(int i=0; i<MC_C_IDIM;       ++i)  in[MC_C_POS       + i] = ((u32*)MC_CONSTANTS)[i];  // constants
  for(int i=0; i<MC_SK_IDIM;      ++i)  in[MC_SK_POS      + i] = sk[i];       // secret key
  for(int i=0; i<MC_NONCE_IDIM;   ++i)  in[MC_NONCE_POS   + i] = nonce[i];    // nonce
  for(int i=0; i<MC_COUNTER_IDIM; ++i)  in[MC_COUNTER_POS + i] = counter[i];  // counter

  u8* ptxt8 = (u8*)ptxt;
  u8* ctxt8 = (u8*)ctxt;
  u32 out[N*N];
  u8* out8 = (u8*)out;
  for(;  0<bdim;  bdim-=4*N*N, ptxt8+=4*N*N, ctxt8+=4*N*N){
    // 1) hash the s20 64-byte blk
    printf("\nblock \x1b[35m");  m_fori(i, 0,MC_COUNTER_IDIM) printf(" %08x", in[MC_COUNTER_POS+i]);  printf("\x1b[0m\n");
    mc_show(in, "in");
    mc20_blk(in,out);  // mc04_blk(in,out); mc08_blk(in,out); mc10_blk(in,out); mc20_blk(in,out); mc40_blk(in,out);
    mc_show(out, "out");
    mc_show((u32*)ptxt8, "ptxt");

    // 2) increase the 64-bit counter  // TODO! implement the proper-precision arithmetic
    in[MC_COUNTER_POS] += 1;
    if(in[MC_COUNTER_POS]==0x00000000)  in[MC_COUNTER_POS+1] += 1;

    // 3) encrypt @ptxt
    for(int i=0; i<m_min(4*N*N,bdim); ++i)  ctxt8[i] = ptxt8[i] ^ out8[i];
    // mc_show((u32*)ctxt8, "ctxt");
  }
}
#endif

// ----------------------------------------------------------------------------------------------------------------------------# @blk1
int main(){
  u32 SK[N*N/2];
  m_fori(i, 0,m_array_idim(SK))  SK[i] = 0x11111111;

  u32 nonce[MC_NONCE_IDIM] = {0x00};  struct timespec ep; clock_gettime(CLOCK_REALTIME, &ep);
  u64 eps = 1000000000ull*ep.tv_sec + ep.tv_nsec;
  // nonce[0x0] = eps>>0x00 & 0xffffffff;
  // nonce[0x1] = eps>>0x20 & 0xffffffff;
  // memset(nonce,0x33,sizeof(nonce));
  nonce[0x00] = 0x00000001;

  i64 bdim = 2 * 4*N*N;
  u8 x[bdim]; memset(x,0x00,bdim);
  u8 y[bdim]; memset(y,0x00,bdim);
  u8 z[bdim]; memset(z,0x00,bdim);
  x[0x00]=0x61; x[0x01]=0x62; x[0x02]=0x63;

  printf("n            \x1b[32m%'5d\x1b[0m\n", N);
  printf("rounds       \x1b[32m%'5d\x1b[0m\n", MC_NROUNDS);
  printf("blk     bits \x1b[32m%'5d\x1b[0m\n", N*N*32);
  printf("c       bits \x1b[32m%'5d\x1b[0m\n", MC_C_IDIM*32);
  printf("sk      bits \x1b[32m%'5d\x1b[0m\n", MC_SK_IDIM*32);
  printf("nonce   bits \x1b[32m%'5d\x1b[0m\n", MC_NONCE_IDIM*32);
  printf("counter bits \x1b[32m%'5d\x1b[0m\n", MC_COUNTER_IDIM*32);

  mc_encrypt(SK,nonce, bdim,x, y);

  putchar(0x0a);
  printf("\x1b[94msk   \x1b[91m:\x1b[0m");  printf(" {");  m_fori(i, 0,MC_SK_IDIM)    printf("0x%08x,", SK[i]);                  printf("}\n");
  printf("\x1b[94mnonce\x1b[91m:\x1b[0m");  printf(" {");  m_fori(i, 0,MC_NONCE_IDIM) printf("0x%08x,", nonce[i]);               printf("}\n");
  printf("\x1b[94mctxt \x1b[91m:\x1b[0m");  printf(" {");  m_fori(i, 0,bdim/4)        printf("0x%s,", fmtu32hbe(((u32*)y)[i]));  printf("}\n");
  printf("\x1b[32mptxt \x1b[91m:\x1b[0m");  printf(" %s\n", x);  // m_for(i, 0,x.bdim/4) print(" %s", fmtu32hbe(((u32*)x)[i]));  putchar(0x0a);
}
