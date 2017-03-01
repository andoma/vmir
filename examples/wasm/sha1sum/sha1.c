/*
 *  sha1.c
 *
 *  Copyright (C) 1998, 2009
 *  Paul E. Jones <paulej@packetizer.com>
 *  All Rights Reserved
 *
 *****************************************************************************
 *  $Id: sha1.c 12 2009-06-22 19:34:25Z paulej $
 *****************************************************************************
 *
 *  Description:
 *      This file implements the Secure Hashing Standard as defined
 *      in FIPS PUB 180-1 published April 17, 1995.
 *
 *      The Secure Hashing Standard, which uses the Secure Hashing
 *      Algorithm (SHA), produces a 160-bit message digest for a
 *      given data stream.  In theory, it is highly improbable that
 *      two messages will produce the same message digest.  Therefore,
 *      this algorithm can serve as a means of providing a "fingerprint"
 *      for a message.
 *
 *  Portability Issues:
 *      SHA-1 is defined in terms of 32-bit "words".  This code was
 *      written with the expectation that the processor has at least
 *      a 32-bit machine word size.  If the machine word size is larger,
 *      the code should still function properly.  One caveat to that
 *      is that the input functions taking characters and character
 *      arrays assume that only 8 bits of information are stored in each
 *      character.
 *
 *  Caveats:
 *      SHA-1 is designed to work with messages less than 2^64 bits
 *      long. Although SHA-1 allows a message digest to be generated for
 *      messages of any number of bits less than 2^64, this
 *      implementation only works with messages with a length that is a
 *      multiple of the size of an 8-bit character.
 *
 */

#include "sha1.h"

static inline void WriteBE32(uint32 v, byte *b) {
  b[0] = (byte)(v >> 24);
  b[1] = (byte)(v >> 16);
  b[2] = (byte)(v >> 8);
  b[3] = (byte)(v);
}



/*
 *  Define the circular shift macro
 */
#define SHA1CircularShift(bits,word) \
                ((((word) << (bits)) & 0xFFFFFFFF) | \
                ((word) >> (32-(bits))))

/* Function prototypes */
void SHA1ProcessMessageBlock(SHA1Context *);
void SHA1PadMessage(SHA1Context *);

/*  
 *  SHA1Reset
 *
 *  Description:
 *      This function will initialize the SHA1Context in preparation
 *      for computing a new message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *
 */
void SHA1Reset(SHA1Context *context) {
    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Pos    = 0;
    context->Message_Digest[0]      = 0x67452301;
    context->Message_Digest[1]      = 0xEFCDAB89;
    context->Message_Digest[2]      = 0x98BADCFE;
    context->Message_Digest[3]      = 0x10325476;
    context->Message_Digest[4]      = 0xC3D2E1F0;
}

/*  
 *  SHA1Result
 *
 *  Description:
 *      This function will return the 160-bit message digest into the
 *      Message_Digest array within the SHA1Context provided
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to use to calculate the SHA-1 hash.
 *
 *
 *  Comments:
 *
 */
void SHA1Finish(SHA1Context *context, byte digest[20]) {
  int i;
  SHA1PadMessage(context);
  for(i = 0; i < 5; i++)
    WriteBE32(context->Message_Digest[i], digest + i * 4);
}

/*  
 *  SHA1Input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion of
 *      the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA-1 context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of the
 *          message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *
 */
void SHA1Input(     SHA1Context         *context,
                    const unsigned char *message_array,
                    unsigned            length) {
    while(length--) {
        context->Buffer[context->Pos++] = (*message_array & 0xFF);
        context->Length_Low += 8;
        /* Force it to 32 bits */
        context->Length_Low &= 0xFFFFFFFF;
        if (context->Length_Low == 0)
            context->Length_High++;
        if (context->Pos == 64)
            SHA1ProcessMessageBlock(context);
        message_array++;
    }
}

/*  
 *  SHA1ProcessMessageBlock
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the Buffer array.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      Many of the variable names in the SHAContext, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *         
 *
 */
void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const unsigned K[] =            /* Constants defined in SHA-1   */      
    {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };
    int         t;                  /* Loop counter                 */
    uint32    temp;               /* Temporary word value         */
    unsigned    W[80];              /* Word sequence                */
    unsigned    A, B, C, D, E;      /* Word buffers                 */

    /*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        W[t] = ((unsigned) context->Buffer[t * 4]) << 24;
        W[t] |= ((unsigned) context->Buffer[t * 4 + 1]) << 16;
        W[t] |= ((unsigned) context->Buffer[t * 4 + 2]) << 8;
        W[t] |= ((unsigned) context->Buffer[t * 4 + 3]);
    }

    for(t = 16; t < 80; t++)
       W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);

    A = context->Message_Digest[0];
    B = context->Message_Digest[1];
    C = context->Message_Digest[2];
    D = context->Message_Digest[3];
    E = context->Message_Digest[4];

    for(t = 0; t < 20; t++) {
        temp =  SHA1CircularShift(5,A) +
                ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++) {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++) {
        temp = SHA1CircularShift(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++) {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    context->Message_Digest[0] += A;
    context->Message_Digest[1] += B;
    context->Message_Digest[2] += C;
    context->Message_Digest[3] += D;
    context->Message_Digest[4] += E;
    context->Pos = 0;
}

/*  
 *  SHA1PadMessage
 *
 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  The last 64
 *      bits represent the length of the original message.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the Buffer array
 *      accordingly.  It will also call SHA1ProcessMessageBlock()
 *      appropriately.  When it returns, it can be assumed that the
 *      message digest has been computed.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to pad
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *
 */
void SHA1PadMessage(SHA1Context *context)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    context->Buffer[context->Pos++] = 0x80;
    while (context->Pos != 56) {
      if (context->Pos == 64)
        SHA1ProcessMessageBlock(context);
      context->Buffer[context->Pos++] = 0;
    }

    // Store the message length as the last 8 octets
    WriteBE32(context->Length_High, &context->Buffer[56]);
    WriteBE32(context->Length_Low, &context->Buffer[60]);
    SHA1ProcessMessageBlock(context);
}

void ShaHash(const byte *data, int data_size, byte digest[20]) {
  SHA1Context ctx;
  SHA1Reset(&ctx);
  SHA1Input(&ctx, data, data_size);
  SHA1Finish(&ctx, digest);
}


void SHA1HmacReset(SHA1HmacContext *hmac, const unsigned char *key, unsigned key_size) {
  byte temp[64];
  byte temp2[64];
  byte digest[20];
  int i;
  
  // If the key is long, hash it first.
  if (key_size > 64) {
    ShaHash(key, key_size, digest);  
    key = digest;
    key_size = sizeof(digest);
  }

  // Fill with key
  for(i = 0; i != key_size; i++) {
    temp[i] = key[i] ^ 0x36;
    temp2[i] = key[i] ^ 0x5C;
  }
  // Fill the rest with zero.
  for(; i!=64; i++) {
    temp[i] = 0x36;
    temp2[i] = 0x5C;
  }
  
  SHA1Reset(&hmac->sha1);
  SHA1Reset(&hmac->sha2);
  
  SHA1Input(&hmac->sha1, temp, sizeof(temp));
  SHA1Input(&hmac->sha2, temp2, sizeof(temp2));
}

void SHA1HmacInput(SHA1HmacContext *hmac, const unsigned char *input, unsigned input_size) {
  SHA1Input(&hmac->sha1, input, input_size);
}

void SHA1HmacFinish(SHA1HmacContext *hmac, byte digest[20]) {
  SHA1Finish(&hmac->sha1, digest);  
  SHA1Input(&hmac->sha2, digest, 20);
  SHA1Finish(&hmac->sha2, digest);
}
