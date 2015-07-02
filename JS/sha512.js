/**
 *  File: sha512.js
 *  Author: Gary Hammock
 *  Date: 2014-12-18
 *
 * ============================================================================
 * REFERENCES
 * ============================================================================
 *
 * FIPS 180-2.  "Secure Hash Standard."  2002 August 01. National Institute of 
 *     Standards and Technology (NIST).  U.S. Department of Commerce.
 *
 * ============================================================================
 * LICENSE (MIT/X11)
 * ============================================================================
 *
 * Copyright (C) 2014 Gary Hammock, PE
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
*/

/**
 *  This function generates the 512-bit Secure Hash Algorithm (SHA-512) hash
 *  of a given input string.
 *
 *  @param input A string to hash with SHA-512.
 *  @returns The SHA-512 hash of the string.
 *
 *  @see FIPS 180-2.
*/
function sha512 (input) {

    // We need to make sure that the string is encoded as UTF-8.  Rather than
    // deal with bit-twiddling, we can use the JavaScript built-in
    // encodeURIComponent() function to handle the conversion.
    var input = encodeURIComponent(input);

    // The hash constants for SHA-512.  Comprised of 80 64-bit integer values
    // per FIPS 180-2.
    var K = initializeHashConstants();

    // Get the initial hash.
    var H = initializeHash();

    // Pad the message per FIPS 180-2, section 5.1.2.
    var message = padMessage(input);

    // FIPS 180-2 defines 8 working variables.
    var a = new UInt64_t(0, 0);
    var b = new UInt64_t(0, 0);
    var c = new UInt64_t(0, 0);
    var d = new UInt64_t(0, 0);
    var e = new UInt64_t(0, 0);
    var f = new UInt64_t(0, 0);
    var g = new UInt64_t(0, 0);
    var h = new UInt64_t(0, 0);

    // FIPS 180-2 defines 2 temporary words.
    var T1 = new UInt64_t(0, 0);
    var T2 = new UInt64_t(0, 0);

    // These represent the functions Ch() and Maj() defined in
    // FIPS 180-2, section 4.1.3.
    var Ch  = new UInt64_t(0, 0);
    var Maj = new UInt64_t(0, 0);

    // These represent both the upper- and lowercase sigma values in
    // FIPS 180-2, section 4.1.3.
    var sigma1 = new UInt64_t(0, 0);
    var sigma0 = new UInt64_t(0, 0);

    var temp1 = new UInt64_t(0, 0);
    var temp2 = new UInt64_t(0, 0);
    var temp3 = new UInt64_t(0, 0);

    // The words of the message schedule (see FIPS 180-2, section 6.3).
    var W = new Array (80);
    for (var i = 0; i < 80; ++i)
        W[i] = new UInt64_t(0, 0);

    for (var i = 0; i < message.length; i += 32) {

        // Prepare the message schedule.
        for (var j = 0; j < 16; ++j) {
            W[j].hi = message[i + (2 * j)    ];
            W[j].lo = message[i + (2 * j) + 1];
        }

        for (var j = 16; j < 80; ++j) {
            // Calculate Sigma1.
            UInt64_rightRotate(temp1, W[j - 2], 19);
            UInt64_rightRotate(temp2, W[j - 2], 61);
            UInt64_rightShift(temp3, W[j - 2], 6);
            sigma1.lo = temp1.lo ^ temp2.lo ^ temp3.lo;
            sigma1.hi = temp1.hi ^ temp2.hi ^ temp3.hi;

            // Calculate Sigma0.
            UInt64_rightRotate(temp1, W[j - 15], 1);
            UInt64_rightRotate(temp2, W[j - 15], 8);
            UInt64_rightShift(temp3, W[j - 15], 7);
            sigma0.lo = temp1.lo ^ temp2.lo ^ temp3.lo;
            sigma0.hi = temp1.hi ^ temp2.hi ^ temp3.hi;

            temp1 = UInt64_add(sigma1, W[j -  7]);
            temp2 = UInt64_add(sigma0, W[j - 16]);
            W[j]  = UInt64_add(temp1, temp2);
        }

        // Initialize the eight working variables with the (i-1)th hash value.
        UInt64_copy(a, H[0]);
        UInt64_copy(b, H[1]);
        UInt64_copy(c, H[2]);
        UInt64_copy(d, H[3]);
        UInt64_copy(e, H[4]);
        UInt64_copy(f, H[5]);
        UInt64_copy(g, H[6]);
        UInt64_copy(h, H[7]);

        for (var j = 0; j < 80; ++j) {
            // Calculate Ch(e, f, g).
            // See eqn 4.8, FIPS 180-2, sect 4.1.3, p 10.
            Ch.lo = (e.lo & f.lo) ^ (~e.lo & g.lo);
            Ch.hi = (e.hi & f.hi) ^ (~e.hi & g.hi);

            // Calculate Maj(a, b, c).
            // See eqn 4.9, FIPS 180-2, sect 4.1.3, p 10.
            Maj.lo = (a.lo & b.lo) ^ (a.lo & c.lo) ^ (b.lo & c.lo);
            Maj.hi = (a.hi & b.hi) ^ (a.hi & c.hi) ^ (b.hi & c.hi);

            // Calculate uppercase Sigma_0(a).
            // See eqn 4.10, FIPS 180-2, sect 4.1.3, p 10.
            UInt64_rightRotate(temp1, a, 28);
            UInt64_rightRotate(temp2, a, 34);
            UInt64_rightRotate(temp3, a, 39);
            sigma0.lo = temp1.lo ^ temp2.lo ^ temp3.lo;
            sigma0.hi = temp1.hi ^ temp2.hi ^ temp3.hi;

            // Calculate uppercase Sigma_1(e).
            // See eqn 4.11, FIPS 180-2, sect 4.1.3, p 10.
            UInt64_rightRotate(temp1, e, 14);
            UInt64_rightRotate(temp2, e, 18);
            UInt64_rightRotate(temp3, e, 41);
            sigma1.lo = temp1.lo ^ temp2.lo ^ temp3.lo;
            sigma1.hi = temp1.hi ^ temp2.hi ^ temp3.hi;

            // Calculate T1 per section 6.3.2.
            temp1 = UInt64_add(h, sigma1);
            temp2 = UInt64_add(Ch, K[j]);
            temp3 = UInt64_add(temp1, temp2);
            T1 = UInt64_add(temp3, W[j]);

            // Calculate T2 per section 6.3.2.
            T2 = UInt64_add(sigma0, Maj);

            UInt64_copy(h, g);
            UInt64_copy(g, f);
            UInt64_copy(f, e);
            e = UInt64_add(d, T1);
            UInt64_copy(d, c);
            UInt64_copy(c, b);
            UInt64_copy(b, a);
            a = UInt64_add(T1, T2);
        }

        // Compute the i-th intermediate hash value.
        H[0] = UInt64_add(a, H[0]);
        H[1] = UInt64_add(b, H[1]);
        H[2] = UInt64_add(c, H[2]);
        H[3] = UInt64_add(d, H[3]);
        H[4] = UInt64_add(e, H[4]);
        H[5] = UInt64_add(f, H[5]);
        H[6] = UInt64_add(g, H[6]);
        H[7] = UInt64_add(h, H[7]);
    }

    // The SHA-512 hash is composed of 8 64-bit values.  We can store it as
    // an array of 16 32-bit big-endian integer values.
    var hash = new Array(16);
    for (var i = 0; i < 8; ++i) {
        hash[(2 * i)    ] = H[i].hi;
        hash[(2 * i) + 1] = H[i].lo;
    }

    // Convert the 32-bit array values to a hex string.
    var hashOutput = "";
    var hexValues = "0123456789abcdef";
    var code = 0x00;

    for (var i = 0; i < (hash.length * 32); i += 8) {
        code = (hash[i >> 5] >>> (24 - (i % 32))) & 0xff;

        hashOutput +=   hexValues.charAt((code >>> 4) & 0x0f)
                      + hexValues.charAt( code        & 0x0f);
    }

    return hashOutput;
}

/**
 *  Add two 64-bit values.
 *
 *  @param x The first addend.
 *  @param y The second addend.
 *  @returns The sum of the two 64-bit values.
*/
function UInt64_add (x, y) {

    var output = new UInt64_t(0, 0);

    // The operations will be performed on four 2-byte (16-bit) half-words.
    // This will allow us to left-shift the values by 16-bits while avoiding
    // overflow in the later operations.
    var hw = new Array (4);

    // The (hw[(0...2)] >>> 16) operations handle the carry operation.
    // (Recall: '>>>' is the zero-fill right-shift operator.)
    hw[0] = (x.lo & 0xffff) + (y.lo & 0xffff);
    hw[1] = (x.lo >>> 16)   + (y.lo >>> 16)   + (hw[0] >>> 16);
    hw[2] = (x.hi & 0xffff) + (y.hi & 0xffff) + (hw[1] >>> 16);
    hw[3] = (x.hi >>> 16)   + (y.hi >>> 16)   + (hw[2] >>> 16);

    // Concatenate the half-words into the 64-bit integer.
    output.hi = (hw[3] << 16) | (hw[2] & 0xffff);
    output.lo = (hw[1] << 16) | (hw[0] & 0xffff);

    return output;
}

/**
 *  This function pads the given message such that it can be evenly
 *  divided into 32-byte blocks.
 *
 *  @param message The message that is to be hashed.
 *  @returns The padded message as an array of 32-bit big-endian words.
 *
 *  @see FIPS 180-2, Section 5.1.2, p. 12.
*/
function padMessage (message) {

    var length = message.length;
    var bits = length * 8;

    // Per FIPS 180-2, we need to pad the message with 0x80 as the first byte
    // following the message contents.  16 bytes are appended to the end of
    // the block to store the message size and zeros are padded to make the
    // block length a multiple of 1024.

    // To make this easier, we'll store the message as an
    // array of 32-bit words.
    var numWords = (length >> 2) + 1;
    var paddedMessage = new Array (numWords);

    var blocks = Math.ceil(numWords / 32);
    for (var i = 0; i < (blocks * 32); ++i)
        paddedMessage[i] = 0x00000000;

    // Concatenate the message bytes into 32-bit big-endian words.
    for (var i = 0; i < bits; i += 8) {
        paddedMessage[i >> 5] |=
            (message.charCodeAt(i / 8) & 0xff) << (24 - (i % 32));
    }

    // The number of bits in the padded message.
    var padStart = bits >> 5;
    var trailerStart = (((bits + 128) >> 10) << 5) + 31;

    paddedMessage[padStart] |= (0x80 << (24 - (bits & 0x1f)));
    paddedMessage[trailerStart] = bits;

    return paddedMessage;
}

/**
 *  This function initializes the SHA-512 message hash based on FIPS 180-2.
 *
 *  @returns An array of 8 64-bit integers representing the initial hash.
 *
 *  @see FIPS 180-2, Section 5.3.4, p. 14.
*/
function initializeHash () {

    // From FIPS 180-2, section 5.3.4, the SHA-512 initial hash value consists
    // of the following eight 64-bit words:
    var h_zero = new Array ( new UInt64_t(0x6a09e667, 0xf3bcc908),
                             new UInt64_t(0xbb67ae85, 0x84caa73b),
                             new UInt64_t(0x3c6ef372, 0xfe94f82b),
                             new UInt64_t(0xa54ff53a, 0x5f1d36f1),
                             new UInt64_t(0x510e527f, 0xade682d1),
                             new UInt64_t(0x9b05688c, 0x2b3e6c1f),
                             new UInt64_t(0x1f83d9ab, 0xfb41bd6b),
                             new UInt64_t(0x5be0cd19, 0x137e2179));

    return h_zero;
}

/**
 *  This function initializes the hash constants used by the SHA-512
 *  algorithm per the values in FIPS 180-2.
 *
 *  @returns The array of 80 hash constants.
 *
 *  @see FIPS 180-2, Section 4.2.3, pp. 10-11.
*/
function initializeHashConstants () {

    var sha512_constants = new Array (

    // Indices 00-15
    new UInt64_t(0x428a2f98, 0xd728ae22), new UInt64_t(0x71374491, 0x23ef65cd),
    new UInt64_t(0xb5c0fbcf, 0xec4d3b2f), new UInt64_t(0xe9b5dba5, 0x8189dbbc),
    new UInt64_t(0x3956c25b, 0xf348b538), new UInt64_t(0x59f111f1, 0xb605d019),
    new UInt64_t(0x923f82a4, 0xaf194f9b), new UInt64_t(0xab1c5ed5, 0xda6d8118),
    new UInt64_t(0xd807aa98, 0xa3030242), new UInt64_t(0x12835b01, 0x45706fbe),
    new UInt64_t(0x243185be, 0x4ee4b28c), new UInt64_t(0x550c7dc3, 0xd5ffb4e2),
    new UInt64_t(0x72be5d74, 0xf27b896f), new UInt64_t(0x80deb1fe, 0x3b1696b1),
    new UInt64_t(0x9bdc06a7, 0x25c71235), new UInt64_t(0xc19bf174, 0xcf692694),

    // Indices 16-31
    new UInt64_t(0xe49b69c1, 0x9ef14ad2), new UInt64_t(0xefbe4786, 0x384f25e3),
    new UInt64_t(0x0fc19dc6, 0x8b8cd5b5), new UInt64_t(0x240ca1cc, 0x77ac9c65),
    new UInt64_t(0x2de92c6f, 0x592b0275), new UInt64_t(0x4a7484aa, 0x6ea6e483),
    new UInt64_t(0x5cb0a9dc, 0xbd41fbd4), new UInt64_t(0x76f988da, 0x831153b5),
    new UInt64_t(0x983e5152, 0xee66dfab), new UInt64_t(0xa831c66d, 0x2db43210),
    new UInt64_t(0xb00327c8, 0x98fb213f), new UInt64_t(0xbf597fc7, 0xbeef0ee4),
    new UInt64_t(0xc6e00bf3, 0x3da88fc2), new UInt64_t(0xd5a79147, 0x930aa725),
    new UInt64_t(0x06ca6351, 0xe003826f), new UInt64_t(0x14292967, 0x0a0e6e70),

    // Indices 32-47
    new UInt64_t(0x27b70a85, 0x46d22ffc), new UInt64_t(0x2e1b2138, 0x5c26c926),
    new UInt64_t(0x4d2c6dfc, 0x5ac42aed), new UInt64_t(0x53380d13, 0x9d95b3df),
    new UInt64_t(0x650a7354, 0x8baf63de), new UInt64_t(0x766a0abb, 0x3c77b2a8),
    new UInt64_t(0x81c2c92e, 0x47edaee6), new UInt64_t(0x92722c85, 0x1482353b),
    new UInt64_t(0xa2bfe8a1, 0x4cf10364), new UInt64_t(0xa81a664b, 0xbc423001),
    new UInt64_t(0xc24b8b70, 0xd0f89791), new UInt64_t(0xc76c51a3, 0x0654be30),
    new UInt64_t(0xd192e819, 0xd6ef5218), new UInt64_t(0xd6990624, 0x5565a910),
    new UInt64_t(0xf40e3585, 0x5771202a), new UInt64_t(0x106aa070, 0x32bbd1b8),

    // Indices 48-63
    new UInt64_t(0x19a4c116, 0xb8d2d0c8), new UInt64_t(0x1e376c08, 0x5141ab53),
    new UInt64_t(0x2748774c, 0xdf8eeb99), new UInt64_t(0x34b0bcb5, 0xe19b48a8),
    new UInt64_t(0x391c0cb3, 0xc5c95a63), new UInt64_t(0x4ed8aa4a, 0xe3418acb),
    new UInt64_t(0x5b9cca4f, 0x7763e373), new UInt64_t(0x682e6ff3, 0xd6b2b8a3),
    new UInt64_t(0x748f82ee, 0x5defb2fc), new UInt64_t(0x78a5636f, 0x43172f60),
    new UInt64_t(0x84c87814, 0xa1f0ab72), new UInt64_t(0x8cc70208, 0x1a6439ec),
    new UInt64_t(0x90befffa, 0x23631e28), new UInt64_t(0xa4506ceb, 0xde82bde9),
    new UInt64_t(0xbef9a3f7, 0xb2c67915), new UInt64_t(0xc67178f2, 0xe372532b),

    // Indices 64-79
    new UInt64_t(0xca273ece, 0xea26619c), new UInt64_t(0xd186b8c7, 0x21c0c207),
    new UInt64_t(0xeada7dd6, 0xcde0eb1e), new UInt64_t(0xf57d4f7f, 0xee6ed178),
    new UInt64_t(0x06f067aa, 0x72176fba), new UInt64_t(0x0a637dc5, 0xa2c898a6),
    new UInt64_t(0x113f9804, 0xbef90dae), new UInt64_t(0x1b710b35, 0x131c471b),
    new UInt64_t(0x28db77f5, 0x23047d84), new UInt64_t(0x32caab7b, 0x40c72493),
    new UInt64_t(0x3c9ebe0a, 0x15c9bebc), new UInt64_t(0x431d67c4, 0x9c100d4c),
    new UInt64_t(0x4cc5d4be, 0xcb3e42b6), new UInt64_t(0x597f299c, 0xfc657e2a),
    new UInt64_t(0x5fcb6fab, 0x3ad6faec), new UInt64_t(0x6c44198c, 0x4a475817)

        );  // Closing parenthesis of sha512_constants = new Array(...);

    return sha512_constants;

}  // End function initializeHashConstants().

/**
 *  Test the SHA-512 implementation with the test value from the standard.
 *
 *  @returns true If the calculated hash equals the given value.
 *
 *  @see FIPS 180-2, Appendix C, Section C.1.
*/
function testSHA512 () {
    // If the calculated SHA512 hash equals the test value defined in
    // FIPS 180-2, Appendix C, section C.1 (p. 45) then the implementation
    // is correct.
    return sha512("abc") ==
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
}

/*******************************************************************************
**                       64-Bit Integer Pseudoclass                           **
*******************************************************************************/

/**
 *  Since JS doesn't have an intrinsic 64-bit integer, we need to create one.
 *  This pseudo-class will emulate the functionality of an intrinsic unsigned
 *  64-bit integer.
 *
 *  @param hiWord The most-significant 32-bits of the integer.
 *  @param loWord The least-significant 32-bits of the integer.
*/
function UInt64_t (hiWord, loWord) {
    this.hi = hiWord;
    this.lo = loWord;
}

/**
 *  Copy the "members" of 64-bit integer into another.
 *
 *  @param dst The 64-bit value that is to receive the copied values.
 *  @param src The 64-bit value that supplies the values to copy.
*/
function UInt64_copy (dst, src) {
    dst.hi = src.hi;
    dst.lo = src.lo;
}

/**
 *  Bitwise right-shift a UInt64_t value.
 *
 *  @param recv The UInt64_t "object" to receive the shifted value.
 *  @param value The value that is to be shifted.
 *  @param shift The number of bits by which the value is to be shifted.
 *  @returns Nothing.
*/
function UInt64_rightShift (recv, value, shift) {

    if (shift < 32) {
        recv.lo = (value.lo >>> shift) | (value.hi << (32 - shift));
        recv.hi = (value.hi >>> shift);
    }

    else if (shift < 64 ) {
        recv.lo = value.hi << (64 - shift);
        recv.hi = 0x00000000;
    }

    else {
        recv.lo = 0x00000000;
        recv.hi = 0x00000000;
    }
}

/**
 *  Bitwise right-circular shift (rotate) a UInt64_t value.
 *
 *  @param recv The UInt64_t "object" to receive the shifted value.
 *  @param value The value that is to be shifted.
 *  @param shift The number of bits by which the value is to be shifted.
 *  @returns Nothing.
*/
function UInt64_rightRotate (recv, value, shift) {

    if (shift < 32) {
        recv.lo = (value.lo >>> shift) | (value.hi << (32 - shift));
        recv.hi = (value.hi >>> shift) | (value.lo << (32 - shift));
    }

    else if (shift < 64) {
        recv.lo = (value.hi >>> (shift - 32)) | (value.lo << (64 - shift));
        recv.hi = (value.lo >>> (shift - 32)) | (value.hi << (64 - shift));
    }

    else {
        recv.lo = 0x00000000;
        recv.hi = 0x00000000;
    }
}