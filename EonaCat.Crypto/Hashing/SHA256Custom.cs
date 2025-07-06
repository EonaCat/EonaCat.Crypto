internal static class SHA256Custom
{
    // SHA-256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
    private static readonly uint[] _k = new uint[]
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    private static readonly uint[] _h0 = new uint[]
    {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    public static byte[] ComputeHash(byte[] data)
    {
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        // 1. Pre-processing (Padding)
        byte[] padded = Pad(data);

        // 2. Initialize hash values
        uint[] H = new uint[8];
        Array.Copy(_h0, H, 8);

        // 3. Process the message in successive 512-bit chunks (64 bytes)
        int blockCount = padded.Length / 64;
        for (int i = 0; i < blockCount; i++)
        {
            uint[] W = new uint[64];
            // Copy chunk into first 16 words W[0..15] as big-endian
            for (int t = 0; t < 16; t++)
            {
                int index = (i * 64) + (t * 4);
                W[t] = (uint)(padded[index] << 24 | padded[index + 1] << 16 | padded[index + 2] << 8 | padded[index + 3]);
            }

            // Extend the first 16 words into the remaining 48 words W[16..63]
            for (int t = 16; t < 64; t++)
            {
                uint s0 = RotateRight(W[t - 15], 7) ^ RotateRight(W[t - 15], 18) ^ (W[t - 15] >> 3);
                uint s1 = RotateRight(W[t - 2], 17) ^ RotateRight(W[t - 2], 19) ^ (W[t - 2] >> 10);
                W[t] = W[t - 16] + s0 + W[t - 7] + s1;
            }

            // Initialize working variables a,b,c,d,e,f,g,h with current hash value
            uint a = H[0];
            uint b = H[1];
            uint c = H[2];
            uint d = H[3];
            uint e = H[4];
            uint f = H[5];
            uint g = H[6];
            uint h = H[7];

            // Main compression function
            for (int t = 0; t < 64; t++)
            {
                uint S1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
                uint ch = (e & f) ^ (~e & g);
                uint temp1 = h + S1 + ch + _k[t] + W[t];
                uint S0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
                uint maj = (a & b) ^ (a & c) ^ (b & c);
                uint temp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            // Add the compressed chunk to the current hash value
            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
            H[5] += f;
            H[6] += g;
            H[7] += h;
        }

        // 4. Produce the final hash value (big-endian)
        byte[] hash = new byte[32];
        for (int i = 0; i < 8; i++)
        {
            hash[i * 4] = (byte)((H[i] >> 24) & 0xff);
            hash[i * 4 + 1] = (byte)((H[i] >> 16) & 0xff);
            hash[i * 4 + 2] = (byte)((H[i] >> 8) & 0xff);
            hash[i * 4 + 3] = (byte)(H[i] & 0xff);
        }

        return hash;
    }

    private static byte[] Pad(byte[] data)
    {
        ulong bitLen = (ulong)data.Length * 8;

        // Padding: append '1' bit then zero bits until message length ≡ 448 mod 512
        int padLen = 64 - (int)((data.Length + 8) % 64);
        if (padLen == 0)
        {
            padLen = 64;
        }

        byte[] padded = new byte[data.Length + padLen + 8];
        Array.Copy(data, padded, data.Length);

        padded[data.Length] = 0x80; // append '1' bit

        // Append length as 64-bit big-endian
        for (int i = 0; i < 8; i++)
        {
            padded[padded.Length - 1 - i] = (byte)((bitLen >> (8 * i)) & 0xff);
        }

        return padded;
    }

    private static uint RotateRight(uint x, int n)
    {
        return (x >> n) | (x << (32 - n));
    }
}
