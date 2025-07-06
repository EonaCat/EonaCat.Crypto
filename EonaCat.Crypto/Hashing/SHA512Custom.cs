using System.Text;

internal class SHA512Custom
{
    // Constants as per SHA512 spec
    private static readonly ulong[] _k = new ulong[]
    {
        0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
        0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
        0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
        0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
        0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
        0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
        0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
        0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
        0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
        0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
        0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
        0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
        0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
        0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
        0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
        0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
        0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
        0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
        0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
        0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
    };

    private static ulong ROTR(ulong x, int n) => (x >> n) | (x << (64 - n));
    private static ulong SHR(ulong x, int n) => x >> n;

    private static ulong Ch(ulong x, ulong y, ulong z) => (x & y) ^ (~x & z);
    private static ulong Maj(ulong x, ulong y, ulong z) => (x & y) ^ (x & z) ^ (y & z);

    private static ulong Sigma0(ulong x) => ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
    private static ulong Sigma1(ulong x) => ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
    private static ulong sigma0(ulong x) => ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7);
    private static ulong sigma1(ulong x) => ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6);

    private static byte[] PadMessage(byte[] message)
    {
        ulong bitLength = (ulong)message.Length * 8;

        // Padding: append 0x80, then 0x00 bytes until length mod 128 == 112
        int paddingLength = 128 - (int)((message.Length + 16) % 128);
        if (paddingLength == 0)
        {
            paddingLength = 128;
        }

        byte[] padded = new byte[message.Length + paddingLength + 16];
        Array.Copy(message, padded, message.Length);

        padded[message.Length] = 0x80;
        // Last 16 bytes = length in bits, big-endian
        for (int i = 0; i < 16; i++)
        {
            padded[padded.Length - 1 - i] = (byte)((bitLength >> (8 * i)) & 0xFF);
        }

        return padded;
    }

    public static byte[] ComputeHash(byte[] message)
    {
        // Initial Hash Values (H0-H7) as per SHA512 spec
        ulong[] H = new ulong[]
        {
            0x6a09e667f3bcc908UL,
            0xbb67ae8584caa73bUL,
            0x3c6ef372fe94f82bUL,
            0xa54ff53a5f1d36f1UL,
            0x510e527fade682d1UL,
            0x9b05688c2b3e6c1fUL,
            0x1f83d9abfb41bd6bUL,
            0x5be0cd19137e2179UL
        };

        byte[] padded = PadMessage(message);

        ulong[] W = new ulong[80];

        for (int chunkIndex = 0; chunkIndex < padded.Length / 128; chunkIndex++)
        {
            // Prepare message schedule W
            for (int t = 0; t < 16; t++)
            {
                int start = chunkIndex * 128 + t * 8;
                W[t] = ((ulong)padded[start] << 56)
                     | ((ulong)padded[start + 1] << 48)
                     | ((ulong)padded[start + 2] << 40)
                     | ((ulong)padded[start + 3] << 32)
                     | ((ulong)padded[start + 4] << 24)
                     | ((ulong)padded[start + 5] << 16)
                     | ((ulong)padded[start + 6] << 8)
                     | ((ulong)padded[start + 7]);
            }
            for (int t = 16; t < 80; t++)
            {
                W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
            }

            // Initialize working vars
            ulong a = H[0];
            ulong b = H[1];
            ulong c = H[2];
            ulong d = H[3];
            ulong e = H[4];
            ulong f = H[5];
            ulong g = H[6];
            ulong h = H[7];

            // Main loop
            for (int t = 0; t < 80; t++)
            {
                ulong T1 = h + Sigma1(e) + Ch(e, f, g) + _k[t] + W[t];
                ulong T2 = Sigma0(a) + Maj(a, b, c);

                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }

            // Compute intermediate hash value
            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
            H[5] += f;
            H[6] += g;
            H[7] += h;
        }

        // Convert hash to byte array (big endian)
        byte[] hash = new byte[64];
        for (int i = 0; i < 8; i++)
        {
            hash[i * 8 + 0] = (byte)(H[i] >> 56);
            hash[i * 8 + 1] = (byte)(H[i] >> 48);
            hash[i * 8 + 2] = (byte)(H[i] >> 40);
            hash[i * 8 + 3] = (byte)(H[i] >> 32);
            hash[i * 8 + 4] = (byte)(H[i] >> 24);
            hash[i * 8 + 5] = (byte)(H[i] >> 16);
            hash[i * 8 + 6] = (byte)(H[i] >> 8);
            hash[i * 8 + 7] = (byte)(H[i]);
        }

        return hash;
    }

    public static string ToHexString(byte[] data)
    {
        StringBuilder stringBuilder = new StringBuilder();
        foreach (byte currentByte in data)
        {
            stringBuilder.AppendFormat("{0:x2}", currentByte);
        }

        return stringBuilder.ToString();
    }
}
