namespace EonaCat.Crypto.Helpers
{
    public static class RandomNumberGeneratorCustom
    {
        // Generate a pseudo-random 32-byte output based on the input nonce
        public static byte[] ComputeHash(byte[] nonce)
        {
            if (nonce == null)
            {
                throw new ArgumentNullException(nameof(nonce));
            }

            // Internal state seed = nonce padded/truncated to 32 bytes
            byte[] state = new byte[32];
            int len = Math.Min(nonce.Length, 32);
            Array.Copy(nonce, state, len);
            if (len < 32)
            {
                for (int i = len; i < 32; i++)
                {
                    state[i] = 0;
                }
            }

            ulong counter = 0;

            // Prepare input = state || counter (8 bytes)
            byte[] input = new byte[40]; // 32 + 8
            Array.Copy(state, input, 32);

            // Append counter in big endian
            for (int i = 0; i < 8; i++)
            {
                input[39 - i] = (byte)(counter >> 8 * i & 0xFF);
            }

            // Compute hash output using our custom SHA256 implementation
            byte[] output = SHA256Custom.ComputeHash(input);

            return output;
        }
    }

}
