using EonaCat.Crypto.Hashing;
using EonaCat.Crypto.Helpers;
using System.Text;

namespace EonaCat.Crypto
{
    public class EonaCatCrypto
    {
        private static readonly string _fileIdentifier = "Encrypted by EonaCat.Crypto => ";

        private const int _blockSize = 64;  // 512-bit block
        private const int _keySize = 128;    // 1024-bit key
        private const int _numRounds = 48;
        private const int _nonceSize = 24;
        private const int _tagSize = 32;    // HMAC-SHA256 tag size

        private readonly byte[][] _roundKeys;
        private readonly byte[] _hmacKey;

        private static readonly byte[] _defaultSalt = RandomNumberGeneratorCustom.ComputeHash(Encoding.UTF8.GetBytes("EONACAT_CRYPTO_SPECIAL_KEY"));

        public EonaCatCrypto(string key, byte[] salt = null)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            try
            {
                salt ??= _defaultSalt;

                // Derive a master key using HKDF with the provided or default salt
                byte[] masterKey = HkdfSha512DeriveKey(keyBytes, salt, _keySize);

                try
                {
                    _roundKeys = ExpandRoundKeysHKDF(masterKey);
                    _hmacKey = HkdfSha512DeriveKey(masterKey, salt, _keySize, info: Encoding.UTF8.GetBytes("EonaCat HMAC Key"));
                }
                finally
                {
                    Array.Clear(masterKey, 0, masterKey.Length);
                }
            }
            finally
            {
                Array.Clear(keyBytes, 0, keyBytes.Length);
            }
        }

        private static byte[] HkdfSha512DeriveKey(byte[] inputKey, byte[] salt, int outputLength, byte[] info = null)
        {
            // HKDF Extract
            byte[] prk;
            using (var hmac = new HMACSHA512Custom(salt))
            {
                prk = hmac.ComputeHash(inputKey);
            }

            // HKDF Expand with optional info for domain separation
            var okm = HkdfExpand(prk, info, outputLength);

            Array.Clear(prk, 0, prk.Length); // Clear PRK for security

            return okm;
        }

        // Constructor from fixed-length byte array key + optional salt
        public EonaCatCrypto(byte[] key, byte[] salt = null)
        {
            if (key == null || key.Length != _keySize)
                throw new ArgumentException($"EonaCat.Crypto: Key must be {_keySize} bytes (1024 bits)");

            salt ??= _defaultSalt;

            // Use HKDF to expand round keys and derive HMAC key with salt
            _roundKeys = ExpandRoundKeysHKDF(key, salt);
            _hmacKey = DeriveHmacKeyHKDF(key, salt);

            Array.Clear(key, 0, key.Length);
        }

        public static void EncryptFile(string inputPath, string outputPath, EonaCatCrypto crypto)
        {
            if (!File.Exists(inputPath))
            {
                Console.WriteLine($"EonaCat.Crypto: Input file does not exist: {inputPath}");
                return;
            }

            byte[] fileBytes = File.ReadAllBytes(inputPath);          // Read original file bytes
            byte[] encryptedBytes = crypto.Encrypt(fileBytes);        // Encrypt file bytes
            File.WriteAllBytes(outputPath, encryptedBytes);           // Write encrypted bytes to output file
            Console.WriteLine($"EonaCat.Crypto: File encrypted: {outputPath}");
        }

        public static void DecryptFile(string inputPath, string outputPath, EonaCatCrypto crypto)
        {
            if (!File.Exists(inputPath))
            {
                Console.WriteLine($"EonaCat.Crypto: Input file does not exist: {inputPath}");
                return;
            }

            byte[] encryptedBytes = File.ReadAllBytes(inputPath);     // Read encrypted file bytes
            byte[] decryptedBytes = crypto.Decrypt(encryptedBytes);   // Decrypt file bytes
            File.WriteAllBytes(outputPath, decryptedBytes);           // Write decrypted bytes to output file
            Console.WriteLine($"EonaCat.Crypto: File decrypted: {outputPath}");
        }

        private static byte[] HkdfExpand(byte[] prk, byte[]? info, int outputLength)
        {
            const int hashLen = 64; // SHA512 output size in bytes
            int n = (int)Math.Ceiling((double)outputLength / hashLen);
            if (n > 255) throw new ArgumentOutOfRangeException(nameof(outputLength), "Output length too large");

            byte[] okm = new byte[outputLength];
            byte[] previousBlock = Array.Empty<byte>();

            int offset = 0;
            using (var hmac = new HMACSHA512Custom(prk))
            {
                for (byte i = 1; i <= n; i++)
                {
                    // Build input = previousBlock || info || i
                    int inputLength = previousBlock.Length + (info?.Length ?? 0) + 1;
                    byte[] input = new byte[inputLength];

                    int pos = 0;
                    if (previousBlock.Length > 0)
                    {
                        Buffer.BlockCopy(previousBlock, 0, input, pos, previousBlock.Length);
                        pos += previousBlock.Length;
                    }
                    if (info != null && info.Length > 0)
                    {
                        Buffer.BlockCopy(info, 0, input, pos, info.Length);
                        pos += info.Length;
                    }
                    input[pos] = i;

                    // Compute HMAC
                    previousBlock = hmac.ComputeHash(input);

                    int toCopy = Math.Min(hashLen, outputLength - offset);
                    Array.Copy(previousBlock, 0, okm, offset, toCopy);
                    offset += toCopy;
                }
            }

            // Clear sensitive buffer
            Array.Clear(previousBlock, 0, previousBlock.Length);

            return okm;
        }


        // --- HKDF Extract and Expand for Round Keys ---
        private static byte[][] ExpandRoundKeysHKDF(byte[] masterKey, byte[] salt = null)
        {
            // Generate salt if none provided
            if (salt == null || salt.Length != _keySize)
            {
                salt = new byte[_keySize];
                salt = RandomNumberGeneratorCustom.ComputeHash(salt);
            }

            byte[] info = Encoding.UTF8.GetBytes("EonaCatCrypto round key");

            byte[] prk;
            using (var hmacExtract = new HMACSHA512Custom(salt))
            {
                prk = hmacExtract.ComputeHash(masterKey);
            }

            byte[][] roundKeys = new byte[_numRounds][];
            using var hmacExpand = new HMACSHA512Custom(prk);

            byte[] previous = Array.Empty<byte>();
            for (int i = 0; i < _numRounds; i++)
            {
                byte[] input = new byte[previous.Length + info.Length + 1];
                Buffer.BlockCopy(previous, 0, input, 0, previous.Length);
                Buffer.BlockCopy(info, 0, input, previous.Length, info.Length);
                input[input.Length -1] = (byte)(i + 1);

                previous = hmacExpand.ComputeHash(input);
                roundKeys[i] = new byte[_blockSize];
                Array.Copy(previous, 0, roundKeys[i], 0, _blockSize);
            }

            // Zero out prk and previous for security
            Array.Clear(prk, 0, prk.Length);
            Array.Clear(previous, 0, previous.Length);

            return roundKeys;
        }

        // --- HKDF Derive Separate HMAC Key ---
        private static byte[] DeriveHmacKeyHKDF(byte[] masterKey, byte[] salt = null)
        {
            // Generate salt if none provided (64 bytes for SHA512 block size)
            if (salt == null || salt.Length == 0)
            {
                salt = new byte[64];
                salt = RandomNumberGeneratorCustom.ComputeHash(salt);
            }

            string signature = "Jeroen Saey - EonaCat";
            string infoString = $"EonaCat Crypto HMAC Key - Signed by {signature}";
            byte[] info = Encoding.UTF8.GetBytes(infoString);

            byte[] prk;
            using (var hmacExtract = new HMACSHA512Custom(salt))
            {
                prk = hmacExtract.ComputeHash(masterKey);
            }

            using var hmacExpand = new HMACSHA512Custom(prk);
            byte[] input = new byte[info.Length + 1];
            Buffer.BlockCopy(info, 0, input, 0, info.Length);
            input[input.Length - 1] = 1; // Counter byte

            byte[] okm = hmacExpand.ComputeHash(input);

            // Clear sensitive buffers
            Array.Clear(prk, 0, prk.Length);
            Array.Clear(input, 0, input.Length);

            byte[] hmacKey = new byte[32];
            Array.Copy(okm, 0, hmacKey, 0, 32);

            Array.Clear(okm, 0, okm.Length);

            return hmacKey;
        }

        // --- S-Box and Inverse S-Box ---
        private static readonly byte[] SBox = new byte[256]
        {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
        };

        private static readonly byte[] InvSBox = new byte[256]
        {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
        };

        // --- GF(2^8) multiplication for MixColumns ---
        private static byte GFMul(byte a, byte b)
        {
            byte p = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                bool hiBitSet = (a & 0x80) != 0;
                a <<= 1;
                if (hiBitSet)
                {
                    a ^= 0x1B;
                }

                b >>= 1;
            }
            return p;
        }

        // --- State transformations for encryption ---
        private static void SubBytes(byte[] state)
        {
            for (int i = 0; i < state.Length; i++)
            {
                state[i] = SBox[state[i]];
            }
        }

        private static void InvSubBytes(byte[] state)
        {
            for (int i = 0; i < state.Length; i++)
            {
                state[i] = InvSBox[state[i]];
            }
        }

        private static void ShiftRows(byte[] state)
        {
            // 4x8 rows, each 8 bytes: AES style ShiftRows (similar)
            // Shift rows by offsets 0,1,2,3
            byte[] temp = new byte[_blockSize];
            Array.Copy(state, temp, _blockSize);

            for (int r = 0; r < 4; r++)
            {
                for (int c = 0; c < 8; c++)
                {
                    state[r + 4 * c] = temp[r + 4 * ((c + r) % 8)];
                }
            }
        }

        private static void InvShiftRows(byte[] state)
        {
            byte[] temp = new byte[_blockSize];
            Array.Copy(state, temp, _blockSize);

            for (int r = 0; r < 4; r++)
            {
                for (int c = 0; c < 8; c++)
                {
                    state[r + 4 * c] = temp[r + 4 * ((c + 8 - r) % 8)];
                }
            }
        }

        private static void MixColumns(byte[] state)
        {
            for (int c = 0; c < 8; c++)
            {
                int i = c * 4;
                byte s0 = state[i];
                byte s1 = state[i + 1];
                byte s2 = state[i + 2];
                byte s3 = state[i + 3];

                byte t0 = (byte)(GFMul(s0, 2) ^ GFMul(s1, 3) ^ s2 ^ s3);
                byte t1 = (byte)(s0 ^ GFMul(s1, 2) ^ GFMul(s2, 3) ^ s3);
                byte t2 = (byte)(s0 ^ s1 ^ GFMul(s2, 2) ^ GFMul(s3, 3));
                byte t3 = (byte)(GFMul(s0, 3) ^ s1 ^ s2 ^ GFMul(s3, 2));

                state[i] = t0;
                state[i + 1] = t1;
                state[i + 2] = t2;
                state[i + 3] = t3;
            }
        }

        private static void InvMixColumns(byte[] state)
        {
            for (int c = 0; c < 8; c++)
            {
                int i = c * 4;
                byte s0 = state[i];
                byte s1 = state[i + 1];
                byte s2 = state[i + 2];
                byte s3 = state[i + 3];

                byte t0 = (byte)(GFMul(s0, 0x0e) ^ GFMul(s1, 0x0b) ^ GFMul(s2, 0x0d) ^ GFMul(s3, 0x09));
                byte t1 = (byte)(GFMul(s0, 0x09) ^ GFMul(s1, 0x0e) ^ GFMul(s2, 0x0b) ^ GFMul(s3, 0x0d));
                byte t2 = (byte)(GFMul(s0, 0x0d) ^ GFMul(s1, 0x09) ^ GFMul(s2, 0x0e) ^ GFMul(s3, 0x0b));
                byte t3 = (byte)(GFMul(s0, 0x0b) ^ GFMul(s1, 0x0d) ^ GFMul(s2, 0x09) ^ GFMul(s3, 0x0e));

                state[i] = t0;
                state[i + 1] = t1;
                state[i + 2] = t2;
                state[i + 3] = t3;
            }
        }

        // --- AddRoundKey ---
        private static void AddRoundKey(byte[] state, byte[] roundKey)
        {
            for (int i = 0; i < _blockSize; i++)
            {
                state[i] ^= roundKey[i];
            }
        }

        // --- Block Encryption ---
        public byte[] EncryptBlock(byte[] block)
        {
            if (block.Length != _blockSize)
            {
                throw new ArgumentException($"EonaCat.Crypto: Block size must be {_blockSize} bytes");
            }

            byte[] state = new byte[_blockSize];
            Array.Copy(block, state, _blockSize);

            AddRoundKey(state, _roundKeys[0]);
            for (int round = 1; round < _numRounds; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, _roundKeys[round]);
            }

            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, _roundKeys[_numRounds - 1]); // final round key (reused last key)

            return state;
        }

        // --- Block Decryption ---
        public byte[] DecryptBlock(byte[] block)
        {
            if (block.Length != _blockSize)
            {
                throw new ArgumentException($"EonaCat.Crypto: Block size must be {_blockSize} bytes");
            }

            byte[] state = new byte[_blockSize];
            Array.Copy(block, state, _blockSize);

            AddRoundKey(state, _roundKeys[_numRounds - 1]);
            InvShiftRows(state);
            InvSubBytes(state);

            for (int round = _numRounds - 2; round >= 0; round--)
            {
                AddRoundKey(state, _roundKeys[round]);
                InvMixColumns(state);
                InvShiftRows(state);
                InvSubBytes(state);
            }

            AddRoundKey(state, _roundKeys[0]);

            return state;
        }

        // --- CTR Mode Encryption/Decryption (same for both) ---
        private byte[] EncryptCTR(byte[] input, byte[] nonce)
        {
            if (nonce == null || nonce.Length != _nonceSize)
            {
                throw new ArgumentException($"EonaCat.Crypto: Nonce must be {_nonceSize} bytes");
            }

            byte[] output = new byte[input.Length];

            int blocks = (input.Length + _blockSize - 1) / _blockSize;

            for (int i = 0; i < blocks; i++)
            {
                byte[] counterBlock = new byte[_blockSize];
                Array.Copy(nonce, 0, counterBlock, 0, _nonceSize);

                // Counter big endian
                int ctr = i;
                counterBlock[_nonceSize + 0] = (byte)(ctr >> 24 & 0xFF);
                counterBlock[_nonceSize + 1] = (byte)(ctr >> 16 & 0xFF);
                counterBlock[_nonceSize + 2] = (byte)(ctr >> 8 & 0xFF);
                counterBlock[_nonceSize + 3] = (byte)(ctr & 0xFF);

                byte[] keystream = EncryptBlock(counterBlock);

                int blockSize = Math.Min(_blockSize, input.Length - i * _blockSize);
                for (int j = 0; j < blockSize; j++)
                {
                    output[i * _blockSize + j] = (byte)(input[i * _blockSize + j] ^ keystream[j]);
                }
            }

            return output;
        }

        // --- Public Encrypt method ---
        public byte[] Encrypt(byte[] plaintext)
        {
            if (plaintext == null)
            {
                throw new ArgumentNullException(nameof(plaintext));
            }

            byte[] nonce = new byte[_nonceSize];
            RandomNumberGeneratorCustom.ComputeHash(nonce);

            byte[] ciphertext = EncryptCTR(plaintext, nonce);

            // Authenticated data = nonce + length(4 bytes) + ciphertext
            byte[] lengthBytes = BitConverter.GetBytes(plaintext.Length);
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(lengthBytes);
            }

            byte[] dataToAuthenticate = new byte[_nonceSize + 4 + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, dataToAuthenticate, 0, _nonceSize);
            Buffer.BlockCopy(lengthBytes, 0, dataToAuthenticate, _nonceSize, 4);
            Buffer.BlockCopy(ciphertext, 0, dataToAuthenticate, _nonceSize + 4, ciphertext.Length);

            byte[] tag;
            using (var hmac = new HMACSHA256Custom(_hmacKey))
            {
                tag = hmac.ComputeHash(dataToAuthenticate);
            }

            byte[] result = new byte[dataToAuthenticate.Length + _tagSize];
            Buffer.BlockCopy(dataToAuthenticate, 0, result, 0, dataToAuthenticate.Length);
            Buffer.BlockCopy(tag, 0, result, dataToAuthenticate.Length, _tagSize);

            // Convert encrypted data to Base64 string
            string base64 = Convert.ToBase64String(result);

            // Prepare the final output: FileIdentifier + Base64 string
            string fullString = _fileIdentifier + base64;

            // Return UTF8 bytes of full string (identifier + base64)
            return Encoding.UTF8.GetBytes(fullString);
        }


        // --- Public Decrypt method ---
        public byte[] Decrypt(byte[] fileBytes)
        {
            if (fileBytes == null || fileBytes.Length == 0)
            {
                throw new ArgumentNullException(nameof(fileBytes));
            }

            // Convert bytes to string
            string fullString = Encoding.UTF8.GetString(fileBytes);

            // Check for file identifier at start
            if (!fullString.StartsWith(_fileIdentifier))
            {
                throw new Exception("EonaCat.Crypto: Invalid file format: missing file identifier");
            }

            // Remove the file identifier prefix
            string base64 = fullString.Substring(_fileIdentifier.Length);

            // Decode Base64 to encrypted data bytes
            byte[] ciphertextWithTag = Convert.FromBase64String(base64);

            if (ciphertextWithTag.Length < _nonceSize + 4 + _tagSize)
            {
                throw new ArgumentException("EonaCat.Crypto: Ciphertext too short");
            }

            int authDataLen = ciphertextWithTag.Length - _tagSize;

            byte[] tag = new byte[_tagSize];
            byte[] authData = new byte[authDataLen];

            Buffer.BlockCopy(ciphertextWithTag, authDataLen, tag, 0, _tagSize);
            Buffer.BlockCopy(ciphertextWithTag, 0, authData, 0, authDataLen);

            byte[] computedTag;
            using (var hmac = new HMACSHA256Custom(_hmacKey))
            {
                computedTag = hmac.ComputeHash(authData);
            }

            if (!ConstantTimeEquals(computedTag, tag))
            {
                throw new Exception("EonaCat.Crypto: Authentication failed (tag mismatch)");
            }

            // Extract nonce and length
            byte[] nonce = new byte[_nonceSize];
            Buffer.BlockCopy(authData, 0, nonce, 0, _nonceSize);

            byte[] lengthBytes = new byte[4];
            Buffer.BlockCopy(authData, _nonceSize, lengthBytes, 0, 4);
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(lengthBytes);
            }

            int plaintextLength = BitConverter.ToInt32(lengthBytes, 0);

            if (plaintextLength < 0 || plaintextLength > authDataLen - _nonceSize - 4)
            {
                throw new Exception("EonaCat.Crypto: Invalid plaintext length");
            }

            byte[] ciphertext = new byte[authDataLen - _nonceSize - 4];
            Buffer.BlockCopy(authData, _nonceSize + 4, ciphertext, 0, ciphertext.Length);

            byte[] plaintext = EncryptCTR(ciphertext, nonce);

            if (plaintext.Length != plaintextLength)
            {
                throw new Exception("EonaCat.Crypto: Plaintext length mismatch");
            }

            return plaintext;
        }


        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

    }
}