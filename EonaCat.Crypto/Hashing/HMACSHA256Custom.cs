namespace EonaCat.Crypto.Hashing
{
    internal class HMACSHA256Custom : IDisposable
    {
        private const int _blockSize = 64; // SHA256 block size in bytes

        private readonly byte[] _key;
        private readonly byte[] _opad;
        private readonly byte[] _ipad;

        private bool disposed = false;

        public HMACSHA256Custom(byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.Length > _blockSize)
            {
                key = SHA256Custom.ComputeHash(key);
            }

            this._key = new byte[_blockSize];
            Array.Copy(key, this._key, key.Length);

            _ipad = new byte[_blockSize];
            _opad = new byte[_blockSize];

            for (int i = 0; i < _blockSize; i++)
            {
                _ipad[i] = (byte)(this._key[i] ^ 0x36);
                _opad[i] = (byte)(this._key[i] ^ 0x5c);
            }
        }

        public byte[] ComputeHash(byte[] message)
        {
            if (disposed)
            {
                throw new ObjectDisposedException(nameof(HMACSHA256Custom));
            }

            byte[] innerInput = new byte[_ipad.Length + message.Length];
            Array.Copy(_ipad, 0, innerInput, 0, _ipad.Length);
            Array.Copy(message, 0, innerInput, _ipad.Length, message.Length);

            byte[] innerHash = SHA256Custom.ComputeHash(innerInput);

            byte[] outerInput = new byte[_opad.Length + innerHash.Length];
            Array.Copy(_opad, 0, outerInput, 0, _opad.Length);
            Array.Copy(innerHash, 0, outerInput, _opad.Length, innerHash.Length);

            return SHA256Custom.ComputeHash(outerInput);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    if (_key != null)
                    {
                        Array.Clear(_key, 0, _key.Length);
                    }

                    if (_ipad != null)
                    {
                        Array.Clear(_ipad, 0, _ipad.Length);
                    }

                    if (_opad != null)
                    {
                        Array.Clear(_opad, 0, _opad.Length);
                    }
                }
                disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }

}
