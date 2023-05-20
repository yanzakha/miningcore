using System;
using MiningCore.Contracts;
using MiningCore.Native;

namespace MiningCore.Crypto.Hashing.Algorithms;
{
    public unsafe class Lyra2Z : IHashAlgorithm
    {
        public byte[] Digest(byte[] data, params object[] extra)
        {
            Contract.RequiresNonNull(data, nameof(data));
            Contract.Requires<ArgumentException>(data.Length == 80, $"{nameof(data)} must be exactly 80 bytes long");

            var result = new byte[32];

            fixed(byte* input = data)
            {
                fixed(byte* output = result)
                {
                    LibMultihash.lyra2z(input, output);
                }
            }

            return result;
        }
    }
}
