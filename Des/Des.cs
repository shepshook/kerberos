using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace DesCrypto
{
    public static class Des
    {
        private static List<BitArray> _subKeys;

        public static byte[] Encrypt(byte[] key, byte[] message)
            => Run(key, message);

        public static byte[] Decrypt(byte[] key, byte[] message)
            => Run(key, message, true);

        public static byte[] Encrypt<TIn>(byte[] key, TIn obj)
            => Encrypt(key, Encoding.UTF8.GetBytes(JsonSerializer.Serialize<TIn>(obj)));

        public static TOut Decrypt<TOut>(byte[] key, byte[] message)
        {
            var str = Encoding.UTF8.GetString(Decrypt(key, message));
            return JsonSerializer.Deserialize<TOut>(str);
        }

        private static byte[] Run(byte[] key, byte[] message, bool decrypt = false)
        {
            _subKeys = GenerateSubKeys(new BitArray(key));

            if (message.Length % 8 != 0)
            {
                var list = message.ToList();
                list.AddRange(Enumerable.Range(0, 8 - message.Length % 8).Select(x => (byte)x));
                message = list.ToArray();
            }

            var messageBlocks = new BitArray(message).SplitBy(64).ToArray();
            var result = new BitArray(message.Length * 8);

            for (var blockNumber = 0; blockNumber < messageBlocks.Length; blockNumber++)
            {
                var block = messageBlocks[blockNumber].Shuffle(Constants.Pi);
                var pair = block.SplitBy(32).ToArray();
                var left = pair[0];
                var right = pair[1];

                for (var i = 0; i < 16; i++)
                {
                    // expanding 32 bits into 48
                    var nextRight = right.Shuffle(Constants.E);
                    if (!decrypt)
                        nextRight.Xor(_subKeys[i]);
                    else
                        nextRight.Xor(_subKeys[^(i + 1)]);

                    nextRight = ApplySBoxes(nextRight);
                    nextRight = nextRight.Shuffle(Constants.P);
                    nextRight = nextRight.Xor(left);
                    left = right;
                    right = nextRight;
                }

                block = new BitArray(Enumerable.Range(0, 64).Select(x => x < 32 ? right[x] : left[x - 32]).ToArray());
                block = block.Shuffle(Constants.Pi1);
                for (var i = 0; i < 64; i++)
                {
                    result.Set(blockNumber * 64 + i, block[i]);
                }
            }

            var finalArray = new byte[message.Length];
            result.CopyTo(finalArray, 0);

            if (decrypt)
            {
                var tailLength = 1;
                // index from end
                var counter = 1;
                while (tailLength <= 7 && finalArray[^counter] - 1 == finalArray[^(counter + 1)]) 
                {
                    counter++;
                    tailLength++;
                }

                if (tailLength == 1 && finalArray[^1] != 0)
                    tailLength = 0;

                finalArray = finalArray.Take(finalArray.Length - tailLength).ToArray();
            }

            return finalArray;
        }

        private static BitArray ApplySBoxes(BitArray block)
        {
            var subblocks = block.SplitBy(6).ToArray();

            var result = new BitArray(32);
            for (var i = 0; i < subblocks.Count(); i++)
            {
                var subblock = subblocks[i];
                var row = new BitArray(new[] { subblock[0], subblock[^1] }).ToSingleInt();
                var col = new BitArray(Enumerable.Range(1, 4).Select(x => subblock[x]).ToArray()).ToSingleInt();

                var value = Constants.SBox[i, row, col];
                var bin = new BitArray(new int[] { value });
                for (var x = 0; x < 4; x++)
                    result.Set(i * 4 + x, bin[x]);
            }
            return result;
        }

        private static List<BitArray> GenerateSubKeys(BitArray key)
        {
            if (key.Length != 56)
                throw new ArgumentException("Key must be 56 bits long");

            bool[] castedKey = key.Cast<bool>().ToArray();

            // Bits are added at positions 8, 16, 24, 32, 40, 48, 56, 64 
            // of the key k so that each byte contains an odd number of ones 
            var expandedKey = new BitArray(Enumerable.Range(0, 64)
                .Select(x => (x + 1) % 8 != 0
                    ? key[x - x / 8]
                    : castedKey.Skip(x / 8 * 7).Take(7).Count(val => val == true) % 2 == 0)
                .ToArray());

            var k = expandedKey.Shuffle(Constants.Pc1);
            var pair = k.SplitBy(28).ToArray();
            var left = pair[0];
            var right = pair[1];

            var result = new List<BitArray>();

            for (var i = 0; i < 16; i++)
            {
                right = right.LeftShift(Constants.Shift[i]);
                left = left.LeftShift(Constants.Shift[i]);

                // combine right + left
                var ki = new BitArray(Enumerable.Range(0, 56).Select(x => x < 28 ? right[x] : left[x - 28]).ToArray());
                result.Add(ki.Shuffle(Constants.Pc2));
            }

            return result;
        }
    }
}
