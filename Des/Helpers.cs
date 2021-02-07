using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace DesCrypto
{
    internal static class Helpers
    {
        public static BitArray Shuffle(this BitArray source, int[] table) 
            => new BitArray(table.Select(x => source[x - 1]).ToArray());

        public static int ToSingleInt(this BitArray source)
        {
            if (source.Length > 32)
                throw new ArgumentException("Argument length shall be at most 32 bits.");

            var array = new int[1];
            source.CopyTo(array, 0);
            return array[0];
        }

        public static IEnumerable<BitArray> SplitBy(this BitArray source, int by)
        {
            if (source.Length % by != 0)
                throw new ArgumentException("Source array cannot be divided by provided value", nameof(by));

            var blocks = new List<BitArray>();
            for (var i = 0; i < source.Length / by; i++)
                blocks.Add(new BitArray(Enumerable.Range(i * by, by).Select(x => source[x]).ToArray()));

            return blocks;
        }
    }
}
