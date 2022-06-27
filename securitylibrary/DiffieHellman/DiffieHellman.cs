using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public int fastPower(int b, int power, int mod)
        {
            if (power == 0) return 1;
            long ret = fastPower(b, power / 2, mod);
            ret = ret * ret % mod;
            if (power % 2 == 1) ret = ret * b % mod;

            return Convert.ToInt32(ret);
        }
        /*
         int get(int m, int g, int private1, int private2) {
            int p1 = fp(g, private1, m);
            int p2 = fp(g, private2, m);

            int key1 = fp(p2, private1, m);
            int key2 = fp(p1, private2, m);
            assert(key1 == key2);
            return key1;
        }
        */

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int p1 = fastPower(alpha, xa, q);
            int p2 = fastPower(alpha, xb, q);

            int key1 = fastPower(p2, xa, q);
            int key2 = fastPower(p1, xb, q);

            List<int> keys = new List<int>();
            keys.Add(key1);
            keys.Add(key2);

            return keys;

        }
    }
}
