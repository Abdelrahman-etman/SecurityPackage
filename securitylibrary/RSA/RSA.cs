using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int fastPower(int b, int power, int mod)
        {
            if (power == 0) return 1;
            long  ret = fastPower(b, power / 2, mod);
            ret = ret * ret % mod;
            if (power % 2 == 1) ret = ret * b % mod;
            
            return Convert.ToInt32(ret);
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            return fastPower(M, e, p * q);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            return fastPower(C, e, p * q);
        }
    }
}
