using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {

        public string getString(string temp)
        {
            string ans = "";
            for(int i = 2; i < temp.Length; i += 2)
            {
                string curHex = temp.Substring(i, 2);
                char curChar = (char)Convert.ToInt32(curHex, 16);

                ans += curChar;
            }

            return ans;
        }
        public string decToHexa(int n)
        {
            
            char[] hexaDeciNum =
                   new char[100];

            int i = 0;

            while (n != 0)
            {
                
                int temp = 0;

                
                temp = n % 16;

                if (temp < 10)
                {
                    hexaDeciNum[i] =
                        (char)(temp + 48);
                    i++;
                }
                else
                {
                    hexaDeciNum[i] =
                        (char)(temp + 87);
                    i++;
                }

                n = n / 16;
            }

            string ans = "";

          
            for (int j = i - 1;
                    j >= 0; j--)
            {
                ans += hexaDeciNum[j];
            }

            return ans;
        }

        public string getHex(string temp)
        {
            string ans = "0x";
            for(int i = 0; i < temp.Length; i++)
            {
                int t = (int)temp[i];
                string curHex = decToHexa(t);
                ans += curHex;
            }
            return ans;
        }
        public override string Decrypt(string cipherText, string key)
        {
            string plainText = cipherText;
            bool wasHex = false;
            if (plainText.Length >= 2 && plainText[0] == '0' && plainText[1] == 'x')
            {
                plainText = getString(plainText);
                key = getString(key);
                wasHex = true;
            }
            
            // vector<int> S(256, 0);
            List<int> S = new List<int>();
            for (int i = 0; i < 256; i++) S.Add(i);
            List<int> T = new List<int>(256);
            for (int i = 0; i < 256; i++) T.Add((int)(key[i % (int)key.Length]));
            // initial permutation
            {
                int j = 0;
                for (int i = 0; i < 256; i++)
                {
                    j = (j + S[i] + T[i]) % 256;
                    var temp = S[i];
                    S[i] = S[j];
                    S[j] = temp;
                }
            }
            {
                string answer = "";
                int i = 0, j = 0, c = 0;
                while (c < plainText.Length)
                {
                    i = (i + 1) % 256;
                    j = (j + S[i]) % 256;
                    var temp = S[i];
                    S[i] = S[j];
                    S[j] = temp;
                    int t = (S[i] + S[j]) % 256;
                    int k = S[t];
                    int p = plainText[c];
                    char nextChar = (char)(p ^ k);
                    answer += nextChar;
                    c++;
                }
                string st = answer;
                if(wasHex)
                {
                    answer = getHex(answer);
                }

                return answer;
            }
        }

        public override string Encrypt(string plainText, string key)
        {
            bool wasHex = false;
            if (plainText.Length >= 2 && plainText[0] == '0' && plainText[1] == 'x')
            {
                plainText = getString(plainText);
                key = getString(key);
                wasHex = true;
            }

            // vector<int> S(256, 0);
            List<int> S = new List<int>();
            for (int i = 0; i < 256; i++) S.Add(i);
            List<int> T = new List<int>(256);
            for (int i = 0; i < 256; i++) T.Add((int)(key[i % (int)key.Length]));
            // initial permutation
            {
                int j = 0;
                for (int i = 0; i < 256; i++)
                {
                    j = (j + S[i] + T[i]) % 256;
                    var temp = S[i];
                    S[i] = S[j];
                    S[j] = temp;
                }
            }
            {
                string answer = "";
                int i = 0, j = 0, c = 0;
                while (c < plainText.Length)
                {
                    i = (i + 1) % 256;
                    j = (j + S[i]) % 256;
                    var temp = S[i];
                    S[i] = S[j];
                    S[j] = temp;
                    int t = (S[i] + S[j]) % 256;
                    int k = S[t];
                    int p = plainText[c];
                    char nextChar = (char)(p ^ k);
                    answer += nextChar;
                    c++;
                }
                string st = answer;
                if (wasHex)
                {
                    answer = getHex(answer);
                }

                return answer;
            }
        }
         
    }
}
