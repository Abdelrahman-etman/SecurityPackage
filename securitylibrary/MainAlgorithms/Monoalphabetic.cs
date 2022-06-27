using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            int[] a = new int[26];
            bool[] vis = new bool[26];
            for (int i = 0; i < 26; i++) vis[i] = false;
            for (int i = 0; i < 26; i++) a[i] = -1;
            for(int  i = 0; i < plainText.Length; i++)
            {
                int c = plainText[i] - 'a';
                int c2 = cipherText[i] - 'A';
                a[c] = c2;
                vis[c2] = true;
            }
            string key = "";
            for(int  i = 0; i < 26; i++)
            {
                if(a[i] == -1)
                {
                    for(int j = 0; j < 26; j++)
                    {
                        if(vis[j] == false)
                        {
                            vis[j] = true;
                            a[i] = j;
                            break;
                        }

                    }
                }
                key += (char)('a' + a[i]);
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string new_key = "";
            for(char c = 'a'; c <= 'z'; c++)
            {
                for(int j = 0; j < 26; j++)
                {
                    if(key[j] == c)
                    {
                        new_key += (char)('a' + j);
                        break;
                    }
                }
            }
            string plain = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int idx = cipherText[i] - 'A';
                plain += new_key[idx];
            }
            return plain;
        }
           
        public string Encrypt(string plainText, string key)
        {
            string cipher = "";
            for(int  i = 0; i < plainText.Length; i++)
            {
                int idx = plainText[i] - 'a';
                cipher += key[idx];
            }
            return cipher;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
               char[] idx = new char[26];
               int c = 0;
               idx[c++] = 'E';
               idx[c++] = 'T';	
               idx[c++] = 'A';	
               idx[c++] = 'O';	
               idx[c++] = 'I';	
               idx[c++] = 'N';	
               idx[c++] = 'S';	
               idx[c++] = 'R';	
               idx[c++] = 'H';	
               idx[c++] = 'L';	
               idx[c++] = 'D';	
               idx[c++] = 'C';	
               idx[c++] = 'U';	
               idx[c++] = 'M';	
               idx[c++] = 'F';	
               idx[c++] = 'P';	
               idx[c++] = 'G';	
               idx[c++] = 'W';	
               idx[c++] = 'Y';	
               idx[c++] = 'B';	
               idx[c++] = 'V';	
               idx[c++] = 'K';	
               idx[c++] = 'X';	
               idx[c++] = 'J';	
               idx[c++] = 'Q';
               idx[c++] = 'Z';

            int[] freq = new int[26];
            for (int i = 0; i < 26; i++) freq[i] = 0;
            for(int i = 0; i < cipher.Length; i++)
            {
                freq[cipher[i] - 'A']++;
            }

            int[] mp = new int[26];

            for(int i = 0; i < 26; i++)
            {
                int mx_idx = 0;
                for(int j = 0; j < 26; j++)
                {
                    if(freq[mx_idx] < freq[j])
                    {
                        mx_idx = j;
                    }
                }

                mp[mx_idx] = idx[i] - 'A';

                freq[mx_idx] = -1;
            }

            string plain = "";
            for(int i = 0; i < cipher.Length; i++)
            {
                plain += (char)(mp[cipher[i] - 'A'] + 'a');
            }

            return plain;

        }               
    }
}
