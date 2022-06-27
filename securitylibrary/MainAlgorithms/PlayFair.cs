using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            char[,] a = new char[5, 5];
            bool[] vis = new bool[26];

            int[] mp = new int[26];
            for (int i = 0; i < 26; i++)
            {
                if ((char)(i + 'a') == 'j') mp[i] = i - 1;
                else mp[i] = i;
            }

            for (int i = 0; i < 26; i++) vis[i] = false;


            int idx = 0;
            for (int i = 0; i < key.Length; i++)
            {
                int x = mp[key[i] - 'a'];
                if (vis[x] == true) continue;
                vis[x] = true;
                int r = idx / 5, c = idx % 5;
                a[r, c] = (char)('a' + x);
                idx++;
            }

            for (char c = 'a'; c <= 'z'; c++)
            {
                int x = mp[c - 'a'];
                if (vis[x] == true) continue;
                vis[x] = true;
                int r = idx / 5, col = idx % 5;
                a[r, col] = c;
                idx++;
            }

            string plain = "";
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                int x = mp[cipherText[i] - 'a'];
                int y = mp[cipherText[i + 1] - 'a'];
                
                int r1 = 0, c1 = 0, r2 = 0, c2 = 0;
                for (int k = 0; k < 5; k++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if ((a[k, j] - 'a') == x)
                        {
                            r1 = k;
                            c1 = j;
                        }
                        if (a[k, j] - 'a' == y)
                        {
                            r2 = k;
                            c2 = j;
                        }
                    }
                }
                // check if same row
                if (r1 == r2)
                {
                    c1 = (c1 + 4) % 5;
                    c2 = (c2 + 4) % 5;
                    plain += a[r1, c1];
                    plain += a[r2, c2];
                }
                // check if same coloumn
                else if (c1 == c2)
                {
                    r1 = (r1 + 4) % 5;
                    r2 = (r2 + 4) % 5;
                    plain += a[r1, c1];
                    plain += a[r2, c2];
                }
                else
                {
                    plain += a[r1, c2];
                    plain += a[r2, c1];
                }
            }

            string ret = "";

            for (int i = plain.Length - 2; i >= 0; i -= 2)
            {
                char A = plain[i];
                char B = plain[i + 1];
                if(B == 'x' && i + 2 == plain.Length)
                {
                    ret += A;
                }
                else if(B == 'x' && plain[i + 2] == A)
                {
                    ret += A;
                }
                else
                {
                    ret += B;
                    ret += A;
                }
            }
            string rev = "";
            for (int i = ret.Length - 1; i >= 0; i--) rev += ret[i];


            return rev;
        }
        public string Encrypt(string plainText, string key)
        {
            
            char[,] a = new char[5, 5];
            bool[] vis = new bool[26];

            int[] mp = new int[26];
            for(int i = 0; i < 26; i++)
            {
                if ((char)(i + 'a') == 'j') mp[i] = i - 1;
                else mp[i] = i;
            }

            for (int i = 0; i < 26; i++) vis[i] = false;
           

            int idx = 0;
            for(int i = 0; i < key.Length; i++)
            {
                int x = mp[key[i] - 'a'];
                if(vis[x] == true) continue;
                vis[x] = true;
                int r = idx / 5, c = idx % 5;
                a[r, c] = (char) ('a' + x);
                idx++;
            }

            for(char c = 'a'; c <= 'z'; c++)
            {
                int x = mp[c - 'a'];
                if (vis[x] == true) continue;
                vis[x] = true;
                int r = idx / 5, col = idx % 5;
                a[r, col] = c;
                idx++;
            }
            string cipher = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int x = mp[plainText[i] - 'a'], y;
                if (i + 1 < plainText.Length)
                {
                    if (plainText[i] == plainText[i + 1]) y = mp['x' - 'a'];

                    else
                    {
                        y = mp[plainText[i + 1] - 'a'];
                        i++;
                    }
                }
                else
                {
                    y = mp['x' - 'a'];
                }
                int r1 = 0, c1 = 0, r2 = 0, c2 = 0;
                for(int k = 0; k < 5; k++)
                {
                    for(int j = 0; j < 5; j++)
                    {
                        if((a[k, j] - 'a') == x)
                        {
                            r1 = k;
                            c1 = j;
                        }
                        if (a[k, j] - 'a' == y)
                        {
                            r2 = k;
                            c2 = j;
                        }
                    }
                }
                // check if same row
                if (r1 == r2)
                {
                    c1 = (c1 + 1) % 5;
                    c2 = (c2 + 1) % 5;
                    cipher += a[r1, c1];
                    cipher += a[r2, c2];
                }
                // check if same coloumn
                else if(c1 == c2)
                {
                    r1 = (r1 + 1) % 5;
                    r2 = (r2 + 1) % 5;
                    cipher += a[r1, c1];
                    cipher += a[r2, c2];
                }
                else
                {
                    cipher += a[r1, c2];
                    cipher += a[r2, c1];
                }
            }

            return cipher.ToUpper();
        }
    }
}
