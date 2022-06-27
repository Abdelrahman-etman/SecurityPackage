using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {

            int[,] key = new int[2, 2];
            for (int i = 0; i < 2; i++)
            {
                List<int> a = new List<int>();
                List<int> b = new List<int>();
                List<int> d = new List<int>();
                for (int j = 0; j < plainText.Count; j += 2)
                {
                    a.Add(plainText[j]);
                    b.Add(plainText[j + 1]);
                    d.Add(cipherText[j + i]);
                }
                bool found_row = false;
                for (int A = 0; A < 26 && found_row == false; A++)
                {
                    for (int B = 0; B < 26 && found_row == false; B++)
                    {
                            bool found = false;
                            for (int j = 0; j < a.Count; j++)
                            {
                                int x = (A * a[j] + B * b[j]) % 26;
                                if (x != d[j])
                                {
                                    found = true;
                                }
                            }
                            if (found == false)
                            {
                                found_row = true;

                                key[i, 0] = A;
                                key[i, 1] = B;
                            }
                    }
                }
                if (found_row == false)
                {
                    /// there is no key;
                    throw new InvalidAnlysisException();
                }
            }
            List<int> ans = new List<int>();
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    ans.Add(key[i, j]);
                }
            }
            return ans;
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int m2 = key.Count;
            int m = (int) Math.Sqrt(m2);
            int [,] key_matrix = new int[m, m];
            for(int i = 0; i < m2; i++)
            {
                int r = i / m, c = i % m;
                key_matrix[r, c] = key[i];
            }
            int[,] key_inv = new int[m, m];
            bool found = false;
            /// To find the inverse
            int det = 0, det_inv = -1;
            if(m2 == 4)
            {
                int a = key_matrix[0, 0], b = key_matrix[0, 1];
                int c = key_matrix[1, 0], d = key_matrix[1, 1];
                det = (a * d - b * c) % 26;
                if (det < 0) det += 26;
                det_inv = -1;
                for(int i = 0; i < 26; i++)
                {
                    if(i * det % 26 == 1)
                    {
                        det_inv = i;
                        break;
                    }
                }
                for(int i = 2; i < 26; i++)
                {
                    if(26 % i == 0 && det % i == 0)
                    {
                        found = true;
                    }
                }
                if (det_inv == -1)
                {
                    found = true;
                    det_inv = 0;
                }
                key_inv[0, 0] = d; key_inv[0, 1] = 26 - b;
                key_inv[1, 0] = 26 - c; key_inv[1, 1] = a;
                for(int i = 0; i < 2; i++)
                {
                    for(int j = 0; j < 2; j++)
                    {
                        key_inv[i, j] = key_inv[i, j] * det_inv % 26;
                    }
                }
                
            }
            else if(m2 == 9)
            {
                for(int i = 0; i < 3; i++)
                {
                    det = det + (key_matrix[0, i] * (key_matrix[1, (i + 1) % 3] * key_matrix[2, (i + 2) % 3] - key_matrix[1, (i + 2) % 3] * key_matrix[2, (i + 1) % 3]) ) % 26;
                    det %= 26;
                    if (det < 26) det += 26;
                }
                int g = 1;
                for(int i = 2; i < 26; i++)
                {
                    if(26 % i == 0 && det % i == 0)
                    {
                        found = true;
                    }
                }
                for(int i = 0; i < 26; i++)
                {
                   if(det * i % 26 == 1)
                    {
                        det_inv = i;
                        break;
                    }
                }
                if (det_inv == -1)
                {
                    found = true;
                    det_inv = 0;
                }
                for(int i = 0; i < 3; i++)
                {
                    for(int j = 0; j < 3; j++)
                    {
                        key_inv[i, j] = ((key_matrix[(j + 1) % 3, (i + 1) % 3] * key_matrix[(j + 2) % 3, (i + 2) % 3]) 
                                      - (key_matrix[(j + 1) % 3, (i + 2) % 3] * key_matrix[(j + 2) % 3, (i + 1) % 3]));
                        key_inv[i, j] %= 26;
                        if (key_inv[i, j] < 26) key_inv[i, j] += 26;
                        key_inv[i, j] = key_inv[i, j] * det_inv % 26;
                    }
                }
            }

            if(found)
            {
                throw new System.Exception();
            }
            List<int> plain = new List<int>();
            for (int i = 0; i < cipherText.Count; i += m)
            {
                int[] p = new int[m];
                for (int j = 0; j < m; j++)
                {
                    p[j] = cipherText[i + j];
                }

                int[] x = new int[m];
                for (int j = 0; j < m; j++) x[j] = 0;
                for (int j = 0; j < m; j++)
                {
                    int res = 0;
                    for (int l = 0; l < m; l++)
                    {
                        res = (res + key_inv[j, l] * p[l]) % 26;
                    }
                    plain.Add(res);
                }
            }
            return plain;
        }



        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m2 = key.Count;
            int m = (int) Math.Sqrt(m2);
            int[,] key_matrix = new int[m, m];

            for(int i = 0; i < m2; i++)
            {
                int r = i / m, c = i % m;
                key_matrix[r, c] = key[i];
            }
            List<int> cipher = new List<int>();
            for (int i = 0; i < plainText.Count; i += m)
            {
                int[] p = new int[m];
                for(int j = 0; j < m; j++)
                {
                    if (i + j < plainText.Count) p[j] = plainText[i + j];
                    else p[j] = 0;
                }
                int[] x = new int[m];
                for (int j = 0; j < m; j++) x[j] = 0;
                for(int j = 0; j < m; j++)
                {
                    int res = 0;
                    for(int l = 0; l < m; l++)
                    {
                        res = (res + key_matrix[j, l] * p[l]) % 26;
                    }
                    cipher.Add(res);
                }
            }
            int Mod = plainText.Count % m;
            while(Mod-- > 0)
            {
                cipher.RemoveAt(cipher.Count - 1);
            }
            return cipher;
            
            

        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int[,] key = new int[3, 3];
            for(int i = 0; i < 3; i++)
            {
                List<int> a = new List<int>();
                List<int> b = new List<int>();
                List<int> c = new List<int>();
                List<int> d  = new List<int>();
                for (int j = 0; j < plainText.Count; j += 3)
                {
                    a.Add(plainText[j]);
                    b.Add(plainText[j + 1]);
                    c.Add(plainText[j + 2]);
                    d.Add(cipherText[j + i]);
                }
                bool found_row = false;
                for(int A = 0; A < 26 && found_row == false; A++)
                {
                    for(int B = 0; B < 26 && found_row == false; B++)
                    {
                        for(int C = 0; C < 26 && found_row == false; C++)
                        {
                            bool found = false;
                            for(int j = 0; j < a.Count; j++)
                            {
                                int x = (A * a[j] + B * b[j] + C * c[j]) % 26;
                                if(x != d[j])
                                {
                                    found = true;
                                }
                            }
                            if(found == false)
                            {
                                found_row = true;
                                
                                key[i, 0] = A;
                                key[i, 1] = B;
                                key[i, 2] = C;
                            }
                        }
                    }
                }
                if (found_row == false)
                {
                    /// there is no key;
                    throw new InvalidAnlysisException();
                }
            }
            List<int> ans = new List<int>();
            for(int i = 0; i < 3; i++)
            {
                for(int j = 0; j < 3; j++)
                {
                    ans.Add(key[i, j]);
                }
            }
            return ans;
        }

        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int[,] key = new int[2, 2];
            for (int i = 0; i < 2; i++)
            {
                List<int> a = new List<int>();
                List<int> b = new List<int>();
                List<int> d = new List<int>();
                for (int j = 0; j < plainText.Length; j += 2)
                {
                    a.Add(plainText[j] - 'a');
                    b.Add(plainText[j + 1] - 'a');
                    d.Add(cipherText[j + i] - 'a');
                }
                bool found_row = false;
                for (int A = 0; A < 26 && found_row == false; A++)
                {
                    for (int B = 0; B < 26 && found_row == false; B++)
                    {
                        bool found = false;
                        for (int j = 0; j < a.Count; j++)
                        {
                            int x = (A * a[j] + B * b[j]) % 26;
                            if (x != d[j])
                            {
                                found = true;
                            }
                        }
                        if (found == false)
                        {
                            found_row = true;

                            key[i, 0] = A;
                            key[i, 1] = B;
                        }
                    }
                }
                if (found_row == false)
                {
                    /// there is no key;
                    throw new InvalidAnlysisException();
                }
            }
            string ans = "";
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    ans  += (char)(key[i, j] + 'a');
                }
            }
            return ans;
        }


        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            int size = cipherText.Length;
            List<int> cipher = new List<int>();
            for(int i = 0; i < size; i++)
            {
                cipher.Add((int) (cipherText[i] - 'a'));
            }

            key = key.ToLower();
            List<int> keyy = new List<int>();
            for(int i = 0; i < key.Length; i++)
            {
                keyy.Add((int) (key[i] - 'a'));
            }

            int m2 = keyy.Count;
            int m = (int)Math.Sqrt(m2);
            int[,] key_matrix = new int[m, m];
            for (int i = 0; i < m2; i++)
            {
                int r = i / m, c = i % m;
                key_matrix[r, c] = keyy[i];
            }
            int[,] key_inv = new int[m, m];
            bool found = false;
            /// To find the inverse
            int det = 0, det_inv = -1;
            if (m2 == 4)
            {
                int a = key_matrix[0, 0], b = key_matrix[0, 1];
                int c = key_matrix[1, 0], d = key_matrix[1, 1];
                det = (a * d - b * c) % 26;
                if (det < 0) det += 26;
                det_inv = -1;
                for (int i = 0; i < 26; i++)
                {
                    if (i * det % 26 == 1)
                    {
                        det_inv = i;
                        break;
                    }
                }
                for (int i = 2; i < 26; i++)
                {
                    if (26 % i == 0 && det % i == 0)
                    {
                        found = true;
                    }
                }
                if (det_inv == -1)
                {
                    found = true;
                    det_inv = 0;
                }
                key_inv[0, 0] = d; key_inv[0, 1] = 26 - b;
                key_inv[1, 0] = 26 - c; key_inv[1, 1] = a;
                for(int i = 0; i < 2; i++)
                {
                    for(int j = 0; j < 2; j++)
                    {
                        key_inv[i, j] = key_inv[i, j] * det_inv % 26;
                    }
                }
            }
            else if (m2 == 9)
            {
                for (int i = 0; i < 3; i++)
                {
                    det = det + (key_matrix[0, i] * (key_matrix[1, (i + 1) % 3] * key_matrix[2, (i + 2) % 3] - key_matrix[1, (i + 2) % 3] * key_matrix[2, (i + 1) % 3])) % 26;
                    det %= 26;
                    if (det < 26) det += 26;
                }
                int g = 1;
                for (int i = 2; i < 26; i++)
                {
                    if (26 % i == 0 && det % i == 0)
                    {
                        found = true;
                    }
                }
                for (int i = 0; i < 26; i++)
                {
                    if (det * i % 26 == 1)
                    {
                        det_inv = i;
                        break;
                    }
                }
                if (det_inv == -1)
                {
                    found = true;
                    det_inv = 0;
                }
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        key_inv[i, j] = ((key_matrix[(j + 1) % 3, (i + 1) % 3] * key_matrix[(j + 2) % 3, (i + 2) % 3])
                                      - (key_matrix[(j + 1) % 3, (i + 2) % 3] * key_matrix[(j + 2) % 3, (i + 1) % 3]));
                        key_inv[i, j] %= 26;
                        if (key_inv[i, j] < 26) key_inv[i, j] += 26;
                        key_inv[i, j] = key_inv[i, j] * det_inv % 26;
                    }
                }
            }

            if (found)
            {
                throw new System.Exception();
            }
            List<int> plain = new List<int>();
            for (int i = 0; i < cipher.Count; i += m)
            {
                int[] p = new int[m];
                for (int j = 0; j < m; j++)
                {
                    p[j] = cipher[i + j];
                }

                int[] x = new int[m];
                for (int j = 0; j < m; j++) x[j] = 0;
                for (int j = 0; j < m; j++)
                {
                    int res = 0;
                    for (int l = 0; l < m; l++)
                    {
                        res = (res + key_inv[j, l] * p[l]) % 26;
                    }
                    plain.Add(res);
                }
            }
            string ret = "";
            for (int i = 0; i < plain.Count; i++)
            {
                ret += (char)(plain[i] + 'A');
            }
            return ret;
        }



        public string Encrypt(string plainText, string key)
        {
            List<int> keyy = new List<int>();
            List<int> plain = new List<int>();
            for(int i = 0; i < plainText.Length; i++)
            {
                plain.Add((int)(plainText[i] - 'a'));
            }
            for(int i = 0; i < key.Length; i++)
            {
                keyy.Add((int)(key[i] - 'a'));
            }    
            int m2 = keyy.Count;
            int m = (int)Math.Sqrt(m2);
            int[,] key_matrix = new int[m, m];

            for (int i = 0; i < m2; i++)
            {
                int r = i / m, c = i % m;
                key_matrix[r, c] = keyy[i];
            }
            List<int> cipher = new List<int>();
            for (int i = 0; i < plain.Count; i += m)
            {
                int[] p = new int[m];
                for (int j = 0; j < m; j++)
                {
                    if (i + j < plain.Count) p[j] = plain[i + j];
                    else p[j] = 0;
                }
                int[] x = new int[m];
                for (int j = 0; j < m; j++) x[j] = 0;
                for (int j = 0; j < m; j++)
                {
                    int res = 0;
                    for (int l = 0; l < m; l++)
                    {
                        res = (res + key_matrix[j, l] * p[l]) % 26;
                    }
                    cipher.Add(res);
                }
            }
            int Mod = plain.Count % m;
            while (Mod-- > 0)
            {
                cipher.RemoveAt(cipher.Count - 1);
            }
            string ret = "";
            for(int i = 0; i < cipher.Count; i++)
            {
                ret += (char)(cipher[i] + 'A');
            }
            return ret;            
            
        }



        public string Analyse3By3Key(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            List<int> plain = new List<int>();
            List<int> cipher = new List<int>();
            for(int i = 0; i < plainText.Length; i++)
            {
                plain.Add((int)(plainText[i] - 'a'));
            }
            for(int i = 0; i < cipherText.Length; i++)
            {
                cipher.Add((int)(cipherText[i] - 'a'));
            }
            int[,] key = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                List<int> a = new List<int>();
                List<int> b = new List<int>();
                List<int> c = new List<int>();
                List<int> d = new List<int>();
                for (int j = 0; j < plain.Count; j += 3)
                {
                    a.Add(plain[j]);
                    b.Add(plain[j + 1]);
                    c.Add(plain[j + 2]);
                    d.Add(cipher[j + i]);
                }
                bool found_row = false;
                for (int A = 0; A < 26 && found_row == false; A++)
                {
                    for (int B = 0; B < 26 && found_row == false; B++)
                    {
                        for (int C = 0; C < 26 && found_row == false; C++)
                        {
                            bool found = false;
                            for (int j = 0; j < a.Count; j++)
                            {
                                int x = (A * a[j] + B * b[j] + C * c[j]) % 26;
                                if (x != d[j])
                                {
                                    found = true;
                                }
                            }
                            if (found == false)
                            {
                                found_row = true;

                                key[i, 0] = A;
                                key[i, 1] = B;
                                key[i, 2] = C;
                            }
                        }
                    }
                }
                if (found_row == false)
                {
                    /// there is no key;
                    throw new InvalidAnlysisException();
                }
            }
            List<int> ans = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    ans.Add(key[i, j]);
                }
            }
            string ret = "";
            for(int i = 0; i < ans.Count; i++)
            {
                ret += (char)(ans[i] + 'a');
            }
            return ret;
        }

    }
}
