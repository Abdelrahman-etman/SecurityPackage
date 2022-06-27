using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int[,] table = new int[26, 26];
            int letter = 0;
            for (int i = 0; i < 26; i++)
            {
                letter = i;
                for (int j = 0; j < 26; j++)
                {
                    table[i, j] = letter;
                    letter++;
                    letter %= 26;
                }
            }
            string key = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int row = plainText[i] - 'a';
                for (int j = 0; j < 26; j++)
                {
                    if ((char)(table[row, j] + 'a') == cipherText[i])
                    {
                        key += (char)(j + 'a');
                        break;
                    }
                }
            }
            for (int i = 0; i < key.Length; i++)
            {
                string substr = key.Substring(i, key.Length - i);
                if (substr == plainText.Substring(0, key.Length - i))
                    return key.Substring(0, i);
            }
            for (int len = 1; len < key.Length; len++)
            {
                bool ok = true;
                for (int i = 0; i < len; i++)
                {
                    for (int j = i + len; j < key.Length; j += len)
                    {
                        if (key[j] != key[i])
                        {
                            ok = false;
                            break;
                        }
                    }
                }
                if (ok)
                    return key.Substring(0, len);
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            int[,] table = new int[26, 26];
            int letter = 0;
            for (int i = 0; i < 26; i++)
            {
                letter = i;
                for (int j = 0; j < 26; j++)
                {
                    table[i, j] = (letter);
                    letter++;
                    letter %= 26;
                }
            }
            string key_stream = key;
            int idx = 0;
            while (key_stream.Length != cipherText.Length)
            {
                key_stream += key[idx];
                idx++;
                idx %= (int)key.Length;
            }
            string plain = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int row = key_stream[i] - 'a';
                for (int j = 0; j < 26; j++)
                {
                    if ((char)(table[row, j] + 'a') == cipherText[i])
                    {
                        plain += (char)(j + 'a');
                        break;
                    }
                }
            }
            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            int[,] table = new int[26, 26];
            int letter = 0;
            for (int i = 0; i < 26; i++)
            {
                letter = i;
                for (int j = 0; j < 26; j++)
                {
                    table[i, j] = (letter);
                    letter++;
                    letter %= 26;
                }
            }
            string key_stream = key;
            int idx = 0;
            while (key_stream.Length != plainText.Length)
            {
                key_stream += key[idx];
                idx++;
                idx %= (int)key.Length;
            }
            string cipher = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int row = plainText[i] - 'a';
                int col = key_stream[i] - 'a';
                cipher += (char)(table[row, col] + 'a');
            }
            return cipher.ToUpper();
        }
    }
}