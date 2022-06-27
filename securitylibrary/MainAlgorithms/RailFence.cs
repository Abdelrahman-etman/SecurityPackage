using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            for(int key = 0; key < 50; key++)
            {
                string cipher = "";
                for (int i = 0; i < key; i++)
                {
                    for (int j = i; j < plainText.Length; j += key)
                    {
                        cipher += plainText[j];
                    }
                }
                cipherText = cipherText.ToLower();
                if(String.Compare(cipher, cipherText) == 0)
                {
                    return key;
                }
            }
            return 1;
        }

        
        public string Decrypt(string cipherText, int key)
        {
            int n = cipherText.Length / key + 2;
            char[,] matrix = new char[key, n];
            int idx = 0;
            for(int i = 0; i < n; i++)
            {
                for(int j = 0; j < key; j++)
                {
                    if(idx < cipherText.Length)
                    {
                        matrix[j, i] = '.'; 
                    }
                    else
                    {
                        matrix[j, i] = '#';
                    }
                    idx++;
                }
            }

            int r = 0, c = 0;
            for(int i = 0; i < cipherText.Length; i++)
            {
                if(matrix[r, c] == '#')
                {
                    r++;
                    c = 0;
                }
                matrix[r, c] = cipherText[i];
                c++;
            }
            string plain = "";
            for(int i = 0; i < n; i++)
            {
                for(int j = 0; j < key; j++)
                {
                    if (matrix[j, i] == '#') continue;
                    plain += matrix[j, i];
                }
            }
            return plain;
        }

        public string Encrypt(string plainText, int key)
        {
            string cipher = "";
            for(int i = 0; i < key; i++)
            {
                for(int j = i; j < plainText.Length; j += key)
                {
                    cipher += plainText[j];
                }
            }
            return cipher;
        }
    }
}
