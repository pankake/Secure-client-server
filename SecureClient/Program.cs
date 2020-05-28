using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace SecureClient
{
    class Program
    {
        public static Random rnd = new Random();
        public static RSACryptoServiceProvider rsa_server;
        public static RSACryptoServiceProvider rsa;
        public static RSAParameters privateParam;
        public static RSAParameters publicParam;
        public static int g;
        public static int module;
        public static int secret;
        public const int port = 600;

        static void Main(string[] args)
        {
          //Console.WindowWidth = 120;
          //Console.WindowHeight = 76;

            X509KeyStorageFlags flags = X509KeyStorageFlags.Exportable;
            X509Certificate2 cert = new X509Certificate2("cert_key.p12", "1234", flags);
            X509Certificate2 certp = new X509Certificate2("public.cer");

            byte[] key = new byte[16];

            //lettura chiave privata
            rsa = (RSACryptoServiceProvider)cert.PrivateKey;

            //esporta i parametri della chiave privata
            privateParam = rsa.ExportParameters(true);

            //lettura chiave pubblica
            rsa = (RSACryptoServiceProvider)certp.PublicKey.Key;

            //esporta i parametri della chiave pubblica
            publicParam = rsa.ExportParameters(false);

            //fornisce l'interfaccia di comunicazione 
            UdpClient client = new UdpClient();

            //crea l'ipendpoint in locale
            IPEndPoint ipep = new IPEndPoint(IPAddress.Parse("127.0.0.1"), port);

            //connessione all'endpoint
            client.Connect(ipep);

            //client status
            int cs = 0;

            while (cs < 3)
            {
                switch(cs)
                {
                    case 0:
                        {
                            Console.Write("Push any key to connect with the server: ");

                            //legge la stringa da tastiera e la converte in byte
                            byte[] packet = Encoding.ASCII.GetBytes(Console.ReadLine());
                            client.Send(packet, packet.Length);

                            //si mette in ascolto
                            var data = client.Receive(ref ipep);
                            Console.Write(Encoding.ASCII.GetString(data));

                            //invio del certificato
                            byte[] certData = cert.Export(X509ContentType.Cert);
                            client.Send(certData, certData.Length);

                            //riceve certificato
                            byte[] certReceived = client.Receive(ref ipep);
                            X509Certificate2 serverCert = new X509Certificate2(certReceived);

                            string resultTrue = serverCert.ToString(true);

                            Console.WriteLine("\nServer's certificate received:\n" + resultTrue);

                            Console.WriteLine("/**********************************************************************************************************************/");

                            rsa_server = (RSACryptoServiceProvider)serverCert.PublicKey.Key;

                            //riceve la chiave simmetrica
                            byte[] encryptedKey = client.Receive(ref ipep);

                            //decritta la chiave con la propria chiave privata
                            rsa.ImportParameters(privateParam);
                            key = rsa.Decrypt(encryptedKey, false);

                            Console.WriteLine("Simmetric Key = " + new UnicodeEncoding().GetString(key));

                            //riceve il modulo e la base da utilizzare
                            byte[] values = client.Receive(ref ipep);

                            module = values[0];
                            g = values[1];

                            cs++;
                            break;
                        }

                    case 1:
                        {
                            Console.WriteLine("Base = " + g);
                            Console.WriteLine("Module = " + module);

                            //riceve gx crittato
                            byte[] encrypt_gx = client.Receive(ref ipep);

                            //decritta gx
                            rsa.ImportParameters(privateParam);
                            byte[] decrypt_gx = rsa.Decrypt(encrypt_gx, true);

                            //converte gx in intero
                            int gx = Int32.Parse(Encoding.ASCII.GetString(decrypt_gx));

                            Console.WriteLine("g^x mod p = " + gx);

                            int expo = rnd.Next(2, 9);
                            Console.WriteLine("Exponent y = " + expo);

                            //calcola g^y mod p
                            int gy = (int)BigInteger.ModPow(g, expo, module);
                            Console.WriteLine("g^y mod p = " + gy);

                            //critta g^y
                            byte[] encrypt_gy = rsa_server.Encrypt(Encoding.ASCII.GetBytes(gy.ToString()), true);

                            //calcola k = (g^x)^y
                            secret = (int)BigInteger.ModPow(gx, expo, module);
                            Console.WriteLine("Secret(k) = " + secret + "\n");

                            Console.WriteLine("/*********************************************************************************************End of parameters********/");

                            //firma il valore hash di k + gx + gy con chiave privata
                            string signedHash = signMessage(secret + gx + gy.ToString(), privateParam);

                            //cifra con chiave simmetrica il valore di hash firmato
                            byte[] signed_BHash = Aes_encrypt(signedHash, key);

                            //invia hash firmato
                            client.Send(signed_BHash, signed_BHash.Length);

                            //invia g^y crittato con chiave pubblica
                            client.Send(encrypt_gy, encrypt_gy.Length);

                            //riceve pacchetto di autenticazione firmato dal server
                            byte[] revSignHash = client.Receive(ref ipep);

                            //decritta il pacchetto
                            string revSignature = Aes_decrypt(revSignHash, key);

                            //verifica dell'hash code
                            if (verifySignature(secret + gy + gx.ToString(), revSignature, publicParam))
                            {
                                Console.WriteLine("<SERVER:> " + "authentication failed, permissions are denied !");
                                Console.WriteLine("<SERVER:> the connection will be rejected, press a key to end");
                                Console.ReadKey();
                                Environment.Exit(0);
                            }

                            else
                            {
                                Console.WriteLine("\n<SERVER:> authentication performed successfully !");
                                Console.WriteLine("<SERVER:> a secret key has been mutually authenticated and validated !\n");

                            }

                            cs++;
                            break;
                        }

                    case 2:
                        {
                            byte[] Btoken = client.Receive(ref ipep);

                            string token = new UnicodeEncoding().GetString(Btoken);

                            Console.WriteLine("Session token: " + token + "\n");

                            Console.Write("Write message: ");
                            
                            //legge la stringa da tastiera e la converte in byte
                            byte[] data = new UnicodeEncoding().GetBytes("<cute girl:> " + Console.ReadLine());

                            //firma della sessione
                            byte[] digest = new UnicodeEncoding().GetBytes(signMessage(data.Length + token + secret, privateParam));

                            //creazione del pacchetto da inviare
                            byte[] sendPacket = new byte[digest.Length + data.Length];
                            System.Buffer.BlockCopy(digest, 0, sendPacket, 0, digest.Length);
                            System.Buffer.BlockCopy(data, 0, sendPacket, digest.Length, data.Length);

                            client.Send(sendPacket, sendPacket.Length);

                            byte[] response = client.Receive(ref ipep);

                            Console.WriteLine(new UnicodeEncoding().GetString(response));

                            if(new UnicodeEncoding().GetString(data).Equals("<cute girl:> " + "bye"))
                                cs++;

                            break;
                        }
                }
            }
        }

        public static String signMessage(String value, RSAParameters privateParam)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            rsa.ImportParameters(privateParam);

            //crea un istanza RSAFormatter
            RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(rsa);

            //setta l'algoritmo di hash col quale effettuare la firma
            RSAFormatter.SetHashAlgorithm("SHA1");

            //crea un istanza dell'algoritmo di hash
            SHA1Managed SHhash = new SHA1Managed();

            //converte la stringa in byte, ne calcola l'hash e lo firma
            byte[] SignedHashValue = RSAFormatter.CreateSignature(SHhash.ComputeHash(new UnicodeEncoding().GetBytes(value)));

            //pone il risultato ottenuto in stringa
            string signature = System.Convert.ToBase64String(SignedHashValue);

            return signature;
        }

        public static bool verifySignature(String value, String signature, RSAParameters publicParam)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            rsa.ImportParameters(publicParam);

            RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(rsa);

            RSADeformatter.SetHashAlgorithm("SHA1");

            SHA1Managed SHhash = new SHA1Managed();

            if (RSADeformatter.VerifySignature(SHhash.ComputeHash(new UnicodeEncoding().GetBytes(value)), System.Convert.FromBase64String(signature)))
            {
                //la firma è valida
                return true;
            }
            else
            {
                //la firma non è valida
                return false;
            }
        }

        static byte[] Aes_encrypt(string plainText, byte[] Key)
        {
            byte[] encrypted;
            byte[] IV;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.GenerateIV();
                IV = aesAlg.IV;

                aesAlg.Mode = CipherMode.CBC;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            var combinedIvCt = new byte[IV.Length + encrypted.Length];
            Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
            Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);
 
            return combinedIvCt;
        }

        static string Aes_decrypt(byte[] cipherTextCombined, byte[] Key)
        {
 
            string plaintext = null;
 
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                byte[] IV = new byte[aesAlg.BlockSize / 8];
                byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

                Array.Copy(cipherTextCombined, IV, IV.Length);
                Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }
            return plaintext;
        }
    }
}
