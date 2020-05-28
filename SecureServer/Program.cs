using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Numerics;
using System.IO;

namespace SecureServer
{
    class Program
    {
        public static Random rnd = new Random();
        public static RSACryptoServiceProvider rsa_client;
        public static RSACryptoServiceProvider rsa;
        public static RSAParameters privateParam;
        public static RSAParameters publicParam;
        public static X509Certificate2 clientCert;
        public static RSAParameters clientParam;
        public static int g;
        public static int module;
        public static int expo;
        public static int secret;

        public static byte[] receivedData = null;
        public const int port = 600;
        public static UdpClient serverSocket = null;
        public static IPEndPoint clientEndpoint = null;

        static void Main(string[] args)
        {
         //Console.WindowWidth = 120;
         //Console.WindowHeight = 76;

            X509KeyStorageFlags flags = X509KeyStorageFlags.Exportable;
            X509Certificate2 cert = new X509Certificate2("cert_key.p12", "1234", flags);
            X509Certificate2 certp = new X509Certificate2("public.cer");

            RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
            byte[] key = new byte[16];

            //lettura chiave privata
            rsa = (RSACryptoServiceProvider)cert.PrivateKey;

            //esporta i parametri dalla chiave privata
            privateParam = rsa.ExportParameters(true);

            //lettura chiave pubblica
            rsa = (RSACryptoServiceProvider)certp.PublicKey.Key;

            //esporta i parametri della chiave pubblica
            publicParam = rsa.ExportParameters(false);

            //fornisce un interfaccia semplice per le comunicazioni tramite socket
            serverSocket = new UdpClient(port);

            // Crea un IPEndPoint per registrare l'indirizzo IP e il numero di porta del mittente
            clientEndpoint = new IPEndPoint(IPAddress.Any, 0);

            //riceve il datagramma dall'end point
            receivedData = serverSocket.Receive(ref clientEndpoint);

            //connessione con l'endpoint specificato
            serverSocket.Connect(clientEndpoint);

            //client status
            int cs = 0;

            while (cs < 3)
            {
                switch (cs)
                {
                    case 0:
                        {
                            Console.WriteLine("<SERVER:> " + "connected...");
                            byte[] packet = Encoding.ASCII.GetBytes("\n<SERVER:> " + "the exchange of parameters begins" + "\n");
                            serverSocket.Send(packet, packet.Length);

                            //invio del certificato
                            byte[] certPub = cert.Export(X509ContentType.Cert);
                            serverSocket.Send(certPub, certPub.Length);

                            //riceve certificato
                            byte[] certReceived = serverSocket.Receive(ref clientEndpoint);
                            clientCert = new X509Certificate2(certReceived);

                            string resultTrue = clientCert.ToString(true);

                            Console.WriteLine("\nClient's certificate received:\n" + resultTrue);

                            Console.WriteLine("/**********************************************************************************************************************/");

                            rsa_client = (RSACryptoServiceProvider)clientCert.PublicKey.Key;

                            //inizializza chiave dell'algoritmo simmetrico
                            random.GetBytes(key);

                            //critta la chiave simmetrica con la chiave pubblica del destinatario
                            byte[] encryptedKey = rsa_client.Encrypt(key, false);

                            //invio della chiave simmetrica
                            serverSocket.Send(encryptedKey, encryptedKey.Length);

                            Console.WriteLine("Simmetric Key = " + new UnicodeEncoding().GetString(key));

                            //genera modulo primo p
                            bool loop = true;
                            int p = 0;

                            while (loop)
                            {
                                p = rnd.Next(2, 200);
                                int result = checkPrime(p);
                                if (result == 1)
                                    loop = false;
                            }                            
                            module = p;

                            //genera base g
                            g = rnd.Next(2, 9);
                            
                            dataExchange(p, g);

                            cs++;
                            break;
                        }

                    case 1:
                        {
                            Console.WriteLine("Base = " + g);
                            Console.WriteLine("Module = " + module);

                            authenticativeProtocol(key);

                            cs++;
                            break;
                        }

                    case 2:
                        {
                            //genera un token Guid (Globally Uniue Identifier) e lo pone in byte
                            byte[] Btoken = new UnicodeEncoding().GetBytes(Guid.NewGuid().ToString());

                            serverSocket.Send(Btoken, Btoken.Length);

                            string token = new UnicodeEncoding().GetString(Btoken);

                            byte[] receivedPacket = serverSocket.Receive(ref clientEndpoint);

                            string data = new UnicodeEncoding().GetString(receivedPacket);

                            //split in due stringhe
                            string[] words = data.Split('<');

                            Console.WriteLine("<" + words[1]);

                            byte[] text = new UnicodeEncoding().GetBytes("<" + words[1]);

                            //verifica della firma 
                            if (!verifySignature(text.Length + token + secret, words[0], clientParam))
                            {
                                Console.Write("<Signature:> compromised integrity of the message !");
                                Console.WriteLine("<SERVER:> the connection will be rejected, press a key to end");
                                Console.ReadKey();
                                Environment.Exit(0);
                            }
                            else
                            {
                                if (words[1].Equals("cute girl:> " + "bye"))
                                    cs++;
                                words = words[1].Split('>');
                                byte[] response = new UnicodeEncoding().GetBytes("<Ronnie James Dio:> " + words[1]);
                                Console.WriteLine("<Signature:> confirmed integrity of the message" + "\n");

                                serverSocket.Send(response, response.Length);
                            }

                            break;
                        }
                }
            }
        }

        public static void authenticativeProtocol(byte[] key)
        {

            expo = rnd.Next(2, 9);
            Console.WriteLine("Exponent x = " + expo);

            //calcola g^x mod p
            int gx = (int)BigInteger.ModPow(g, expo, module);

            Console.WriteLine("g^x mod p = " + gx);

            //critta g^x mod p
            byte[] encrypt_gx = rsa_client.Encrypt(Encoding.ASCII.GetBytes(gx.ToString()), true);

            //invia g^x crittato
            serverSocket.Send(encrypt_gx, encrypt_gx.Length);

            //riceve pacchetto firmato dal client
            byte[] signedBHash = serverSocket.Receive(ref clientEndpoint);

            //decritta con AES a chiave simmetrica
            string signature = Aes_decrypt(signedBHash, key);

            //riceve dal client g^y crittato
            byte[] encrypt_gy = serverSocket.Receive(ref clientEndpoint);

            //decritta g^y
            rsa.ImportParameters(privateParam);
            string decrypt_gy = Encoding.ASCII.GetString(rsa.Decrypt(encrypt_gy, true));

            //converte g^y in intero
            int gy = Int32.Parse(decrypt_gy);

            Console.WriteLine("g^y mod p = " + gy);

            //calcola la chiave k = (g^y)^x
            secret = (int)BigInteger.ModPow(gy, expo, module);

            Console.WriteLine("Secret(k) = " + secret + "\n");

            Console.WriteLine("/*********************************************************************************************End of parameters********/");

            clientParam = rsa_client.ExportParameters(false);

            //verifica dell'hash code
            if (!verifySignature(secret + gx + gy.ToString(), signature, clientParam))
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

                //il server si autentica al client
                //firma il valore hash di k + gy + gx con la sua chiave privata
                string revSignature = signMessage(secret + gy + gx.ToString(), privateParam);

                //cifra con chiave simmetrica il valore hash firmato
                byte[] revSignHash = Aes_encrypt(revSignature, key);

                //invia hash firmato
                serverSocket.Send(revSignHash, revSignHash.Length);
            }
        }

        public static void dataExchange(int module, int g)
        {

            //converte e invia modulo e base
            byte bmodule = Convert.ToByte(module);
            byte bg = Convert.ToByte(g);

            byte[] valuesPacket = new byte[16];
            valuesPacket[0] = bmodule;
            valuesPacket[1] = bg;

            serverSocket.Send(valuesPacket, valuesPacket.Length);
        }
        
        public static int checkPrime(int n)
        {
            int i;

            for (i = 2; i <= n - 1; i++)
            {
                if (n % i == 0)
                {
                    return 0;
                }
            }

            if (i == n)
            {
                return 1;
            }
            return 0;
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

        static byte[] Aes_encrypt(string plainText, byte[] Key)
        {
            byte[] encrypted;
            byte[] IV;

            //crea un istanza di Aes
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                //genera un vettore di inizializzazione utilizzato per l'algoritmo
                aesAlg.GenerateIV();

                //inizializza il vettore
                IV = aesAlg.IV;

                //setta il cifrario
                aesAlg.Mode = CipherMode.CBC;

                //crea entità usata per crittografare i dati
                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                //creazione degli stream usati per la crittografia dei dati
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //scrive i dati nello stream
                            swEncrypt.Write(plainText);
                        }

                        //i dati crittati si trovano nell'istanza di memory stream
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            //unisce i due vettori
            var combinedIvCt = new byte[IV.Length + encrypted.Length];
            Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
            Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);

            return combinedIvCt;
        }

        static string Aes_decrypt(byte[] cipherTextCombined, byte[] Key)
        {

            //contiene il testo decrittato
            string plaintext = null;

            //crea un istanza di aes
            using (Aes aesAlg = Aes.Create())
            {

                //inizializza la chiave
                aesAlg.Key = Key;

                //crea vettore per l'inizializzazione
                byte[] IV = new byte[aesAlg.BlockSize / 8];

                //contiene il testo cifrato 
                byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

                //combina i dati
                Array.Copy(cipherTextCombined, IV, IV.Length);
                Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

                //inizializza il vettore
                aesAlg.IV = IV;

                //setta la modalità del cifrario (a blocchi)
                aesAlg.Mode = CipherMode.CBC;

                //oggetto usato per decrittare i dati
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                //creazione degli stream usati per decrittare i dati
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            //legge il testo decrittato                           
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
    }
}
