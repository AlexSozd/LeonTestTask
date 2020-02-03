using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

public class LeonSDK
{
    const int CRL_AES_BLOCK = 16; /*!< Number of bytes (uint8_t) necessary to store an AES block. */
    const int CRL_AES192_KEY = 24; /*!< Number of bytes (uint8_t) necessary to store an AES key of 192 bits. */
    const int CRL_AES256_KEY = 32; /*!< Number of bytes (uint8_t) necessary to store an AES key of 256 bits. */
    public const int DIG_FULLSTATUS = 0;
    const int LAN_MAX_PASSWORD_LEN = 32;
    public const uint NUC_ETH_MAGIC = 0x454E5543; //454E5543		magic	1162761539	uint
    public const uint NUC_ETH_TYPE_CMD = 0x00000001;              // Команда от сервера
    const int SALT_SIZE = 256; //128;

    uint[] k = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

    // r specifies the per-round shift amounts
    uint[] r = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

    byte[] AES256_KEY, buf1;

    Random rand;

    TcpClient tc = null;
    NetworkStream tcpstr;
    AesManaged AES_m = null;
    ICryptoTransform decryptor;
    ICryptoTransform encryptor;

    public LeonSDK()
	{

	}
    public void Connect(string ip, int port, string Password)
    {
        //RoutedEventArgs newEventArgs;
        bool WasConnected = false;
        int b_rec_count, ans_size = 47 + 16;
        try
        {
            Array.Clear(buf1, 0, 1024);

            if (tc != null)
            {
                tc.Close();
                tc = null;
            }

            //Создаем Tcp соединение
            tc = new TcpClient();
            tc.NoDelay = true;
            tc.Connect(ip, port);

            //Ожидаем получения блока в 256 байт случайных чисел от прибора
            tcpstr = tc.GetStream();
            tcpstr.ReadTimeout = 1000;
            b_rec_count = tcpstr.Read(buf1, 0, SALT_SIZE);
            if (b_rec_count == SALT_SIZE)
            {
                //Получили блок случайных чисел - теперь расшифровываем паролем прибора
                AES_m = new AesManaged();
                WasConnected = true;

                //Делаем ключ для расшифровки из пароля
                Encoding ascii = System.Text.Encoding.GetEncoding(1251);
                Encoding unicode = Encoding.Unicode;
                byte[] unicodeBytes = unicode.GetBytes(Password);
                byte[] asciiBytes = Encoding.Convert(unicode, ascii, unicodeBytes);
                byte[] bytePass = new byte[LAN_MAX_PASSWORD_LEN];
                Array.Clear(bytePass, 0, LAN_MAX_PASSWORD_LEN);
                Array.Copy(asciiBytes, bytePass, asciiBytes.Length);
                bytePass[LAN_MAX_PASSWORD_LEN - 1] = 0;

                AES256_KEY = new byte[CRL_AES256_KEY];
                Array.Copy(bytePass, AES256_KEY, CRL_AES256_KEY);

                AES_m.Mode = CipherMode.ECB;
                decryptor = AES_m.CreateDecryptor(AES256_KEY, null);
                MemoryStream mstr = new MemoryStream(buf1);
                CryptoStream crstr = new CryptoStream(mstr, decryptor, CryptoStreamMode.Read);
                StreamReader str = new StreamReader(crstr);
                //Расшифровываем блок в 256 байт
                int Принято = crstr.Read(buf2, 0, SALT_SIZE);

                // Ксорим расшифрованный блок паролем
                for (int i = 0; i < SALT_SIZE; i++)
                {
                    buf2[i] = (byte)(buf2[i] ^ bytePass[i % LAN_MAX_PASSWORD_LEN]);
                }

                //Первые 32 байта будут ключем шифрования для соединения с прибором
                Array.Copy(buf2, AES256_KEY, CRL_AES256_KEY);

                // Рассчитываем md5 полученного и обработанного блока в 256 байт
                byte[] result = new byte[16];
                md5(buf2, SALT_SIZE, result);

                decryptor = AES_m.CreateDecryptor(AES256_KEY, null);

                //отправляем полученный md5 обратно в прибор для сравнения. Прибор также рассчитывает md5 и потом сравнивает свой md5 c тем что мы отправляем.
                //Если они совпадут - соединение рабочее, иначе прибор разорвет связь.
                tcpstr.WriteTimeout = 1000;
                tcpstr.Write(result, 0, 16);
                global::System.Threading.Thread.Sleep(20);

                //Запрашиваем полное состояние пробора первый раз

                MakeHeading(buf1, DIG_FULLSTATUS, 0, NUC_ETH_TYPE_CMD);
                SendCommandToDevice(buf1, 0, 16);

                //Делаем паузу в 400 миллисекунд
                global::System.Threading.Thread.Sleep(400);

                //Запрашиваем полное состояние второй раз

                MakeHeading(buf1, DIG_FULLSTATUS, 0, NUC_ETH_TYPE_CMD);
                SendCommandToDevice(buf1, 0, 16);
                global::System.Threading.Thread.Sleep(50);

                //Ожидаем получение полного состояния прибора 
                //СостояниеКонтроляПриб РезультатСети;
                for (int i = 0; i < 5; i++)
                {
                    /*РезультатСети = ЧтениеДанныхССети();
                    if (РезультатСети == СостояниеКонтроляПриб.ПолноeСостояниеПолучено)
                    {
                        //Полное состояние прибора получено - оповещаем об этом (ОтветПриборПодключен)
                        newEventArgs = new СобытияИзмененияСАргументом(1, ТРИО_ПриборПодключен_Event, this);
                        RaiseEvent(newEventArgs);
                        return;
                    }
                    else if (РезультатСети == СостояниеКонтроляПриб.НетСвязи)
                    {
                        //Оповещаем что оборвалась связь
                        newEventArgs = new СобытияИзмененияСАргументом(-1, ТРИО_ПриборПодключен_Event, this);
                        RaiseEvent(newEventArgs);
                        return;

                    }*/
                }
                global::System.Threading.Thread.Sleep(50);
            }

            //newEventArgs = new СобытияИзмененияСАргументом(-2, ТРИО_ПриборПодключен_Event, this);
            //RaiseEvent(newEventArgs);
            return;// false;
        }
        catch (Exception ee)
        {
            if (WasConnected)
            {
                //newEventArgs = new СобытияИзмененияСАргументом(-1, ТРИО_ПриборПодключен_Event, this);
            }
            else
            {
                //newEventArgs = new СобытияИзмененияСАргументом(-2, ТРИО_ПриборПодключен_Event, this);
            }
            //RaiseEvent(newEventArgs);
            //return; // false;
        }
    }
    public void ReadAllData()
    {
        //Read Data from app server
        try
        {
            int BUFFER_SIZE = 1024;
            byte[] rec = new byte[BUFFER_SIZE], rec1 = new byte[BUFFER_SIZE];
            //Проверка соединения
            int byte_count = 128 + 16;

            // Flags = false?

            tcpstr.ReadTimeout = 5000;   //Время таймаута
            //Чтение данных из сети
            int recbytecount = tcpstr.Read(rec1, 0, byte_count);
            if(recbytecount == byte_count)
            {
                //Проверка размеров блока и его дешифровка, ключ получен ранее при соединении с прибором
                decryptor = AES_m.CreateDecryptor(AES256_KEY, null);
                MemoryStream mstr = new MemoryStream(rec1);
                CryptoStream crstr = new CryptoStream(mstr, decryptor, CryptoStreamMode.Read);
                StreamReader str = new StreamReader(crstr);
                int recbytescount = crstr.Read(buf1, 0, byte_count);
                //Проверка пакета данных
                uint BegPos = 0;
                uint pocketType = 0;
            }
        }
        catch
        {
            //
        }
    }
    private void md5(byte[] initial_msg, uint initial_len, byte[] digest)
    {
            byte[] msg = new byte[312 + 8];//[256 * 8];
            // These vars will contain the hash
            uint h0, h1, h2, h3;

            uint new_len, offset;
            uint[] w = new uint[16];
            uint a, b, c, d, i, f, g, temp;

            // Initialize variables - simple count in nibbles:
            h0 = 0x67452301;
            h1 = 0xefcdab89;
            h2 = 0x98badcfe;
            h3 = 0x10325476;

            //Pre-processing:
            //append "1" bit to message    
            //append "0" bits until message length in bits ? 448 (mod 512)
            //append length mod (2^64) to message
            //      312                                 (uint)((uint)512 / 8)    (448 / 8)
            for (new_len = initial_len + 1; new_len % (512 / 8) != 448 / 8; new_len++)
                ;

            Array.Copy(initial_msg, msg, initial_len);
            msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
            for (offset = initial_len + 1; offset < new_len; offset++)
            {
                msg[offset] = 0; // append "0" bits
            }

            // append the len in bits at the end of the buffer.
            to_bytes(initial_len * 8, msg, new_len);
            // initial_len>>29 == initial_len*8>>32, but avoids overflow.
            to_bytes(initial_len >> 29, msg, new_len + 4);

            // Process the message in successive 512-bit chunks:
            //for each 512-bit chunk of message:
            for (offset = 0; offset < new_len; offset += (512 / 8))
            {

                // break chunk into sixteen 32-bit words w[j], 0 ? j ? 15
                for (i = 0; i < 16; i++)
                {
                    w[i] = to_int32(msg, offset + i * 4);
                }

                // Initialize hash value for this chunk:
                a = h0;
                b = h1;
                c = h2;
                d = h3;

                // Main loop:
                for (i = 0; i < 64; i++)
                {

                    if (i < 16)
                    {
                        f = (b & c) | ((~b) & d);
                        g = i;
                    }
                    else if (i < 32)
                    {
                        f = (d & b) | ((~d) & c);
                        g = (5 * i + 1) % 16;
                    }
                    else if (i < 48)
                    {
                        f = b ^ c ^ d;
                        g = (3 * i + 5) % 16;
                    }
                    else
                    {
                        f = c ^ (b | (~d));
                        g = (7 * i) % 16;
                    }

                    temp = d;
                    d = c;
                    c = b;
                    b = b + LeftRotate((a + f + k[i] + w[g]), (int)r[i]);
                    a = temp;

                }

                // Add this chunk's hash to result so far:
                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;

            }

            // cleanup
            //    free(msg);

            //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
            to_bytes(h0, digest, 0);
            to_bytes(h1, digest, 4);
            to_bytes(h2, digest, 8);
            to_bytes(h3, digest, 12);
    }

    private static void to_bytes(uint val, byte[] bytes, uint Смещ)
    {
        bytes[0 + Смещ] = (byte)val;
        bytes[1 + Смещ] = (byte)(val >> 8);
        bytes[2 + Смещ] = (byte)(val >> 16);
        bytes[3 + Смещ] = (byte)(val >> 24);
    }
    private static uint to_int32(byte[] bytes, uint Смещ)
    {
        return (uint)bytes[0 + Смещ]
            | ((uint)bytes[1 + Смещ] << 8)
            | ((uint)bytes[2 + Смещ] << 16)
            | ((uint)bytes[3 + Смещ] << 24);
    }
    private static uint LeftRotate(uint x, int c)
    {
        return (uint)(((x) << (c)) | ((x) >> (32 - (c))));
    }

    private bool SendCommandToDevice(byte[] buffer, int offset, int size)
    {
        int randomNumber;
        if (offset != 0) throw new NotImplementedException();
        //Считаем CRC
        UInt16 crc = CRC16(buffer, (ushort)offset, (ushort)size); // расчитанное CRC16
        buffer[size] = (byte)(crc & 0xFF);
        buffer[size + 1] = (byte)((crc >> 8) & 0xFF);
        int Size_rnd = size + 2 + 32;
        if (Size_rnd <= 64)
        {
            Size_rnd = 64;
        }
        else if (Size_rnd <= 128)
        {
            Size_rnd = 128;
        }
        else
        {
            throw new NotImplementedException();
        }
        //Добавляем Size_rnd- 32 байта случаных чисел
        for (int i = 0; i < (Size_rnd - (size + 2)); i++)
        {
            randomNumber = random.Next(0, 255);
            buffer[size + 2 + i] = (byte)randomNumber;
        }
        buffer[Size_rnd - 1] = (byte)(size + 2);

        //Шифруем

        AesManaged aesManaged2 = new AesManaged();
        aesManaged2.Mode = CipherMode.ECB;
        encryptor = aesManaged2.CreateEncryptor(AES256_KEY, null);
        byte[] buffer2 = new byte[256];
        int Обработано = encryptor.TransformBlock(buffer, 0, Size_rnd, buffer2, 0);
        tcpstr.WriteTimeout = 1000;
        tcpstr.Write(buffer2, 0, Обработано);

        return true;
    }
    private ushort CRC16(byte[] pcBlock, ushort Start, ushort len)
    {
        ushort crc = 0xFFFF;
        byte i;
        ushort Указатель = Start;
        while (len-- > 0)
        {
            crc ^= (ushort)(pcBlock[Указатель++] << 8);

            for (i = 0; i < 8; i++)
                crc = ((crc & 0x8000) != 0) ? ((ushort)((crc << 1) ^ 0x1021)) : ((ushort)(crc << 1));
        }
        crc = (ushort)((crc << 8) + (crc >> 8));  // обмен байтов местами

        return crc;
    }
    private static void MakeHeading(byte[] buf, int CommandCode, uint ID, uint SendType, byte chan = 0)
    {
        //1 - magic
        buf[0] = (byte)(NUC_ETH_MAGIC & 0xFF);
        buf[1] = (byte)((NUC_ETH_MAGIC >> 8) & 0xFF);
        buf[2] = (byte)((NUC_ETH_MAGIC >> 16) & 0xFF);
        buf[3] = (byte)((NUC_ETH_MAGIC >> 24) & 0xFF);
        //2 id
        buf[4] = (byte)(ID & 0xFF);
        buf[5] = (byte)((ID >> 8) & 0xFF);
        buf[6] = (byte)((ID >> 16) & 0xFF);
        buf[7] = (byte)((ID >> 24) & 0xFF);
        //type
        buf[8] = (byte)(SendType & 0xFF);
        buf[9] = (byte)((SendType >> 8) & 0xFF);
        buf[10] = (byte)((SendType >> 16) & 0xFF);
        buf[11] = (byte)((SendType >> 24) & 0xFF);
        //command
        buf[12] = (byte)(CommandCode & 0xFF);
        buf[13] = (byte)chan;
        buf[14] = 0;
        buf[15] = 0;
    }
}
