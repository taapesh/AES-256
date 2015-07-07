import java.io.*;
import java.util.Arrays;

public class AES
{
    private static final boolean DEBUG = false;
    private static final int INPUT_KEY_LENGTH = 32;         // Length of input key
    private static final int NUM_ROUNDS = 14;               // Number of rounds of algorithm to perform
    private static final int KC = 8;                        // Key columns
    private static final int NUM_COLS = (NUM_ROUNDS+1)*4;   // Number of columns in expanded key array
    private static final int LEN_STATE = 16;                // Length of state array


    private static byte[]   state = new byte[LEN_STATE];            // Array to hold state
    private static byte[][] roundKeys = new byte[NUM_COLS][4];      // Array to hold expanded key
    private static byte[]   tmpkey = new byte[4];                   // Array to hold temporary values used to expand key\
    private static byte[]   key;                      // Array to hold bytes of input key
    private static String   inputFile;                // Store name of input file

    private static final char[] RCON = {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d };

    private static final char[] SBOX = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

    private static final char[] INV_SBOX = {
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

    private final static int[] LogTable = {
            0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3,
            100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193,
            125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120,
            101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142,
            150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56,
            102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16,
            126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186,
            43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87,
            175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232,
            44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160,
            127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183,
            204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157,
            151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209,
            83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171,
            68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165,
            103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7};

    private final static int[] AlogTable = {
            1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53,
            95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170,
            229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49,
            83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205,
            76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136,
            131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154,
            181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163,
            254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160,
            251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65,
            195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117,
            159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
            155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84,
            252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202,
            69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14,
            18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23,
            57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1};

    private final static int[] STATE_IDX = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
    private final static int[] KEY_IDX = {
            0, 4, 8,  12, 16, 20, 24, 28,
            1, 5, 9,  13, 17, 21, 25, 29,
            2, 6, 10, 14, 18, 22, 26, 30,
            3, 7, 11, 15, 19, 23, 27, 31};

    private final static int[] KEY_IDX_EXPANDED = {
            0, 4, 8,  12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56,
            1, 5, 9,  13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57,
            2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58,
            3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59};


    public static void main(String[] args)
    {
        String keyFile;
        String option;

        // Get command line args
        if (args.length < 3)
        {
            System.err.println("Program usage: java AES <option> <name of key file> <name of input file>");
            return;
        }
        else
        {
            option = args[0];
            keyFile = args[1];
            inputFile = args[2];
        }

        /*
        // TESTING:
        inputFile = "plaintext";
        keyFile = "key";
        option = "e";
        */

        String line;
        try
        {
            BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(new File(keyFile))));

            if ((line = r.readLine()) != null)
                key = stringToByteArray(line);

            r.close();
        }
        catch (Exception e)
        {
            System.err.println(e.getMessage());
        }

        keyExpansion();

        if (option.equals("e"))
        {
            encrypt();

            // TESTING
            if (DEBUG)
            {
                inputFile += ".enc";
                decrypt();
                verifyDecryption();
            }
        }
        else if (option.equals("d"))
        {
            inputFile += ".enc";
            decrypt();
        }
    }

    public static void verifyDecryption()
    {
        String decryptedFile = "plaintext.enc.dec";
        String plaintextFile = "plaintext";

        try
        {
            BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(new File(decryptedFile))));
            String decryptedText = r.readLine();
            r.close();

            r = new BufferedReader(new InputStreamReader(new FileInputStream(new File(plaintextFile))));
            String originalText = r.readLine();
            r.close();

            if (decryptedText.equalsIgnoreCase(originalText))
            {
                System.out.println("Success!");
            }
            else
            {
                System.out.println("There was a problem.");
            }
        }
        catch (Exception e)
        {
            // pass
        }
    }

    private static void keyExpansion()
    {
        // First 32 entries are just the initial key
        for(int i = 0; i < KC; i++)
            for(int j = 0; j < 4; j++)
                roundKeys[i][j] = key[4 * i + j];

        // Assign temp key values
        for(int i = 0; i < 4; i++)
            tmpkey[i] = key[4 * KC + (i-4)];

        // Create rest of expanded key
        for(int i = KC; i < NUM_COLS; )
        {
            // ROTATE BYTES
            {
                byte tmp = tmpkey[0];
                for (int c = 0; c < 3; c++)
                    tmpkey[c] = tmpkey[c + 1];
                tmpkey[3] = tmp;
            }

            // SUB BYTES
            {
                tmpkey[0] = (byte) SBOX[(tmpkey[0] & 0xFF)];
                tmpkey[1] = (byte) SBOX[(tmpkey[1] & 0xFF)];
                tmpkey[2] = (byte) SBOX[(tmpkey[2] & 0xFF)];
                tmpkey[3] = (byte) SBOX[(tmpkey[3] & 0xFF)];
            }

            for(int j = 0; j < 4; j++)
            {
                if (j == 0)
                {
                    roundKeys[i][j] = (byte) (roundKeys[i-KC][j] ^ tmpkey[j] ^ RCON[i / KC]);
                }
                else
                {
                    roundKeys[i][j] = (byte) (roundKeys[i-KC][j] ^ tmpkey[j]);
                }
                tmpkey[j] = roundKeys[i][j];

            }
            i++;

            // Create next 12 bytes of expanded key
            for(int j = 0; j < 3; j++) {
                for (int k = 0; k < 4; k++) {
                    tmpkey[k] = (byte) (roundKeys[i - KC][k] ^ tmpkey[k]);
                    roundKeys[i][k] = tmpkey[k];
                }
                i++;
            }

            // Extra step for 256 bit key
            if(i < NUM_COLS)
            {
                // SUB BYTES
                {
                    tmpkey[0] = (byte) SBOX[(tmpkey[0] & 0xFF)];
                    tmpkey[1] = (byte) SBOX[(tmpkey[1] & 0xFF)];
                    tmpkey[2] = (byte) SBOX[(tmpkey[2] & 0xFF)];
                    tmpkey[3] = (byte) SBOX[(tmpkey[3] & 0xFF)];
                }

                for(int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        tmpkey[k] = (byte) (roundKeys[i - KC][k] ^ tmpkey[k]);
                        roundKeys[i][k] = tmpkey[k];
                    }
                    i++;
                }
            }
        }
    }

    public static void encrypt()
    {
        try
        {
            BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(new File(inputFile))));
            PrintWriter p = new PrintWriter(new File(inputFile + ".enc"));

            String line = r.readLine();

            // Append 0's to end of line if it is not 32 characters long already
            int length = line.length();
            while(length != INPUT_KEY_LENGTH) {
                line += "0";
                length++;
            }

            state = stringToByteArray(line);

            {
                System.out.println("The Plaintext is:");
                printState();
                System.out.println("The CipherKey is:");
                printKey(false);
                System.out.println();
                System.out.println("The expanded key is:");
                printKey(true);
                System.out.println();
            }

            addRoundKey(0);

            // Perform encryption rounds of AES-256
            for(int round = 1; round < NUM_ROUNDS; round++)
            {
                subBytes();
                shiftRows();
                mixColumns2();
                addRoundKey(round);
            }

            // One more round without mix columns step
            subBytes();
            shiftRows();
            addRoundKey(NUM_ROUNDS);

            String hex = "";
            String[] printThese = new String[16];

            for(int i = 0; i < LEN_STATE; i++)
            {
                String tmp = Integer.toHexString( (state[i] & 0xF0) >> 4);
                tmp += Integer.toHexString(state[i] & 0x0F);
                printThese[i] = tmp;
                hex += tmp;
            }

            // 0, 4, 8, 12
            // 1, 5, 9, 13
            // 2, 6, 10, 14
            // 3, 7, 11, 15
            System.out.println("The ciphertext:");
            for(int i = 1; i <= 16; i++)
            {
                System.out.print(printThese[STATE_IDX[i-1]].toUpperCase());

                if (i % 4 == 0)
                    System.out.println();
                else
                    System.out.print(" ");
            }

            hex = hex.toUpperCase();
            p.println(hex);
            r.close();
            p.close();
        }
        catch(Exception e)
        {
            System.err.println(e.getMessage());
        }
    }

    public static void decrypt()
    {
        try
        {
            BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(new File(inputFile))));
            PrintWriter p = new PrintWriter(new File(inputFile + ".dec"));

            String line = r.readLine();

            // Append 0's to end of line if it is not 32 characters long already
            int length = line.length();
            while(length != INPUT_KEY_LENGTH) {
                line += "0";
                length++;
            }

            state = stringToByteArray(line);

            addRoundKey(NUM_ROUNDS);
            invShiftRows();
            invSubBytes();

            // Perform decryption rounds of AES-256
            for(int round = NUM_ROUNDS-1; round >  0; round--)
            {
                addRoundKey(round);
                invMixColumn2();
                invShiftRows();
                invSubBytes();
            }
            addRoundKey(0);

            String hex = "";
            String[] printThese = new String[16];

            for(int i = 0; i < LEN_STATE; i++)
            {
                String tmp = Integer.toHexString( (state[i] & 0xF0) >> 4);
                tmp += Integer.toHexString(state[i] & 0x0F);
                printThese[i] = tmp;
                hex += tmp;
            }

            System.out.println("The decryption of the ciphertext:");
            for(int i = 1; i <= 16; i++)
            {
                System.out.print(printThese[STATE_IDX[i-1]].toUpperCase());

                if (i % 4 == 0)
                    System.out.println();
                else
                    System.out.print(" ");
            }
            System.out.println();
            System.out.println("The decryption of the ciphertext:");

            printStateLine();

            hex = hex.toUpperCase();

            p.println(hex);
            r.close();
            p.close();
        }
        catch (Exception e)
        {
            System.err.println(e.getMessage());
        }
    }

    private static void addRoundKey(int round)
    {
        int c = 0;
        for(int i = round * 4; i < (round+1)*4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[c] = (byte) (state[c] ^ roundKeys[i][j]);
                c++;
            }
        }
        System.out.println("After addRoundKey(" + round + "):");
        printStateLine();
    }

    private static void subBytes()
    {
        for(int i = 0; i < state.length; i++)
            state[i] = (byte) SBOX[(state[i] & 0xFF)];

        System.out.println("After subBytes:");
        printStateLine();
    }

    private static void shiftRows()
    {
        byte[] newState = new byte[LEN_STATE];
        int idx = 0;
        for(int i = 0; i < LEN_STATE; i++)
        {
            newState[i] = state[idx];
            idx += 5;
            if (idx > LEN_STATE-1)
            {
                idx = idx - LEN_STATE;
            }
        }
        state = newState;

        System.out.println("After shiftRows");
        printStateLine();
    }

    // In the following two methods, the input c is the column number in
    // your evolving state matrix st (which originally contained
    // the plaintext input but is being modified).  Notice that the state here is defined as an
    // array of bytes.  If your state is an array of integers, you'll have
    // to make adjustments.

    // I had to modify the the indexes because I did not use a 2D array to represent state
    private static void mixColumns2()
    {
        // This is another alternate version of mixColumn, using the
        // logtables to do the computation.
        byte[] a = new byte[4];

        for(int i = 0; i < 4; i++)
        {
            // Indexes: 1,2,3...,15
            int i0 = i * 4;
            int i1 = i0 + 1;
            int i2 = i1 + 1;
            int i3 = i2 + 1;

            a[0] = state[i0];
            a[1] = state[i1];
            a[2] = state[i2];
            a[3] = state[i3];

            state[i0] = (byte)(mul(2,a[0]) ^ a[2] ^ a[3] ^ mul(3,a[1]));
            state[i1] = (byte)(mul(2,a[1]) ^ a[3] ^ a[0] ^ mul(3,a[2]));
            state[i2] = (byte)(mul(2,a[2]) ^ a[0] ^ a[1] ^ mul(3,a[3]));
            state[i3] = (byte)(mul(2,a[3]) ^ a[1] ^ a[2] ^ mul(3,a[0]));
        }

        System.out.println("After mixColumns:");
        printStateLine();
    }

    private static void invSubBytes()
    {
        for(int i = 0; i < state.length; i++)
            state[i] = (byte) INV_SBOX[(state[i] & 0xFF)];

        System.out.println("After invSubBytes");
        printStateLine();
    }

    private static void invShiftRows()
    {
        byte[] newState = new byte[LEN_STATE];

        int idx = 0;
        for(int i = 0; i < LEN_STATE; i++)
        {
            newState[idx] = state[i];
            idx += 5;
            if (idx > 15)
            {
                idx = idx - LEN_STATE;
            }
        }
        state = newState;

        System.out.println("After invShiftRows");
        printStateLine();
    }

    private static void invMixColumn2()
    {
        byte a[] = new byte[4];

        for(int i = 0; i < 4; i++)
        {
            // Indexes: 1,2,3...,15
            int i0 = i * 4;
            int i1 = i0 + 1;
            int i2 = i1 + 1;
            int i3 = i2 + 1;

            a[0] = state[i0];
            a[1] = state[i1];
            a[2] = state[i2];
            a[3] = state[i3];

            state[i0] = (byte)(mul(0xE,a[0]) ^ mul(0xB,a[1]) ^ mul(0xD, a[2]) ^ mul(0x9,a[3]));
            state[i1] = (byte)(mul(0xE,a[1]) ^ mul(0xB,a[2]) ^ mul(0xD, a[3]) ^ mul(0x9,a[0]));
            state[i2] = (byte)(mul(0xE,a[2]) ^ mul(0xB,a[3]) ^ mul(0xD, a[0]) ^ mul(0x9,a[1]));
            state[i3] = (byte)(mul(0xE,a[3]) ^ mul(0xB,a[0]) ^ mul(0xD, a[1]) ^ mul(0x9,a[2]));
        }

        System.out.println("After invMixColumns:");
        printStateLine();
    }

    private static byte[] stringToByteArray(String s)
    {
        int len = s.length();
        byte[] ar = new byte[len / 2];
        int j = 0;
        for(int i = 0; i < len / 2; i++)
        {
            ar[i] = (byte) ((Character.digit(s.charAt(j++), LEN_STATE) << 4) + Character.digit(s.charAt(j++), LEN_STATE));
        }
        return ar;
    }

    private static byte mul(int a, byte b)
    {
        int inda = (a < 0) ? (a + 256) : a;
        int indb = (b < 0) ? (b + 256) : b;

        if ( (a != 0) && (b != 0) )
        {
            int index = (LogTable[inda] + LogTable[indb]);
            return (byte)(AlogTable[ index % 255 ] );
        }
        else
            return 0;
    }

    private static void printState()
    {
        for(int i = 1; i <= 16; i++)
        {
            String s = String.format("%02X", state[STATE_IDX[i-1]] & 0xFF);
            System.out.print(s);

            if (i % 4 == 0)
                System.out.println();
            else
                System.out.print(" ");
        }
        System.out.println();
    }

    private static void printStateLine()
    {
        for(int i = 1; i <= 16; i++)
        {
            String s = String.format("%02X", state[i-1] & 0xFF);
            System.out.print(s);
        }
        System.out.println();
    }

    private static void printKey(boolean isExpanded) {
        String[] printThese =  new String[60];

        if (!isExpanded)
        {
            for (int i = 1; i <= 32; i++)
            {
                String s = String.format("%02X", key[KEY_IDX[i-1]]);
                System.out.print(s);

                if (i % 8 == 0)
                    System.out.println();
                else
                    System.out.print(" ");
            }
        }
        else
        {
            int n = 0;
            int col = 0;
            int start = 0;
            int counter = 1;

            for(int i = 1; i <= 60; i++)
            {
                String s = "";
                for(int j = 0; j < 4; j++)
                {
                    //System.out.println("(" + n + "," + col + ")");
                    s += String.format("%02X", roundKeys[n][col]);
                    n++;
                }
                n = start;

                counter++;
                if (counter % 4 == 0)
                    start += 4;

                col++;
                if(col == 4)
                    col = 0;

                printThese[i-1] = s;
            }

            for (int i = 1; i <= 60; i++)
            {
                System.out.print(printThese[KEY_IDX_EXPANDED[i - 1]]);

                if (i % 15 == 0)
                    System.out.println();
                else
                    System.out.print(" ");
            }
        }
    }
}