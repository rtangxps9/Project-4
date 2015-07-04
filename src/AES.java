import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;

import javax.xml.bind.DatatypeConverter;

public class AES {

	// The round constant word array.
	final static int RCON[] = {
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
		0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d};

	// S-box
	final static int S[] = {
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
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

	// Inverse S-box
	final static int INV_S[] = {
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
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

	final static int[] LogTable = {
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

	final static int[] AlogTable = {
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

	final static int ROUNDS = 14; // Number of rounds to perform. AES-128 10 AES-192 12 AES-256 14
	final static int COLUMNS = 4; // Number of columns comprising of the State.
	final static int WORDS = 8;   // Number of 32-bit words comprising of the Cipher Key. AES-128 4 AES-192 6 AES-256 8

	// Small function that takes the byte value and returns the corresponding S-box value.
	private static byte subByte (byte value) {
		return (byte) (S[value & 0x000000ff] & 0xff);
	}

	//Inverse of subByte
	private static byte invSubByte (byte value) {
		return (byte) (INV_S[value & 0x000000ff] & 0xff);
	}

	private static byte[] subBytes (byte[] state) {
		byte[] sWord = new byte[4];
		for(int i = 0; i < COLUMNS; i++) {
			sWord = getWord(i, state, sWord);
			sWord = subWord(sWord);
			setWord(i, sWord, state);
		}
		return state;
	}

	private static byte[] invSubBytes (byte[] state) {
		byte[] sWord = new byte[4];
		for(int i = 0; i < COLUMNS; i++) {
			sWord = getWord(i, state, sWord);
			sWord = invSubWord(sWord);
			setWord(i, sWord, state);
		}
		return state;
	}

	private static byte[] getRow (int nthRow, byte[] source, byte[] result) {
		for(int i = 0; i < COLUMNS; i++)
			result[i] = source[nthRow + i * 4];
		return result;
	}

	private static byte[] setRow (int nthRow, byte[] row, byte[] destination) {
		for(int i = 0; i < COLUMNS; i++)
			destination[nthRow + i * 4] = row[i];
		return destination;
	}

	private static byte[] shiftRows (byte[] state) {
		byte[] temp = new byte[4];
		for(int i = 1; i < 4; i++) {
			temp = getRow(i, state, temp);
			for(int j = 0; j < i; j++)
				temp = rotWord(temp);
			setRow(i, temp, state);
		}

		return state;
	}

	private static byte[] invShiftRows (byte[] state) {
		byte[] temp = new byte[4];
		for(int i = 1; i < 4; i++) {
			temp = getRow(i, state, temp);
			for(int j = 0; j < i; j++)
				temp = invRotWord(temp);
			setRow(i, temp, state);
		}

		return state;
	}

	private static byte[] mixColumns (byte[] state) {
		byte[] temp = new byte[4];

		for (int i = 0; i < COLUMNS; i++) {
			temp = getWord(i, state, temp);
			temp = mixColumn2(i, temp);
			setWord(i, temp, state);
		}

		return state;
	}

	private static byte[] mixColumn2 (int c, byte[] word) {
		// This is another alternate version of mixColumn, using the 
		// logtables to do the computation.
		byte[] temp = new byte[4];

		// This is exactly the same as mixColumns1, if 
		// the mul columns somehow match the b columns there.
		temp[0] = (byte)(mul(2,word[0]) ^ word[2] ^ word[3] ^ mul(3,word[1]));
		temp[1] = (byte)(mul(2,word[1]) ^ word[3] ^ word[0] ^ mul(3,word[2]));
		temp[2] = (byte)(mul(2,word[2]) ^ word[0] ^ word[1] ^ mul(3,word[3]));
		temp[3] = (byte)(mul(2,word[3]) ^ word[1] ^ word[2] ^ mul(3,word[0]));

		for (int i = 0; i < 4; i++) {
			word[i] = temp[i];
		}
		return word;
	} // mixColumn2

	private static byte[] invMixColumns (byte[] state) {
		byte[] temp = new byte[4];

		for (int i = 0; i < COLUMNS; i++) {
			temp = getWord(i, state, temp);
			temp = invMixColumn2(i, temp);
			setWord(i, temp, state);
		}

		return state;
	}

	private static byte[] invMixColumn2 (int c, byte[] word) {
		byte temp[] = new byte[4];

		temp[0] = (byte)(mul(0xE,word[0]) ^ mul(0xB,word[1]) ^ mul(0xD, word[2]) ^ mul(0x9,word[3]));
		temp[1] = (byte)(mul(0xE,word[1]) ^ mul(0xB,word[2]) ^ mul(0xD, word[3]) ^ mul(0x9,word[0]));
		temp[2] = (byte)(mul(0xE,word[2]) ^ mul(0xB,word[3]) ^ mul(0xD, word[0]) ^ mul(0x9,word[1]));
		temp[3] = (byte)(mul(0xE,word[3]) ^ mul(0xB,word[0]) ^ mul(0xD, word[1]) ^ mul(0x9,word[2]));

		for (int i = 0; i < 4; i++) {
			word[i] = temp[i];
		}
		return word;
	} // invMixColumn2

	private static byte[] addRoundkey (byte[] state, byte[] key, int round) {
		byte[] sWord = new byte[4];
		byte[] kWord = new byte[4];
		for (int i = 0; i < COLUMNS; i++) {
			sWord = getWord(i, state, sWord);
			kWord = getWord(i + round * COLUMNS, key, kWord);
			setWord(i, xor(sWord, kWord), state);
		}

		return state;
	}

	// This method takes in the input key and creates a key schedule.
	// The output is the expanded key.
	private static byte[] keyExpansion (byte[] key) {
		byte[] result = new byte[240];
		byte[] word = new byte[4];
		byte[] temp = new byte[4];
		int i = 0;

		// Put key into the first 32 bytes into the expanded key
		while (i < WORDS) {
			setWord(i, getWord(i, key, word), result);
			i++;
		}

		while (i < COLUMNS * (ROUNDS + 1)) {
			getWord(i - 1, result, word);
			if (i % WORDS == 0) {
				word = subWord(rotWord(word));
				word[0] = (byte) (word[0] ^ (RCON[i/WORDS] & 0xff));
			}
			else if (WORDS > 6 && i % WORDS == 4)
				word = subWord(word);
			word = xor(word, getWord(i - WORDS, result, temp));
			setWord(i, word, result);
			i++;
		}

		return result;
	}

	// Takes a four byte word and applies S-box to each of the four bytes.
	private static byte[] subWord (byte[] word) {
		for(int i = 0; i < 4; i++) {
			word[i] = subByte(word[i]);
		}
		return word;
	}

	// Takes a four byte word and returns each byte's location in the S-box
	private static byte[] invSubWord (byte[] word) {
		for(int i = 0;i < 4; i++) {
			word[i] = invSubByte(word[i]);
		}
		return word;
	}	

	// Takes a four byte word and performs a cyclic permutation.
	private static byte[] rotWord (byte[] word) {
		byte temp;
		temp = word[0];
		for(int i = 0; i < 3; i++)
			word [i] = word[i+1];
		word[3] = temp;
		return word;
	}

	// Inverses the rotWord method
	private static byte[] invRotWord (byte[] word) {
		byte temp;
		temp = word[3];
		for(int i = 3; i > 0; i--)
			word [i] = word[i-1];
		word[0] = temp;
		return word;
	}

	// Write a word to the nth place of the destination.
	private static void setWord (int nthWord, byte[] word, byte[] destination) {
		int start = nthWord * 4;
		for (int i = 0; i < 4; i++) {
			destination[start + i] = word[i];
		}
	}

	// Read the nth word from the source.
	private static byte[] getWord (int nthWord, byte[] source, byte[] result) {
		int start = nthWord * 4;
		for (int i =  0; i < 4; i++) {
			result[i] = source[start + i];
		}
		return result;
	}

	// Utility Functions
	// Converts byte array to hex string.
	// Input:	byte[] array
	// Output:	String (this is a hex string)
	public static String toHexString (byte[] array) {
		return DatatypeConverter.printHexBinary(array);
	}

	// Converts hex string to byte array.
	// Input:	String s (this is a hex string)
	// Output:	byte[]
	public static byte[] toByteArray (String s) {
		return DatatypeConverter.parseHexBinary(s);
	}

	// XOR function that performs word1 ^ word2.
	// Input:	byte[] word1, byte[] word2
	// Output:	byte[] word1
	private static byte[] xor (byte[] word1, byte[] word2) {
		for (int i = 0; i < word1.length; i++) {
			word1[i] = (byte) (word1[i] ^ word2[i]);
		}

		return word1;
	}

	private static byte mul (int a, byte b) {
		int inda = (a < 0) ? (a + 256) : a;
		int indb = (b < 0) ? (b + 256) : b;

		if ( (a != 0) && (b != 0) ) {
			int index = (LogTable[inda] + LogTable[indb]);
			byte val = (byte)(AlogTable[ index % 255 ] );
			return val;
		}
		else 
			return 0;
	} // mul

	private static byte[] encrypt (byte[] state, byte[] expandedKey) {
		int round = 0;

		// Step 2: Initial Round
		//   1. AddRoundKey
		state =  addRoundkey(state, expandedKey, round);

		//System.out.println("After addRoundKey(" + round + "):");
		//System.out.println(toHexString(state));


		// Step 3: Rounds
		//   1. SubBytes
		//   2. ShiftRows
		//   3. MixColumns
		//   4. AddRoundKey
		round++;
		while (round < ROUNDS) {
			state = subBytes(state);
			//System.out.println("After subBytes:");
			//System.out.println(toHexString(state));
			state = shiftRows(state);
			//System.out.println("After shiftRows:");
			//System.out.println(toHexString(state));
			state = mixColumns(state);
			//System.out.println("After mixColumns:");
			//System.out.println(toHexString(state));
			state = addRoundkey(state, expandedKey, round);
			//System.out.println("After addRoundKey(" + round + "):");
			//System.out.println(toHexString(state));
			round++;
		}
		//System.out.println("Round: " + round);

		// Step 4: Final Round
		//   1. SubBytes
		//   2. ShiftRows
		//   3. AddRoundKey
		state = subBytes(state);
		//System.out.println("After subBytes:");
		//System.out.println(toHexString(state));
		state = shiftRows(state);
		//System.out.println("After shiftRows:");
		//System.out.println(toHexString(state));
		state = addRoundkey(state, expandedKey, round);
		//System.out.println("After addRoundKey(" + round + "):");
		//System.out.println(toHexString(state));

		return state;
	}

	private static byte[] decrypt (byte[] state, byte[] expandedKey) {
		int round = 14;

		state =  addRoundkey(state, expandedKey, round);
		//System.out.println("After addRoundKey(" + round + "):");
		//System.out.println(toHexString(state));
		state = invShiftRows(state);
		//System.out.println("After invShiftRows:");
		//System.out.println(toHexString(state));
		state = invSubBytes(state);
		//System.out.println("After invSubBytes:");
		//System.out.println(toHexString(state));
		round--;

		while (round > 0) {
			state = addRoundkey(state, expandedKey, round);
			//System.out.println("After addRoundKey(" + round + "):");
			//System.out.println(toHexString(state));
			state = invMixColumns(state);
			//System.out.println("After invMixColumns:");
			//System.out.println(toHexString(state));
			state = invShiftRows(state);
			//System.out.println("After invShiftRows:");
			//System.out.println(toHexString(state));
			state = invSubBytes(state);
			//System.out.println("After invSubBytes:");
			//System.out.println(toHexString(state));
			round--;
		}

		state = addRoundkey(state, expandedKey, round);
		//System.out.println("After addRoundKey(" + round + "):");
		//System.out.println(toHexString(state));

		return state;
	}

	public static void main(String[] args) {		
		if (args.length != 3) {
			System.err.println("Must have three arguments.");
			return;
		}

		String mode, keyFileName, inputFileName;
		long startTime, endTime;

		mode = args[0];
		if (!(mode.equals("e")) && !(mode.equals("d"))) {
			System.err.println("Invalid option.");
			return;
		}
		
		keyFileName = args[1];
		inputFileName = args[2];

		try {
			BufferedReader input = new BufferedReader(new FileReader(inputFileName));
			BufferedReader key = new BufferedReader(new FileReader(keyFileName));
			String inputLine, keyLine;

			if ((keyLine = key.readLine()) == null) {
				System.err.println("Empty key file.");
			}
			else {
				// Step 1: Key Expansions
				byte[] expandedKey = keyExpansion(toByteArray(keyLine));
				
				File output = new File (inputFileName + "." + ((mode.equals("e")) ? "enc" : "dec"));
				
				if (!output.exists()) {
					output.createNewFile();
				}
				
				FileWriter fw = new FileWriter(output.getAbsoluteFile());
				BufferedWriter bw = new BufferedWriter(fw);
				
				startTime = System.nanoTime();
				while ((inputLine = input.readLine()) != null) {
					if(inputLine.length() > 32)
						inputLine = inputLine.substring(0,32);
					else if(inputLine.length() == 32)
						inputLine = inputLine;
					else {
						int remaining = 32 - inputLine.length();
						String toAdd = "";
						for(int i = 0;i<remaining;i++)
							toAdd += '0';
						inputLine += toAdd;
					}
					// Step 1.1: Move the input to a byte array.
					try {
						byte[] state = toByteArray(inputLine);
						if (mode.equals("e")) {
							state = encrypt(state, expandedKey);
						}
						else {
							state = decrypt(state, expandedKey);
						}
						bw.write(toHexString(state) + "\n");
					}
					catch (IllegalArgumentException e) {
						System.err.println("ERROR: Input line contains illegal character.");
						continue;
					}
				}
				endTime = System.nanoTime();
				double difference = endTime - startTime;
				double newDiff = difference / 1000000;
				long filesize = (new File(inputFileName)).length();
				double bandwidth = (filesize) / difference;
				System.out.println(bandwidth + " bytes/ms");
				bandwidth = bandwidth * 8 / 1000;
				System.out.println(bandwidth + " MB/s");
				bw.close();
			}

			input.close();
			key.close();
		}
		catch (FileNotFoundException e) {
			System.out.println( "Unable to open file '" + 
					inputFileName + "' or '" + keyFileName + "'");  
		}
		catch (IOException e) {
			System.out.println( "Error reading file '" +
					inputFileName + "' or '" + keyFileName + "'");
		}
		
		

		//String key = "0000000000000000000000000000000000000000000000000000000000000000";
		//String plaintext = "00112233445566778899AABBCCDDEEFF";
		//String option = "e";

		//state = encrypt(state, expandedKey);
		//System.out.println("\n\n\n\nDECRYPTION STARTS HERE");
		//state = decrypt(state, expandedKey);


		/*		boolean DEBUG = false;
//
//		int i = 0, j, Nb, Nk, Nr;
//		boolean encrypt = true;
//		String arg;
//		int length = 128, reqArgCounter = 0;
//		boolean ECB = true;
//		String mode = null, keyFileName, inputFileName;
//
//		// Parsing command line.
//		while (i < args.length) {
//			arg = args[i++];
//			if (arg.startsWith("-")) {
//				if (arg.equals("-length")) {
//					if (i < args.length)
//						length = Integer.parseInt(args[i++]);
//					else
//						System.err.println("-length requires a length");
//					if (DEBUG)
//						System.out.println("length = " + length);
//				}
//				else if (arg.equals("-mode")) {
//					if (i < args.length)
//						mode = args[i++]; 
//					if (mode.equals("CBC"))
//						ECB = false;
//					else if (mode.equals("ECB"))
//						ECB = true;
//					else
//						System.err.println("AES: illegal mode " + mode);						
//				}
//				else
//					System.err.println("AES: unknown option " + arg);
//			}
//			else {
//				if (reqArgCounter == 0) {
//					encrypt = (arg.equals("e")) ? true : false;
//					reqArgCounter++;
//				}
//				else if (reqArgCounter == 1) {
//					keyFileName = arg;
//					reqArgCounter++;
//				}
//				else {
//					inputFileName = arg;
//					reqArgCounter++;
//				}
//			}
//		}
//		if (i == args.length)
//			System.err.println("Usage: AES option [length] [mode] keyFile inputFile");
//		else if (reqArgCounter != 3)
//			System.err.println("AES: not enough required arguments or invalid number of arguments");
//		else {
//			System.out.println("This is our implementation of AES-" + Integer.toString(length) + " using " + mode + " block cipher mode.");
//			// TODO: Delete this when bonus completed
//			System.out.println("Currently the options are not implemented. Thus this is just AES-256 ECB.");
//			
//			if (encrypt) {
//				
//			}
//			else {
//
//			}
//		}*/

	}

}
