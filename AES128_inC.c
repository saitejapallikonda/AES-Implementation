/*
 * Indian Institute of Information Technology Vadodara International Campus Diu
 * CS-364: Introduction to Cryptography and Network Security
 * Done by : Pallikonda Sai Teja
 */

#include <stdio.h>

// AES - Subbytes
unsigned char S[16][16] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

// The MixColumns matrix
const int mixColumnsMatrix[4][4] = {
    { 2, 3, 1, 1 },
    { 1, 2, 3, 1 },
    { 1, 1, 2, 3 },
    { 3, 1, 1, 2 }
};

// Function for multipling with x with s under modulo x^8 + x^4 + x^3 + x + 1
unsigned char x(unsigned char s)
{
	unsigned char t;
	t = (s<<1);
	
	if((s>>7) == 1)
	{
		t = (t ^ 27);
	}
	return (t);
}

// Sub Byte Function
unsigned char subByte(unsigned char a)
{
    int t1,t2;
    t1 = a & 15;
    t2 = (a>>4);

    return (S[t2][t1]);
}

// Inverse Sub Byte Function
unsigned char invSubByte(unsigned char a)
{
	int i,j;
	unsigned char x;
	for(i=0;i<16;i++)
	{
		for(j=0;j<16;j++)
		{
			if(S[i][j]==a)
			{
				x = i;
				x = ((x<<4)|j);
				break;
			}
		}
	}
	return x;
}

// Shift Row Function
void shiftRows(unsigned char cipher[4][4])
{
    unsigned char temp[4];
    int i,j=0;
    for(i = 1; i < 4; i++)
    {
        for(j = 0; j < 4; j++)
        {
            temp[j] = cipher[i][(j+i)%4];
        }
        for(j = 0; j < 4; j++)
        {
            cipher[i][j] = temp[j];
        }
    }
}

// Inverse Shift Row Function
void invShiftRows(unsigned char cipher[4][4])
{
    unsigned char temp[4];
    int i,j=0;
    for(i = 1; i < 4; i++)
    {
        for(j = 0; j < 4; j++)
        {
            temp[j] = cipher[i][(4+j-i)%4];
        }
        for(j = 0; j < 4; j++)
        {
            cipher[i][j] = temp[j];
        }
    }
}


// MixColumns function
void mixColumn(unsigned char input[4][4])
{
	unsigned char output[4][4] = {0};
	int i,j;
	
	for(j=0;j<4;j++)
	{
		for(i=0;i<4;i++)
		{
			output[i][j] = x(input[i][j]) ^ x(input[(i+1)%4][j]) ^ input[(i+1)%4][j] ^ input[(i+2)%4][j] ^ input[(i+3)%4][j];
		}	
	}
	for(j=0;j<4;j++)
	{
		for(i=0;i<4;i++)
		{
			input[i][j] = output[i][j];
		}	
	}
}

// Key Scheduling Algorithm of AES 128 
void keyScheduling(unsigned char key[16], unsigned char roundKey[11][4][4])
{
    unsigned int Rcon[] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};
	int i,j,k;
    
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            roundKey[0][j][i] = key[i * 4 + j];
        }
    }

    for (i = 1; i < 11; i++) 
	{
        unsigned char temp[4];

        temp[0] = roundKey[i - 1][1][3];
        temp[1] = roundKey[i - 1][2][3];
        temp[2] = roundKey[i - 1][3][3];
        temp[3] = roundKey[i - 1][0][3];
        for (j = 0; j < 4; j++) 
		{
            temp[j] = subByte(temp[j]);
        }
        temp[0] ^= Rcon[i - 1] >> 24;

        for (j = 0; j < 4; j++) 
		{
            roundKey[i][j][0] = roundKey[i - 1][j][0] ^ temp[j];
            for (k = 1; k < 4; k++) 
			{
                roundKey[i][j][k] = roundKey[i - 1][j][k] ^ roundKey[i][j][k - 1];
            }
        }
    }
}

/* Main Function */
int main()
{
	unsigned char plainText[4][4], cipherText[4][4], temp[4][4]; 
	unsigned char key[16];
	unsigned char roundKey[11][4][4];
	int i=0,j=0,k=0;
	
	// Taking Input Plain Text
	printf("Enter the Plain Text(in 16-hexadecimal) : \n");
	for(i = 0; i < 4; i++)
	{
		for(j = 0; j < 4; j++)
		{
			scanf("%x",&temp[i][j]);
		}
	}
	
	for(i = 0; i < 4; i++)
	{
		for(j = 0; j < 4; j++)
		{
			plainText[j][i] = temp[i][j];
		}
	}
	
	// Taking Input Key 
	printf("Enter the Key(in 16-hexadecimal) : \n");
	for(i=0;i<16;i++)
	{
		scanf("%x",&key[i]);
	}
	
	keyScheduling(key, roundKey); // function call will produce 11 round keys
	printf("\n");
	//Printing 11 Round Keys
	for (i = 0; i < 11; i++) 
	{
	    printf("Round Key %d : ", i);

    	for (j = 0; j < 4; j++) 
		{
        	for (k = 0; k < 4; k++) 
			{
            	printf("%x ", roundKey[i][k][j]);
        	}
    	}
    	printf("\n");
	}
	printf("\n");
	
	//Printing Plain Text before Encryption
	printf("Plain Text before Encryption : " );
	for(i = 0; i < 4; i++)
	{
		for(j = 0; j < 4; j++)
		{
			printf("%x ",plainText[j][i]);
		}
	}
	printf("\n");
	
	//Xoring Plain Text with RoundKey 0
	for(i = 0; i < 4; i++)
	{
		for(j = 0; j < 4; j++)
		{
			cipherText[j][i] = ((plainText[j][i]) ^ (roundKey[0][j][i])) ;
		}
	}
	
	// Encrypting Plain Text from Rounds 1 to 9
	for(i=1;i<=9;i++)
	{
		// Sub byte function for respective Round
		for(j=0;j<4;j++)
		{
			for(k=0;k<4;k++)
			{
				cipherText[j][k] = subByte(cipherText[j][k]);
			}
		}

		//Shift rows for respective Round
		shiftRows(cipherText);
		
		// Mix columns for respective Round
		mixColumn(cipherText);

		// Xoring with Round key of respective Round
		for (j = 0; j < 4; j++) 
		{
        	for (k = 0; k < 4; k++) 
			{
            	cipherText[k][j] ^= roundKey[i][k][j];
        	}
    	}
		
		// Printing Encrypted Plain Text after respective Round
		printf("\nEncrypted Cipher Text After Round %d : ",i);
		for(k = 0; k < 4; k++)
		{
			for(j = 0; j < 4; j++)
			{
				printf("%x ",cipherText[j][k]);
			}
		}
		
	}
	
	// Encrypting Plain Text in Round 10
	// Sub byte function for round 10
	for(j = 0; j < 4; j++)
	{
		for(k = 0; k < 4; k++)
		{
			cipherText[j][k] = subByte(cipherText[j][k]);
		}
	}

	// Shift rows function for Round 10
	shiftRows(cipherText);

	// Xoring with Round key 10
	for(j = 0; j < 4; j++)
	{
		for(k = 0; k < 4; k++)
		{
			cipherText[k][j] = cipherText[k][j] ^ roundKey[10][k][j];
		}
	}
	printf("\n");
	
	// Printing Final Encrypted Cipher Text after Round 10
	printf("\nCipher Text after final Encryption or (after Round 10) : ");
	for(i = 0; i < 4; i++)
	{
		for(j = 0; j < 4; j++)
		{
			printf("%x ",cipherText[j][i]);
		}
	}
	printf("\n");
	
	// Decryption of Round 10
	// Xoring with round key 10
	for(j=0;j<4;j++)
	{
		for(k=0;k<4;k++)
		{
			cipherText[k][j] = cipherText[k][j] ^ roundKey[10][k][j];
		}
	}
	
	// Inverse shift rows function for Round 10
	invShiftRows(cipherText);
	
	// Inverse Sub byte function for Round 10
	for(j=0;j<4;j++)
	{
		for(k=0;k<4;k++)
		{
			cipherText[j][k] = invSubByte(cipherText[j][k]);
		}
	}	
	
	// Decrypting Plain Text from Rounds 1 to 9
	for(i=9;i>=1;i--)
	{
		printf("\nDecrypted Cipher Text before Round %d : ",i);
		for(k = 0; k < 4; k++)
		{
			for(j = 0; j < 4; j++)
			{
				printf("%x ",cipherText[j][k]);
			}
		}
		// Xoring with round key of respective Round
		for(j = 0; j < 4; j++)
		{
			for(k = 0; k < 4; k++)
			{
				cipherText[k][j] = cipherText[k][j] ^ roundKey[i][k][j];
			}
		}
		
		// Inverse mix columns for respective Round
		mixColumn(cipherText);
		mixColumn(cipherText);
		mixColumn(cipherText);
		
		// Inverse shift rows for respective Round
		invShiftRows(cipherText);
		
		// Inverse sub byte function for respective Round
		for(j=0;j<4;j++)
		{
			for(k=0;k<4;k++)
			{
				cipherText[j][k] = invSubByte(cipherText[j][k]);
			}
		}	
	}
	
	// Xoring Cipher Text with RoundKey 0
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			cipherText[j][i] ^= roundKey[0][j][i];
		}
	}
	printf("\n");
	
	//Finally printing Decrypted Cipher Text
	printf("\nCipher Text after Decryption : ");
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			printf("%x ",cipherText[j][i]);
		}
	}
	
	printf("\n\n");
	//Printing Plain Text before Encryption
	printf("Plain Text before Encryption : " );
	for(i = 0; i < 4; i++)
	{
		for(j = 0; j < 4; j++)
		{
			printf("%x ",plainText[j][i]);
		}
	}
	printf("\nCipher Text after Decryption : ");
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			printf("%x ",cipherText[j][i]);
		}
	}
	printf("\n\nSuccessfully implemented the encryption as well as the decryption of AES-128 block cipher.\n");
}
