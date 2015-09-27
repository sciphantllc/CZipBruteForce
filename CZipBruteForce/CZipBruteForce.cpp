#include "stdafx.h"

/*
CZipBruteForce

This program is designed to do a fast password-based brute force attack on a zip file.  It has a number of
optimizations to make it reasonably fast.  While the code is Windows-specific, it could be made to work on
most platforms pretty easily.

TODO:
1) The zip file support in this is rudimentary at best and just enough to get at the first file in the zip.  In the 
   future, it'd probably be  better to support specifying the filename on the command line or automatically picking 
   the smallest file with a password (since it will process fastest).
2) Command line processing should be made better
3) Allow specifying the valid password characters
4) The passwords printed while running are AFTER the last block given out, which has not been processed yet.  In order
   to make these more useful for continuing with the "-password" command line option, print the last COMPLETED 
   password.
5) Verbosity setting for output
6) Make the successful password the last thing printed, even though other threads are still processing.
7) Don't require the whole file to be read in at once
*/

#define ProcessLastPasswordByte ProcessLastPasswordByte3
#define ProcessPasswords ProcessPasswords1

// Arbitrary limit on maximum password length.  
// Realistically, trying more than this is probably not very useful except if the valid character set is very, very small
const int MAX_PASSWORD_LENGTH = 15;


/*********************************************
** Zip-specific structures and enumerations **
*********************************************/

// Compression types, as used by the zip file format
enum CompressionType
{
    COMP_STORED    = 0,
    COMP_SHRUNK    = 1,
    COMP_REDUCED1  = 2,
    COMP_REDUCED2  = 3,
    COMP_REDUCED3  = 4,
    COMP_REDUCED4  = 5,
    COMP_IMPLODED  = 6,
    COMP_TOKEN     = 7,
    COMP_DEFLATE   = 8,
    COMP_DEFLATE64 = 9   
};


// A file record structure from a zip file
#pragma pack(push, 1)
struct ZipFileRecord
{
    BYTE rgbSignature[4];    //0x04034b50
    WORD wVersion;
    WORD wFlags;
    WORD wCompression;
    WORD wFileTime;
    WORD wFileDate;
    DWORD dwCrc;
    DWORD dwCompressedSize;
    DWORD dwUncompressedSize;
    WORD wFileNameLength;
    WORD wExtraFieldLength;
};
#pragma pack(pop)

// The number of bytes in the encryption header
const int ENCRYPTION_HEADER_LENGTH = 12;


/*****************************
** Table-building functions **
*****************************/

// Build the CRC32 table
__declspec(align(128)) DWORD g_rgdwCRC32Table[256];
void BuildCRCTable()
{
    const DWORD dwPolynomial = 0xEDB88320;

	for (DWORD dwByte = 0; dwByte < 256; dwByte++)
    {
		DWORD dwCrc = dwByte;
		for (DWORD j = 0; j < 8; j++)
		{
			dwCrc = (dwCrc >> 1) ^ (-int(dwCrc & 1) & dwPolynomial);
		}
		
		g_rgdwCRC32Table[dwByte] = dwCrc;
    }
}


// Build the table that replaces the decrypt_byte function
__declspec(align(128)) BYTE g_rgbDecryptByteTable[65536];
void BuildDecryptByteTable()
{
	for ( DWORD i = 0; i < 65536; i++ )
	{
        WORD wTemp = ((i & 0xffff) | 2);

		g_rgbDecryptByteTable[i] = ((wTemp * (wTemp ^ 1)) >> 8);
	}
}


// Table to help in dealing with finding the next relevant password byte
__declspec(align(128)) BYTE g_rgbPasswordTraversalTable[256];
BYTE g_rgbPasswordOffsets[256]; // Inverse lookup for character to position
void GenerateValidCharsTable(BYTE* pbValidBytes, int nValidByteCount, BYTE bTableStartIndex)
{
	// Start all entries pointing to the start entry
	for ( int nIndex = 0; nIndex < 256; nIndex++ )
	{
		g_rgbPasswordTraversalTable[nIndex] = bTableStartIndex;
		g_rgbPasswordOffsets[nIndex] = (BYTE)nIndex;
	}

	// Next, build the table
    for (int nIndex = 0; nIndex < nValidByteCount - 1; nIndex++)
    {
        g_rgbPasswordTraversalTable[pbValidBytes[nIndex]] = pbValidBytes[nIndex + 1];
		g_rgbPasswordOffsets[pbValidBytes[nIndex]] = (BYTE)nIndex;
    }
	g_rgbPasswordTraversalTable[pbValidBytes[nValidByteCount - 1]] = 0;
	g_rgbPasswordOffsets[pbValidBytes[nValidByteCount - 1]] = (BYTE)nValidByteCount - 1;
	g_rgbPasswordOffsets[0] = 0x0;
}


// Structure to hold the state related to a particular thread
struct ThreadData
{
	BYTE* pbOutputBuffer; // Pointer to the thread-specific buffer for the decompressed data
	z_stream decompressionStream; // thread-specific z_stream instance
	QWORD qwPasswordsProcessed; // Count of the number of passwords processed by this thread
};


// These are the same for all threads
BYTE* g_pbAlignedEncryptedData = NULL; // The encrypted data for the file
BYTE g_bPasswordVerificationValue; // The LSB of the CRC32
BYTE* g_pbFileBuffer = NULL; // Buffer to hold the zip file
ZipFileRecord* g_pFileRecord; // Pointer to the relevant zip header entry
CompressionType g_compressionType; // The type of compression for the file
BOOL g_fFound = FALSE; // Set to TRUE if the password is found
volatile BOOL g_fKeepProcessing = TRUE; // Set to FALSE to stop processing, like if the password was found
CRITICAL_SECTION g_passwordCritSec; // Critical section to use when giving out batches of passwords

QWORD g_qwPasswordsPerGroup; // Number of passwords to give out at once
DWORD g_dwPasswordsPerGroupPower; // An order of magnitude of passwords to give out at once, based on the number of valid characters
size_t g_nValidPasswordCharacterCount = 0; // Count of the number of valid password characters

// List of all the possible password characters to try
BYTE g_rgbValidPasswordCharacters[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '~', '`', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '-', '+', '=',
	                                    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 
										'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
									    '{', '[', '}', ']', '|', '\\', ':', ';', '\"', '\'', '<', ',', '>', '.', '?', '/', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0' }; // 94 total, not including NULLs


DWORD inline FullEvalCRCInflate(ThreadData* pThreadData, DWORD dwKey0, DWORD dwKey1, DWORD dwKey2, DWORD dwDataBytes, BYTE* pbNextDataByte)
{
	const int DECRYPT_BLOCK_SIZE = 5;

	int err;
	BYTE c;
	DWORD dwCalculatedCRC;
	DWORD dwBytesDecrypted;
	BYTE* pbOutputByte;
	DWORD dwBytesLeft = dwDataBytes;
	BYTE rgbDecryptedBuffer[DECRYPT_BLOCK_SIZE];

	// Prepare the decompression stream
    err = inflateReset(&(pThreadData->decompressionStream));
	if ( Z_OK != err )
	{
		return 0;
	}

	pThreadData->decompressionStream.next_out = pThreadData->pbOutputBuffer;
	pThreadData->decompressionStream.avail_out = (uInt)g_pFileRecord->dwUncompressedSize;

	// Decrypt in blocks - ideally we decrypt as little at a time as possible before hitting an error, but do it as efficiently as possible.
	dwBytesDecrypted = 0;
	do
	{
		pbOutputByte = rgbDecryptedBuffer;

		// Decrypt a block of data
		DWORD dwBlockSize = (DECRYPT_BLOCK_SIZE > dwBytesLeft) ? dwBytesLeft : DECRYPT_BLOCK_SIZE;
		DWORD dwBytesToDecrypt = dwBlockSize;
		do
		{
			c = *pbNextDataByte ^ g_rgbDecryptByteTable[(WORD)dwKey2];

		    dwKey0 = g_rgdwCRC32Table[(BYTE)(dwKey0 ^ c)] ^ (dwKey0 >> 8);
		    dwKey1 = dwKey1 + (BYTE)dwKey0;
		    dwKey1 = dwKey1 * 0x08088405 + 1;
		    dwKey2 = (g_rgdwCRC32Table[((BYTE)dwKey2 ^ ((BYTE)(dwKey1 >> 24)))] ^ (dwKey2 >> 8));

			*pbOutputByte++ = c;

			pbNextDataByte++;
		}
		while ( --dwBytesToDecrypt );

		// Decompress the decrypted data
	    pThreadData->decompressionStream.next_in  = rgbDecryptedBuffer;
	    pThreadData->decompressionStream.avail_in = dwBlockSize;

		err = inflate(&pThreadData->decompressionStream, Z_NO_FLUSH);

		// Make sure that all the input was used
		if (0 != pThreadData->decompressionStream.avail_in)
		{
			return 0;
		}

		if ( (Z_OK != err ) && ( Z_STREAM_END != err ) )
		{
			return 0;
		}

		dwBytesLeft -= dwBlockSize;
	}
	while ((pThreadData->decompressionStream.avail_out) && (dwBytesLeft));

	// CRC32 the data
	pbNextDataByte = pThreadData->pbOutputBuffer;
	dwCalculatedCRC = 0xffffffff;
	dwBytesLeft = g_pFileRecord->dwUncompressedSize;
	do
	{
		c = *pbNextDataByte;

		pbNextDataByte++;

	    dwCalculatedCRC = ((dwCalculatedCRC) >> 8) ^ g_rgdwCRC32Table[(c) ^ ((dwCalculatedCRC) & 0x000000FF)];
		dwBytesLeft--;
	}
	while ( dwBytesLeft );
	dwCalculatedCRC = ~dwCalculatedCRC;

	return dwCalculatedCRC;
}


DWORD inline FullEvalCRC(ThreadData* pThreadData, DWORD dwKey0, DWORD dwKey1, DWORD dwKey2, DWORD dwBytesLeft, BYTE* pbNextDataByte)
{
	switch ( g_pFileRecord->wCompression )
	{
	case COMP_DEFLATE:
		return FullEvalCRCInflate(pThreadData, dwKey0, dwKey1, dwKey2, dwBytesLeft, pbNextDataByte);

	case COMP_SHRUNK:
	case COMP_REDUCED1:
	case COMP_REDUCED2:
	case COMP_REDUCED3:
	case COMP_REDUCED4:
	case COMP_IMPLODED:
	case COMP_TOKEN:
	case COMP_DEFLATE64:
	default:
		return 0;
	}

	return 0;
}


__declspec(nothrow) BYTE ProcessLastPasswordByte3(ThreadData* pThreadData, DWORD dwKey0, DWORD dwKey1, DWORD dwKey2)
{
	BYTE* pbNextPasswordByte = g_rgbValidPasswordCharacters;

	do
	{
		register DWORD dwKey0_1 = dwKey0;
		register DWORD dwKey0_2 = dwKey0;
		register DWORD dwKey0_3 = dwKey0;

		register DWORD dwKey1_1 = dwKey1;
		register DWORD dwKey1_2 = dwKey1;
		register DWORD dwKey1_3 = dwKey1;

		register DWORD dwKey2_1 = dwKey2;
		register DWORD dwKey2_2 = dwKey2;
		register DWORD dwKey2_3 = dwKey2;

		BYTE* pbNextDataByte = g_pbAlignedEncryptedData;
		BYTE c1;

		// Add 1 character to the current password state
		BYTE* pbFirstPasswordByte = pbNextPasswordByte;
        dwKey0_1 = (g_rgdwCRC32Table[(BYTE)(dwKey0_1 ^ *pbNextPasswordByte++)] ^ (dwKey0_1 >> 8));
        dwKey0_2 = (g_rgdwCRC32Table[(BYTE)(dwKey0_2 ^ *pbNextPasswordByte++)] ^ (dwKey0_2 >> 8));
        dwKey0_3 = (g_rgdwCRC32Table[(BYTE)(dwKey0_3 ^ *pbNextPasswordByte++)] ^ (dwKey0_3 >> 8));

		dwKey1_1 = dwKey1_1 + (byte)dwKey0_1;
        dwKey1_2 = dwKey1_2 + (byte)dwKey0_2;
        dwKey1_3 = dwKey1_3 + (byte)dwKey0_3;

		dwKey1_1 = dwKey1_1 * 0x08088405 + 1;
        dwKey1_2 = dwKey1_2 * 0x08088405 + 1;
        dwKey1_3 = dwKey1_3 * 0x08088405 + 1;

        dwKey2_1 = (g_rgdwCRC32Table[(BYTE)(dwKey2_1 ^ ((byte)(dwKey1_1 >> 24)))] ^ (dwKey2_1 >> 8));
        dwKey2_2 = (g_rgdwCRC32Table[(BYTE)(dwKey2_2 ^ ((byte)(dwKey1_2 >> 24)))] ^ (dwKey2_2 >> 8));
        dwKey2_3 = (g_rgdwCRC32Table[(BYTE)(dwKey2_3 ^ ((byte)(dwKey1_3 >> 24)))] ^ (dwKey2_3 >> 8));

		// Process the header bytes
		pbNextDataByte = g_pbAlignedEncryptedData;
	    for (int i = 0; i < ENCRYPTION_HEADER_LENGTH - 1; i++)
	    {
			c1 = *pbNextDataByte ^ g_rgbDecryptByteTable[(WORD)dwKey2_1];
	        dwKey0_1 = (g_rgdwCRC32Table[(BYTE)(dwKey0_1 ^ c1)] ^ (dwKey0_1 >> 8));
	        dwKey1_1 = dwKey1_1 + (byte)dwKey0_1;
	        dwKey1_1 = dwKey1_1 * 0x08088405 + 1;
	        dwKey2_1 = (g_rgdwCRC32Table[((BYTE)dwKey2_1 ^ ((BYTE)(dwKey1_1 >> 24)))] ^ (dwKey2_1 >> 8));

			c1 = *pbNextDataByte ^ g_rgbDecryptByteTable[(WORD)dwKey2_2];
	        dwKey0_2 = (g_rgdwCRC32Table[(BYTE)(dwKey0_2 ^ c1)] ^ (dwKey0_2 >> 8));
	        dwKey1_2 = dwKey1_2 + (byte)dwKey0_2;
	        dwKey1_2 = dwKey1_2 * 0x08088405 + 1;
	        dwKey2_2 = (g_rgdwCRC32Table[((BYTE)dwKey2_2 ^ ((BYTE)(dwKey1_2 >> 24)))] ^ (dwKey2_2 >> 8));

			c1 = *pbNextDataByte ^ g_rgbDecryptByteTable[(WORD)dwKey2_3];
	        dwKey0_3 = (g_rgdwCRC32Table[(BYTE)(dwKey0_3 ^ c1)] ^ (dwKey0_3 >> 8));
	        dwKey1_3 = dwKey1_3 + (byte)dwKey0_3;
	        dwKey1_3 = dwKey1_3 * 0x08088405 + 1;
	        dwKey2_3 = (g_rgdwCRC32Table[((BYTE)dwKey2_3 ^ ((BYTE)(dwKey1_3 >> 24)))] ^ (dwKey2_3 >> 8));

			pbNextDataByte++;
	    }

	    // Test to see if the check byte is correct - if not, abort
		c1 = *pbNextDataByte ^ g_rgbDecryptByteTable[(WORD)dwKey2_1];
	    if ((g_bPasswordVerificationValue == c1) || (c1 == ((g_pFileRecord->wFileTime >> 8) & 0xff))) // For some reason, sometimes it's the file time?
	    {
	        dwKey0_1 = (g_rgdwCRC32Table[(BYTE)(dwKey0_1 ^ c1)] ^ (dwKey0_1 >> 8));
	        dwKey1_1 = dwKey1_1 + (byte)dwKey0_1;
	        dwKey1_1 = dwKey1_1 * 0x08088405 + 1;
	        dwKey2_1 = (g_rgdwCRC32Table[((BYTE)dwKey2_1 ^ ((BYTE)(dwKey1_1 >> 24)))] ^ (dwKey2_1 >> 8));

			DWORD dwCalculatedCRC = FullEvalCRC(pThreadData, dwKey0_1, dwKey1_1, dwKey2_1, g_pFileRecord->dwCompressedSize - ENCRYPTION_HEADER_LENGTH, pbNextDataByte + 1);
		    if (g_pFileRecord->dwCrc == dwCalculatedCRC)
		    {
				g_fFound = TRUE;
		        return (BYTE)*pbFirstPasswordByte;
		    }
	    }

		c1 = *pbNextDataByte ^ g_rgbDecryptByteTable[(WORD)dwKey2_2];
	    if ((g_bPasswordVerificationValue == c1) || (c1 == ((g_pFileRecord->wFileTime >> 8) & 0xff))) // For some reason, sometimes it's the file time?
	    {
	        dwKey0_2 = (g_rgdwCRC32Table[(BYTE)(dwKey0_2 ^ c1)] ^ (dwKey0_2 >> 8));
	        dwKey1_2 = dwKey1_2 + (byte)dwKey0_2;
	        dwKey1_2 = dwKey1_2 * 0x08088405 + 1;
	        dwKey2_2 = (g_rgdwCRC32Table[((BYTE)dwKey2_2 ^ ((BYTE)(dwKey1_2 >> 24)))] ^ (dwKey2_2 >> 8));

			DWORD dwCalculatedCRC = FullEvalCRC(pThreadData, dwKey0_2, dwKey1_2, dwKey2_2, g_pFileRecord->dwCompressedSize - ENCRYPTION_HEADER_LENGTH, pbNextDataByte + 1);
		    if (g_pFileRecord->dwCrc == dwCalculatedCRC)
		    {
				g_fFound = TRUE;
		        return (BYTE)*(pbFirstPasswordByte + 1);
		    }
		}

		c1 = *pbNextDataByte ^ g_rgbDecryptByteTable[(WORD)dwKey2_3];
	    if ((g_bPasswordVerificationValue == c1) || (c1 == ((g_pFileRecord->wFileTime >> 8) & 0xff))) // For some reason, sometimes it's the file time?
	    {
	        dwKey0_3 = (g_rgdwCRC32Table[(BYTE)(dwKey0_3 ^ c1)] ^ (dwKey0_3 >> 8));
	        dwKey1_3 = dwKey1_3 + (byte)dwKey0_3;
	        dwKey1_3 = dwKey1_3 * 0x08088405 + 1;
	        dwKey2_3 = (g_rgdwCRC32Table[((BYTE)dwKey2_3 ^ ((BYTE)(dwKey1_3 >> 24)))] ^ (dwKey2_3 >> 8));

			DWORD dwCalculatedCRC = FullEvalCRC(pThreadData, dwKey0_3, dwKey1_3, dwKey2_3, g_pFileRecord->dwCompressedSize - ENCRYPTION_HEADER_LENGTH, pbNextDataByte + 1);
		    if (g_pFileRecord->dwCrc == dwCalculatedCRC)
		    {
				g_fFound = TRUE;
		        return (BYTE)*(pbFirstPasswordByte + 2);
		    }
		}
	}
	while ('\0' != *pbNextPasswordByte);

	return 0;
}


// Keeps track of the current encryption keys and byte added while traversing the password tree
// On success, uses bAddedByte to reconstruct the successful password
struct PasswordState
{
	DWORD dwKey0;
	DWORD dwKey1;
	DWORD dwKey2;
	BYTE bAddedByte;
};


BOOL ProcessPasswords1(ThreadData* pThreadData, LPCSTR szStartPassword, QWORD qwMaxPasswords)
{
	size_t nPasswordLength;
	PasswordState passwordStates[MAX_PASSWORD_LENGTH + 1];
	PasswordState* pCurrentPasswordState;
	PasswordState* pNextPasswordState;
	size_t nCurrentLength;

	// Create the first password (0 length password)
	passwordStates[0].bAddedByte = 0;
	passwordStates[0].dwKey0 = 0x12345678;
	passwordStates[0].dwKey1 = 0x23456789;
	passwordStates[0].dwKey2 = 0x34567890;

	if ( NULL == szStartPassword )
	{
		// Start with password length = 1
		nPasswordLength = 1;
		pCurrentPasswordState = passwordStates;
		nCurrentLength = 0;
	}
	else
	{
		// If we've been given a starting password, set the password state to reflect it
		nPasswordLength = strlen(szStartPassword);

		pCurrentPasswordState = passwordStates;
		for (size_t nCharIndex = 1; nCharIndex < nPasswordLength; nCharIndex++ )
		{
			pNextPasswordState = pCurrentPasswordState + 1;

			pNextPasswordState->bAddedByte = szStartPassword[nCharIndex - 1];
		    pNextPasswordState->dwKey0 = (g_rgdwCRC32Table[(BYTE)(pCurrentPasswordState->dwKey0 ^ pNextPasswordState->bAddedByte)] ^ (pCurrentPasswordState->dwKey0 >> 8));
			pNextPasswordState->dwKey1 = pCurrentPasswordState->dwKey1 + (BYTE)pNextPasswordState->dwKey0;
			pNextPasswordState->dwKey1 = pNextPasswordState->dwKey1 * 0x08088405 + 1;
		    pNextPasswordState->dwKey2 = (g_rgdwCRC32Table[(BYTE)(pCurrentPasswordState->dwKey2 ^ ((BYTE)(pNextPasswordState->dwKey1 >> 24)))] ^ (pCurrentPasswordState->dwKey2 >> 8));

			pCurrentPasswordState++;
		}

		// Set the current length - this will make it try all last password characters instead of exactly starting at the given one, but that's OK
		nCurrentLength = nPasswordLength - 1;
		pCurrentPasswordState = &(passwordStates[nCurrentLength]);
	}

	while ( qwMaxPasswords-- > 0 )
	{
		// Add a character to the password until the password is the required length (minus 1, because the final bit is handled by the called function)
		while ( nCurrentLength < nPasswordLength - 1 )
		{
			pNextPasswordState = pCurrentPasswordState + 1;

			// Add this byte to the password state
			pNextPasswordState->bAddedByte = g_rgbValidPasswordCharacters[0];
		    pNextPasswordState->dwKey0 = (g_rgdwCRC32Table[(BYTE)(pCurrentPasswordState->dwKey0 ^ pNextPasswordState->bAddedByte)] ^ (pCurrentPasswordState->dwKey0 >> 8));
			pNextPasswordState->dwKey1 = pCurrentPasswordState->dwKey1 + (BYTE)pNextPasswordState->dwKey0;
			pNextPasswordState->dwKey1 = pNextPasswordState->dwKey1 * 0x08088405 + 1;
		    pNextPasswordState->dwKey2 = (g_rgdwCRC32Table[(BYTE)(pCurrentPasswordState->dwKey2 ^ ((BYTE)(pNextPasswordState->dwKey1 >> 24)))] ^ (pCurrentPasswordState->dwKey2 >> 8));

			nCurrentLength++;
			pCurrentPasswordState = pNextPasswordState;
		}

		// Process all the the passwords last bytes
		if ( BYTE bLastByte = ProcessLastPasswordByte(pThreadData, pCurrentPasswordState->dwKey0, pCurrentPasswordState->dwKey1, pCurrentPasswordState->dwKey2) )
		{
			// We found a matching password!
			printf( "Password found: " );
			for ( size_t nCharIndex = 1; nCharIndex < nPasswordLength; nCharIndex++ )
			{
				printf( "%c", passwordStates[nCharIndex].bAddedByte );
			}
			printf( "%c\n", bLastByte );

			return TRUE;
		}

		pThreadData->qwPasswordsProcessed += g_nValidPasswordCharacterCount;

		// Move to next password, tracking back a character if we've tried the last valid character
		while ( (nCurrentLength > 0) && (0 == (pCurrentPasswordState->bAddedByte = g_rgbPasswordTraversalTable[pCurrentPasswordState->bAddedByte]) ) )
		{
			pNextPasswordState = pCurrentPasswordState;
			pCurrentPasswordState--;
			nCurrentLength--;
		}

		// If we haven't finished all the passwords at the current length, advance the character at the current position (not necessarily the last position if we've backtracked a char)
		if ( nCurrentLength > 0 )
		{
			pNextPasswordState = pCurrentPasswordState;
			pCurrentPasswordState--;

			// Update the state at this length
		    pNextPasswordState->dwKey0 = (g_rgdwCRC32Table[(BYTE)(pCurrentPasswordState->dwKey0 ^ pNextPasswordState->bAddedByte)] ^ (pCurrentPasswordState->dwKey0 >> 8));
			pNextPasswordState->dwKey1 = pCurrentPasswordState->dwKey1 + (BYTE)pNextPasswordState->dwKey0;
			pNextPasswordState->dwKey1 = pNextPasswordState->dwKey1 * 0x08088405 + 1;
		    pNextPasswordState->dwKey2 = (g_rgdwCRC32Table[(BYTE)(pCurrentPasswordState->dwKey2 ^ ((BYTE)(pNextPasswordState->dwKey1 >> 24)))] ^ (pCurrentPasswordState->dwKey2 >> 8));

			pCurrentPasswordState = pNextPasswordState;
		}
		else
		{
			// If we're all the way back at the beginning, increase password length and continue
			nPasswordLength++;
		}
	}

	return FALSE;
}


// Holds the next password to give out
BYTE g_rgbNextPassword[MAX_PASSWORD_LENGTH + 1];

// This function does the work of creating the next chunk of passwords to give to a thread
VOID GetNextPassword(BYTE* pbPassword, QWORD* pqwPasswordCount)
{
	EnterCriticalSection( &g_passwordCritSec );

	// Update pbPassword with the next password
	CopyMemory( pbPassword, g_rgbNextPassword, MAX_PASSWORD_LENGTH );

	// Right-justify the password
	BYTE rgbRealignedPasswords[MAX_PASSWORD_LENGTH + 1];
	ZeroMemory( rgbRealignedPasswords, MAX_PASSWORD_LENGTH + 1 );
	DWORD dwPreviousPasswordLength = (DWORD) strlen( (LPSTR) g_rgbNextPassword );
	memcpy( rgbRealignedPasswords + (MAX_PASSWORD_LENGTH - dwPreviousPasswordLength), g_rgbNextPassword, dwPreviousPasswordLength );

	// Add g_qwPasswordsPerGroup to the last password count
	BYTE bCarry = 0;
	QWORD qwPasswordsToIncrease = g_qwPasswordsPerGroup - 1;
	BYTE rgbPasswordsProcessed[MAX_PASSWORD_LENGTH + 1];
	ZeroMemory( rgbPasswordsProcessed, MAX_PASSWORD_LENGTH + 1 );
	INT nBytePosition = MAX_PASSWORD_LENGTH - 1;

	// Start at the least significant value, and do simple addition
	while ( ((bCarry) || (qwPasswordsToIncrease > 0)) && (nBytePosition > 0) )
	{
		WORD wNewValue;
		if ( 0 != rgbRealignedPasswords[nBytePosition] )
		{
			wNewValue = (g_rgbPasswordOffsets[rgbRealignedPasswords[nBytePosition]] + 1) + (WORD)(qwPasswordsToIncrease % g_nValidPasswordCharacterCount) + bCarry;
		}
		else
		{
			wNewValue = (WORD)(qwPasswordsToIncrease % g_nValidPasswordCharacterCount) + bCarry;
		}
		wNewValue--;

		rgbRealignedPasswords[nBytePosition] = g_rgbValidPasswordCharacters[wNewValue % g_nValidPasswordCharacterCount];
		bCarry = (BYTE)(wNewValue / g_nValidPasswordCharacterCount);

		qwPasswordsToIncrease /= g_nValidPasswordCharacterCount;
		nBytePosition--;
	}

	// Make sure that the last g_dwPasswordsPerGroupPower bytes are the first character
	for ( DWORD dwIndex = 1; dwIndex <= g_dwPasswordsPerGroupPower; dwIndex++ )
	{
		rgbRealignedPasswords[MAX_PASSWORD_LENGTH - dwIndex] = g_rgbValidPasswordCharacters[0];
	}

	// Move it back to be left-justified
	BYTE* pbFirstValue = rgbRealignedPasswords;
	while ( '\0' == *pbFirstValue )
	{
		pbFirstValue++;
	}
	strcpy_s( (LPSTR)g_rgbNextPassword, MAX_PASSWORD_LENGTH, (LPSTR)pbFirstValue );

	LeaveCriticalSection( &g_passwordCritSec );

	// Set the password count - It's actually passwords / count(valid_chars)
	*pqwPasswordCount = g_qwPasswordsPerGroup;
}


// Thread main
DWORD WINAPI BruteForceZipThreadProc(__in  LPVOID lpParameter)
{
	ThreadData* pThreadData = (ThreadData*) lpParameter;
	BYTE rgbNextPassword[MAX_PASSWORD_LENGTH + 1];
	QWORD qwPasswordCount = 0;

	FillMemory( rgbNextPassword, MAX_PASSWORD_LENGTH + 1, g_rgbValidPasswordCharacters[0] );

	while ( g_fKeepProcessing )
	{
		// Get a password
		GetNextPassword( rgbNextPassword, &qwPasswordCount );

		// Process
		if ( ProcessPasswords(pThreadData, (LPCSTR)rgbNextPassword, qwPasswordCount / g_nValidPasswordCharacterCount) )
		{
			g_fKeepProcessing = FALSE;
			break;
		}
	}

	return 0;
}


// Returns the number of CPUs on the machine, which is used as the default thread count
int GetCpuCount()
{
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);

	return sysinfo.dwNumberOfProcessors;
}


// Prints the usage info for the program
void PrintHelp()
{
	_tprintf(
		_T("CZipBruteForce - Fast zip password cracker\n")
		_T("Usage: CZipBruteForce <zip filename> [-threads <num>] [-password <password>]\n")
		_T("\n")
		_T("Required args:\n")
		_T("  <zip filename> - The name of a password-protected zip file\n")
		_T("Optional args:\n")
		_T("  -threads <num> - number of threads to use.  Default = CPU count\n")
		_T("  -password <password> - initial password.  Default = '0'\n")
		);
}


CHAR FIRST_PASSWORD[] = "0";
int __cdecl _tmain(int argc, _TCHAR* argv[])
{
	int nThreadCount = GetCpuCount();
	LPSTR szFirstPassword = FIRST_PASSWORD;
	LPTSTR tszZipFilename = NULL;

	// Set the first password
	ZeroMemory( g_rgbNextPassword, MAX_PASSWORD_LENGTH + 1 );
	g_rgbNextPassword[0] = g_rgbValidPasswordCharacters[0];

	// Command line argument parsing
	if ( 0 == argc )
	{
		return -1;
	}

	int nCurrentArgument = 1;
	while ( nCurrentArgument < argc )
	{
		if ( 0 == _tcscmp( argv[nCurrentArgument], _T("-threads") ) )
		{
			if ( nCurrentArgument < argc - 1 )
			{
				nCurrentArgument++;

				nThreadCount = _ttoi(argv[nCurrentArgument]);
			}
		}
		else if ( 0 == _tcscmp( argv[nCurrentArgument], _T("-password") ) )
		{
			if ( nCurrentArgument < argc - 1 )
			{
				nCurrentArgument++;

				size_t nCharsConverted;
				wcstombs_s( &nCharsConverted, (LPSTR)g_rgbNextPassword, MAX_PASSWORD_LENGTH, argv[nCurrentArgument], MAX_PASSWORD_LENGTH );
			}
		}
		else
		{
			if ( (nCurrentArgument < argc) && (NULL == tszZipFilename) )
			{
				tszZipFilename = argv[nCurrentArgument];
			}
			else
			{
				_tprintf( _T("Unknown command line argument: %s\n"), argv[nCurrentArgument] );
				PrintHelp();
				return -1;
			}
		}

		nCurrentArgument++;
	}

	// Do a little basic validation of command line options
	if ( 0 >= nThreadCount )
	{
		printf( "Bad thread count: %d\n", nThreadCount );
		PrintHelp();
		return -1;
	}

	if ( NULL == tszZipFilename )
	{
		printf( "Missing zip filename\n" );
		PrintHelp();
		return -1;
	}

	// Build out the CRC table - this could be statically defined
	BuildCRCTable();

	// Build the table that pre-calcs some of the decrypt math - this could be statically defined
	BuildDecryptByteTable();

	// Build the table that allows traversal of passwords
	GenerateValidCharsTable( g_rgbValidPasswordCharacters, ARRAYSIZE(g_rgbValidPasswordCharacters), g_rgbValidPasswordCharacters[0] );

	// Read in the file
	HANDLE hZipFile = CreateFile( tszZipFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
	if ( INVALID_HANDLE_VALUE == hZipFile )
	{
		return -1;
	}

	DWORD dwFileLength = GetFileSize( hZipFile, NULL );

	SAFE_MEM_RET(g_pbFileBuffer = new BYTE[dwFileLength]);
	SAFE_MEM_RET(g_pbAlignedEncryptedData = (BYTE*)_aligned_malloc(dwFileLength, 16) );
	DWORD dwBytesRead;
	ReadFile( hZipFile, g_pbFileBuffer, dwFileLength, &dwBytesRead, NULL );

	// Get the first zip record and get an aligned copy of the encrypted data
	g_pFileRecord = (ZipFileRecord*) g_pbFileBuffer;
	BYTE* pbFileData = ((BYTE*) g_pFileRecord) + sizeof(ZipFileRecord) + g_pFileRecord->wFileNameLength + g_pFileRecord->wExtraFieldLength;
	memcpy( g_pbAlignedEncryptedData, pbFileData, g_pFileRecord->dwCompressedSize );

	g_bPasswordVerificationValue = ((g_pFileRecord->dwCrc & 0xff000000) >> 24);

	// Calculate the number of valid password characters
	g_nValidPasswordCharacterCount = strlen((const char*)g_rgbValidPasswordCharacters);

	InitializeCriticalSection( &g_passwordCritSec );

	// Figure out what power of g_nValidPasswordCharacterCount is about 100M
	g_dwPasswordsPerGroupPower = (DWORD) floor(log((double)100000000) / log((double)g_nValidPasswordCharacterCount));
	g_qwPasswordsPerGroup = (QWORD) pow((double)g_nValidPasswordCharacterCount, (double)g_dwPasswordsPerGroupPower) + 1;

	// Create threads for processing
	ThreadData* pThreadData = new ThreadData[nThreadCount];
	HANDLE* phThreads = new HANDLE[nThreadCount];
	HANDLE* phDoneExecuting = new HANDLE[nThreadCount];
	for ( int nThreadIndex = 0; nThreadIndex < nThreadCount; nThreadIndex++ )
	{
		ZeroMemory( &(pThreadData[nThreadIndex].decompressionStream), sizeof(z_stream) );
		pThreadData[nThreadIndex].pbOutputBuffer = new BYTE[g_pFileRecord->dwUncompressedSize];
	    pThreadData[nThreadIndex].decompressionStream.zalloc = (alloc_func)0;
	    pThreadData[nThreadIndex].decompressionStream.zfree = (free_func)0;
		pThreadData[nThreadIndex].qwPasswordsProcessed = 0;
		pThreadData[nThreadIndex].decompressionStream.opaque = (voidpf)0;
	    inflateInit2(&(pThreadData[nThreadIndex].decompressionStream), -15);

		phThreads[nThreadIndex] = CreateThread( NULL, 0, BruteForceZipThreadProc, &(pThreadData[nThreadIndex]), 0, NULL );
		phDoneExecuting[nThreadIndex] = phThreads[nThreadIndex];
		SetThreadPriority(phThreads[nThreadIndex], THREAD_PRIORITY_IDLE);
	}

	DWORD dwBefore = GetTickCount();

	// Wait until keypress or password is found
	QWORD qwPasswordsProcessed;
	do
	{
		// Every 5 seconds, print out the approximate average passwords per second
		Sleep( 5000 );

		qwPasswordsProcessed = 0;
		for ( int nThreadIndex = 0; nThreadIndex < nThreadCount; nThreadIndex++ )
		{
			qwPasswordsProcessed += pThreadData[nThreadIndex].qwPasswordsProcessed;
		}

		DWORD dwAfter = GetTickCount();
		printf( "Passwords per second: %I64d - %s\n", qwPasswordsProcessed / ((dwAfter - dwBefore) / 1000), g_rgbNextPassword);
	}
	while ( !_kbhit() && g_fKeepProcessing );

	g_fKeepProcessing = FALSE;
	printf( "Shutting down... This may take a while... \n" );

	// Wait for all the threads to exit
	WaitForMultipleObjects(nThreadCount, phDoneExecuting, TRUE, INFINITE);

	// TODO: Get the latest password executed (not the next one to process), unless we found a solution
	printf( "%s\n", g_rgbNextPassword );

	return 0;
}

