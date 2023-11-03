#include <iostream>
#include <conio.h>
#include <stdio.h>
#include <stdint.h>
using namespace std;

#pragma once
#include <iostream>
using namespace std;

#define BUFF_SIZE 1024
#define LSHIFT_nBIT(x, L, N) (((x << L) | (x >>  (-L & (N-1)))) & (((uint64_t) 1 << N) -1))
//макрос, обеспечивающий циклический сдвиг влево для числаx(состоит из N битов) на L битов

// 1 | 4 -> 0xC
static const uint8_t Sbox[8][16] = {
	{0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3},
	{0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1},
	{0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2},
	{0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8},
	{0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1},
	{0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6},
	{0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7},
	{0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE},
};

size_t GOST_28147_89(uint8_t* to, uint8_t mode, uint8_t* key256b, uint8_t* from, size_t length);

void split_256bits_to_32bits(uint8_t* key256b, uint32_t* keys32b);
void split_64bits_to_32bits(uint64_t block64b, uint32_t* block32b_1, uint32_t* block32b_2);
void split_32bits_to_8_bits(uint32_t block32b, uint8_t* blocks8b);
void split_64bits_to_8bits(uint64_t block64b, uint8_t* blocks8b);

uint64_t join_8bits_to_64_bits(uint8_t* blocks8b);
uint32_t join_4bits_to_32_bits(uint8_t* blocks4b);
uint64_t join_32bits_to_64bits(uint32_t block32b_1, uint32_t block32b_2);

void feistel_cipher(uint8_t mode, uint32_t* block32b_1, uint32_t* block32b_2, uint32_t* keys32);
void round_of_fiestel_cipher(uint32_t* block32_1, uint32_t* block32_2, uint32_t* keys32b, uint8_t round);

uint32_t substitution_table(uint32_t block32b, uint8_t sbox_row);
void substitution_table_by_4bits(uint8_t* blocks4b, uint8_t sbox_row);


static inline void print_array(uint8_t*, size_t);

int main()
{
	uint8_t encrypted[BUFF_SIZE], decrypted[BUFF_SIZE];
	uint8_t key256b[33]{ "this_is_a_pasw_for_GOST_28147_89" };

	uint8_t buffer[BUFF_SIZE], * ch;
	ch = buffer;
	size_t position = 0;
	while ((*ch++ = getchar()) != '\n') //
		position++;
	buffer[position] = '\0';

	cout << "OPEN MESSAGE:\n";
	print_array(buffer, position);
	for (uint8_t i = 0; i < position; ++i)
	{
		cout << buffer[i];
	}
	cout << endl << endl;

	position = GOST_28147_89(encrypted, 'E', key256b, buffer, position);
	cout << "ENCRYPTED MESSAGE:" << endl;
	print_array(encrypted, position);
	for (uint8_t i = 0; i < position; ++i)
	{
		cout << encrypted[i];
	}
	cout << endl << endl;

	position = GOST_28147_89(decrypted, 'D', key256b, encrypted, position);
	cout << "DECRYPTED MESSAGE:" << endl;
	print_array(decrypted, position);
	for (uint8_t i = 0; i < position; ++i)
	{
		cout << decrypted[i];
	}
	cout << endl;
	return 0;
}

size_t GOST_28147_89(uint8_t* to, uint8_t mode, uint8_t* key256b, uint8_t* from, size_t length)
{
	length = length % 8 == 0 ? length : length + (8 - (length % 8));
	uint32_t N1, N2, keys32b[8];
	split_256bits_to_32bits(key256b, keys32b);

	for (size_t i = 0; i < length; i += 8) //цикл для того, чтобы все сообщение зашифровалось
	{
		split_64bits_to_32bits(
			join_8bits_to_64_bits(from + i),
			&N1, &N2
		);
		feistel_cipher(mode, &N1, &N2, keys32b);
		split_64bits_to_8bits(
			join_32bits_to_64bits(N1, N2),
			(to + i)
		);
	}
	return length;
}

void split_64bits_to_8bits(uint64_t block64b, uint8_t* blocks8b)
{
	for (uint8_t i = 0; i < 8; ++i)
	{
		blocks8b[i] = (uint8_t)(block64b >> (8 * (7 - i)));
	}
}

uint64_t join_32bits_to_64bits(uint32_t block32b_1, uint32_t block32b_2)
{
	uint64_t block64b;
	block64b = ((uint64_t)(block32b_2)) << 32;
	block64b = block64b | block32b_1;
	return block64b;
}

uint64_t join_8bits_to_64_bits(uint8_t* blocks8b)
{
	uint64_t block64b;
	for (uint8_t* p = blocks8b; p < blocks8b + 8; ++p)
	{
		block64b = (block64b << 8) | *p;
	}
	return block64b;
}

void  split_64bits_to_32bits(uint64_t block64b, uint32_t* block32b_1, uint32_t* block32b_2)
{
	//N1 содержит младшие биты, N2 содержит старшие биты
	*block32b_2 = (uint32_t)(block64b);
	*block32b_1 = (uint32_t)(block64b >> 32);
}

void split_256bits_to_32bits(uint8_t* key256b, uint32_t* keys32b)
{
	uint8_t* p8 = key256b;
	for (uint32_t* p32 = keys32b; p32 < keys32b + 8; ++p32) //keys32b + 8 * (sizeof(uint32_t)), чтобы пропустить уже записанный элемент.
	{
		for (uint8_t i = 0; i < 4; ++i)
		{
			//00000000000000000000000000000000 << 8 | 01010101 = 00000000000000000000000001010101
			////////////////////....///////////////////
			*p32 = (*p32 << 8) | *(p8 + i);
		}
		p8 += 4;
	}
}

void feistel_cipher(uint8_t mode, uint32_t* block32b_1, uint32_t* block32b_2, uint32_t* keys32b)
{
	switch (mode)
	{
	case 'E': case 'e':
	{
		//K0,K1,K2,K3,K4,K5,K6,K7,K0,K1,K2,K3,K4,K5,K6,K7,K0,K1,K2,K3,K4,K5,K6,K7
		for (uint8_t round = 0; round < 24; ++round)
		{
			round_of_fiestel_cipher(block32b_1, block32b_2, keys32b, round);
		}

		//K7,K6,K5,K4,K3,K2,K1,K0
		for (uint8_t round = 31; round >= 24; --round)
		{
			round_of_fiestel_cipher(block32b_1, block32b_2, keys32b, round);
		}
		break;
	}
	case 'D': case 'd':
	{
		for (int round = 0; round < 8; ++round)
		{
			//K0,K1,K2,K3,K4,K5,K6,K7
			round_of_fiestel_cipher(block32b_1, block32b_2, keys32b, round);
		}

		for (int round = 31; round >= 8; --round)
		{
			//K7,K6,K5,K4,K3,K2,K1,K0,K7,K6,K5,K4,K3,K2,K1,K0,K7,K6,K5,K4,K3,K2,K1,K0
			round_of_fiestel_cipher(block32b_1, block32b_2, keys32b, round);
		}
		break;
	}
	}
}

void round_of_fiestel_cipher(uint32_t* block32_1, uint32_t* block32_2, uint32_t* keys32b, uint8_t round)
{
	uint32_t result_of_iter, temp;

	result_of_iter = (*block32_1 + keys32b[round % 8]) % UINT32_MAX;

	result_of_iter = substitution_table(result_of_iter, round % 8);

	result_of_iter = (uint32_t)LSHIFT_nBIT(result_of_iter, 11, 32);

	temp = *block32_1;
	*block32_1 = result_of_iter ^ *block32_2;
	*block32_2 = temp;
}

uint32_t substitution_table(uint32_t block32b, uint8_t sbox_row)
{
	uint8_t blocks4bits[4];
	split_32bits_to_8_bits(block32b, blocks4bits);
	substitution_table_by_4bits(blocks4bits, sbox_row);
	return join_4bits_to_32_bits(blocks4bits);
}

void substitution_table_by_4bits(uint8_t* blocks4b, uint8_t sbox_row)
{
	uint8_t block4b_1, block4b_2;
	for (uint8_t i = 0; i < 4; ++i)
	{
		//0x0F = 00001111
		// 11111111 & 0x0F = 00001111
		block4b_1 = Sbox[sbox_row][blocks4b[i] & 0x0F];

		block4b_2 = Sbox[sbox_row][blocks4b[i] >> 4];

		blocks4b[i] = block4b_2;

		blocks4b[i] = (blocks4b[i] << 4) | block4b_1;
	}
}

void split_32bits_to_8_bits(uint32_t block32b, uint8_t* blocks8b)
{
	for (uint8_t i = 0; i < 4; ++i)
	{
		blocks8b[i] = (uint8_t)(block32b >> (24 - (i * 8)));
	}
}

uint32_t join_4bits_to_32_bits(uint8_t* blocks4b)
{
	uint32_t block32b = 0;
	for (uint8_t i = 0; i < 4; ++i)
	{
		block32b = block32b << 8 | blocks4b[i];
	}
	return block32b;
}

static inline void print_array(uint8_t* array, size_t length)
{
	cout << "[ ";
	for (size_t i = 0; i < length; ++i)
	{
		cout << static_cast<int>(array[i]) << ' ';
	}
	cout << "]" << endl;
}

