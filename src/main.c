/*
* Copyright (c) 2012 by naehrwert
* This file is released under the GPLv2.
*/
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>

#include "util.h"
#include "kgen.h"
#include "aes_xts.h"
#include "keys.h"
#include <time.h>

#ifdef _WIN32
#include <io.h>
#include "getopt.h"
#else
#include <unistd.h>
#include <getopt.h>
#endif


/*! Size of one sector. */
#define SECTOR_SIZE 0x200
#define BUFFER_SIZE 0x100000

/*! Encrypt data. */
static BOOL do_encrypt = FALSE;
/*! eflash or vflash sector. */
static BOOL is_vflash = FALSE;
/*! Phat console type. */
static BOOL is_phat = FALSE;
/*! Arcade console type. */
static BOOL is_arcade = FALSE;

/*! Parameters. */
s8 *_start_sector = "0";
s8 *_num_sectors = NULL;

/*! Input eid root key file. */
static s8 *_eid_root_key_file = NULL;
/*! Input data file. */
static s8 *_file_in = NULL;
/*! Output data file. */
static s8 *_file_out = NULL;

/*! Shorter Versions of arg options. */
#define ARG_NULL no_argument
#define ARG_NONE no_argument
#define ARG_REQ required_argument
#define ARG_OPT optional_argument

static struct option options[] = 
{
	{"help", ARG_NONE, NULL, 'h'},
	{"encrypt", ARG_NONE, NULL, 'e'},
	{"vflash", ARG_NONE, NULL, 'v'},
	{"phat", ARG_NONE, NULL, 'p'},
	{"arcade", ARG_NONE, NULL, 'a'},
	{"start-sector", ARG_REQ, NULL, 's'},
	{"num-sectors", ARG_REQ, NULL, 'n'},
	{NULL, ARG_NULL, NULL, 0}
};


void print_help(char **argv)
{
	printf("PlayStation 3 ENCDEC emulator  0.1.0 \n");
	printf("usage: %s [-h] [-e] [-v] [-p] [-a] [-s START_SECTOR] [-n NUM_SECTORS]\n", argv[0] );
	printf("                     [eid_root_key_file] [sector_file] <out_file>\n\n");
	printf("positional arguments:\n");
	printf("  eid_root_key_file\n");
	printf("  sector_file\n");
	printf("  out_file\n\n");
	printf("optional arguments:\n");
	printf("  -h, --help            show this help message and exit\n");
	printf("  -e, --encrypt         encrypt data instead of decrypt\n");
	printf("  -v, --vflash          vflash/eflash region\n");
	printf("  -p, --phat            phat console\n");
	printf("  -a, --arcade          arcade console\n");
	printf("  -s START_SECTOR, --start-sector START_SECTOR\n");
	printf("                        sector start index, used for crypto only\n");
	printf("  -n NUM_SECTORS, --num-sectors NUM_SECTORS\n");
	printf("                        sector count\n");

	exit(1);
}

static void parse_args(int argc, char **argv)
{
	char c;

	while((c = getopt_long(argc, argv, "h?evpas:n:", options, NULL)) != -1)
	{
		switch(c)
		{
		case 'h':
			print_help(argv);
			break;
		case 'e':
			do_encrypt = TRUE;
			break;
		case 'v':
			is_vflash = TRUE;
			break;
		case 'p':
			is_phat = TRUE;
			break;
		case 'a':
			is_arcade = TRUE;
			break;
		case 's':
			_start_sector = optarg;
			break;
		case 'n':
			_num_sectors = optarg;
			break;
		case '?':
			print_help(argv);
			break;
		}
	}

	// Get positional arguments.
	if(argc - optind < 2)
		{
			printf("[*] Error: incorrect arguments!\n");
			print_help(argv);
		}
		_eid_root_key_file = argv[optind];
		_file_in = argv[optind + 1];

	if(argc - optind == 3)
		_file_out = argv[optind + 2];
	else
		_file_out = "out.bin";
}

/*! Swap u16 endianness. */
static void _es16_buffer(u8 *buf, u32 length)
{
	u16 *ptr = (u16 *)buf;
	u32 i;

	for(i = 0; i < length/2; i++)
		ptr[i] = _ES16(ptr[i]);
}

/*! Decrypt sectors. */
void decrypt_all_sectors(const s8 *out_file, const s8 *in_file, u64 start_sector, u64 num_sectors, u8 *ata_k1, u8 *ata_k2, u8 *edec_k1, u8 *edec_k2, BOOL is_phat, BOOL is_vflash)
{
	FILE *in;
	FILE *out;
	aes_xts_ctxt_t xts_ctxt;
	aes_context aes_ctxt;
	u64 i;
	u64 chunk_size;
	u64 position = 0;
	u64 sectors_to_read = num_sectors;
	u8 *zero_iv = (u8 *)malloc(sizeof(u8) * 0x10);
	u8 *buffer = (u8 *)malloc(sizeof(u8) * BUFFER_SIZE);
	
	
	while (sectors_to_read > 0)
	{
		//Read file to buffer.
		in = fopen(in_file, "rb");

		_fseeki64(in, position, SEEK_SET);
		if (sectors_to_read >= (BUFFER_SIZE / SECTOR_SIZE))
			chunk_size = BUFFER_SIZE;
		else 
			chunk_size = (sectors_to_read * SECTOR_SIZE);

		fread(buffer, (size_t)chunk_size, 1, in);
		fclose(in);
		
		//Decrypt buffer.
		for(i = 0; i < (chunk_size / SECTOR_SIZE); i++)
		{
			//Decrypt sector.
			if (is_vflash == TRUE)
			{
				if (is_phat == TRUE)
				{
					//Set key for AES-CBC
					aes_setkey_dec(&aes_ctxt, edec_k1, 128);
					//Decrypt CBC sector.
					memset(zero_iv, 0, 0x10);
					aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, SECTOR_SIZE, zero_iv, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
					//XOR initial block in sector with sector index value.
					buffer[(SECTOR_SIZE * i)+0x8] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 56 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0x9] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 48 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xA] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 40 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xB] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 32 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xC] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 24 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xD] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 16 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xE] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 8 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xF] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) & 0xFF);
				}
				else
				{
					//Init AES-XTS context.
					aes_xts_init(&xts_ctxt, AES_DECRYPT, edec_k1, edec_k2, 128);
					//Decrypt XTS sector.
					aes_xts_crypt(&xts_ctxt, (u64)((position / SECTOR_SIZE) + i + start_sector), SECTOR_SIZE, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
				}
			}
			else
			{
				if (is_phat == TRUE)
				{
					//Swap endian for ata only.				
					_es16_buffer(buffer + (SECTOR_SIZE * i), SECTOR_SIZE);
					//Set key for AES-CBC
					aes_setkey_dec(&aes_ctxt, ata_k1, 192);
					//Decrypt CBC sector.
					memset(zero_iv, 0, 0x10);
					aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, SECTOR_SIZE, zero_iv, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
				}
				else
				{
					//Swap endian for ata only.
					_es16_buffer(buffer + (SECTOR_SIZE * i), SECTOR_SIZE);
					//Init AES-XTS context.
					aes_xts_init(&xts_ctxt, AES_DECRYPT, ata_k1, ata_k2, 128);
					//Decrypt XTS sector.
					aes_xts_crypt(&xts_ctxt, (u64)((position / SECTOR_SIZE) + i + start_sector), SECTOR_SIZE, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
				}
			}
		}

		//Write buffer to file
		out = fopen(out_file, "r+b");
		_fseeki64(out, position, SEEK_SET);
		fwrite(buffer, (size_t)chunk_size, 1, out);
		fclose(out);

		//Updating vars.
		position += chunk_size;
		sectors_to_read -= (u64)(chunk_size / SECTOR_SIZE);
	}
}

/*! Encrypt sectors. */
void encrypt_all_sectors(const s8 *out_file, const s8 *in_file, u64 start_sector, u64 num_sectors, u8 *ata_k1, u8 *ata_k2, u8 *edec_k1, u8 *edec_k2, BOOL is_phat, BOOL is_vflash)
{
	FILE *in;
	FILE *out;
	aes_xts_ctxt_t xts_ctxt;
	aes_context aes_ctxt;
	u64 i;
	u64 chunk_size;
	u64 position = 0;
	u64 sectors_to_read = num_sectors;
	u8 *zero_iv = (u8 *)malloc(sizeof(u8) * 0x10);
	u8 *buffer = (u8 *)malloc(sizeof(u8) * BUFFER_SIZE);
	
	
	while (sectors_to_read > 0)
	{
		//Read file to buffer.
		in = fopen(in_file, "rb");
		_fseeki64(in, position, SEEK_SET);

		if (sectors_to_read >= (BUFFER_SIZE / SECTOR_SIZE))
			chunk_size = BUFFER_SIZE;
		else 
			chunk_size = (sectors_to_read * SECTOR_SIZE);

		fread(buffer, (size_t)chunk_size, 1, in);
		fclose(in);
		
		//Encrypt buffer.
		for(i = 0; i < (chunk_size / SECTOR_SIZE); i++)
		{
			//Encrypt sector.
			if (is_vflash == TRUE)
			{
				if (is_phat == TRUE)
				{
					//XOR initial block in sector with sector index value.
					buffer[(SECTOR_SIZE * i)+0x8] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 56 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0x9] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 48 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xA] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 40 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xB] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 32 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xC] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 24 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xD] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 16 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xE] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 8 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xF] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) & 0xFF);
					//Set key for AES-CBC
					aes_setkey_enc(&aes_ctxt, edec_k1, 128);
					//Encrypt CBC sector.
					memset(zero_iv, 0, 0x10);
					aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, SECTOR_SIZE, zero_iv, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
				}
				else
				{
					//Init AES-XTS context.
					aes_xts_init(&xts_ctxt, AES_ENCRYPT, edec_k1, edec_k2, 128);
					//Encrypt XTS sector.
					aes_xts_crypt(&xts_ctxt, (u64)((position / SECTOR_SIZE) + i + start_sector), SECTOR_SIZE, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
				}
			}
			else
			{
				if (is_phat == TRUE)
				{
					//Set key for AES-CBC
					aes_setkey_enc(&aes_ctxt, ata_k1, 192);
					//Encrypt CBC sector.
					memset(zero_iv, 0, 0x10);
					aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, SECTOR_SIZE, zero_iv, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
					//Swap endian for ata only.				
					_es16_buffer(buffer + (SECTOR_SIZE * i), SECTOR_SIZE);
				}
				else
				{
					//Init AES-XTS context.
					aes_xts_init(&xts_ctxt, AES_ENCRYPT, ata_k1, ata_k2, 128);
					//Encrypt XTS sector.
					aes_xts_crypt(&xts_ctxt, (u64)((position / SECTOR_SIZE) + i + start_sector), SECTOR_SIZE, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
					//Swap endian for ata only.
					_es16_buffer(buffer + (SECTOR_SIZE * i), SECTOR_SIZE);
				}
			}
		}

		//Write buffer to file
		out = fopen(out_file, "r+b");

		_fseeki64(out, position, SEEK_SET);
		fwrite(buffer, (size_t)chunk_size, 1, out);
		fclose(out);

		//Updating vars.
		position += chunk_size;
		sectors_to_read -= (u64)(chunk_size / SECTOR_SIZE);
	}
}

int main(int argc, char **argv)
{
	time_t t1 = time(NULL);
	
	//Check for args.
	if(argc <= 1)
		print_help(argv);
	
	//Parse them.
	parse_args(argc, argv);
	
	//Check eid_root_key_file.
	FILE* eid_root_key_file = fopen(_eid_root_key_file, "rb");
	if (eid_root_key_file == NULL)
	{
		printf("[*] Error: could not read eid_root_key_file!\n");
		return -1;
	}
	else
	{
		_fseeki64(eid_root_key_file, 0, SEEK_END);
		u64 eid_root_key_file_size = _ftelli64(eid_root_key_file);

		fclose(eid_root_key_file);
		
		if (eid_root_key_file_size != 0x30)
		{
			printf("[*] Error: incorrect eid_root_key_file size!\n");
			return -1;
		}
	}
	
	
	//Setup vars.
	u8 *eid_root_key = _read_buffer(_eid_root_key_file, NULL);
	u8 ata_k1[0x20], ata_k2[0x20], edec_k1[0x20], edec_k2[0x20];
	memset(ata_k1, 0, 0x20);
	memset(ata_k2, 0, 0x20);
	memset(edec_k1, 0, 0x20);
	memset(edec_k2, 0, 0x20);

	//Generate keys.
	if (is_arcade)
	{
		generate_ata_keys(arcade_root_key, arcade_root_iv, ata_arcade_seed, ata_arcade_seed, ata_k1, ata_k2);
		generate_encdec_keys(arcade_root_key, arcade_root_iv, encdec_arcade_data_seed, encdec_arcade_tweak_seed, edec_k1, edec_k2);
	}
	else
	{
		generate_ata_keys(eid_root_key, eid_root_key + 0x20, ata_data_seed, ata_tweak_seed, ata_k1, ata_k2);
		generate_encdec_keys(eid_root_key, eid_root_key + 0x20, encdec_data_seed, encdec_tweak_seed, edec_k1, edec_k2);
	}

	//Print keys.
	_hexdump(stdout, "ATA-DATA-KEY    ", 0, ata_k1, 0x20, 0);
	_hexdump(stdout, "ATA-TWEAK-KEY   ", 0, ata_k2, 0x20, 0);
	_hexdump(stdout, "ENCDEC-DATA-KEY ", 0, edec_k1, 0x20, 0);
	_hexdump(stdout, "ENCDEC-TWEAK-KEY", 0, edec_k2, 0x20, 0);

	FILE* sector_file = fopen(_file_in, "rb");
	if (sector_file == NULL)
	{
		printf("[*] Error: incorrect sector_file!\n");
		return -1;
	}

	// Get sector file size.
	_fseeki64(sector_file, 0, SEEK_END);
	u64 sector_file_size = _ftelli64(sector_file);
	_fseeki64(sector_file, 0, SEEK_SET);
	fclose(sector_file);

	//Check sector file size.
	if (sector_file_size % 0x200 != 0)
	{
		printf("[*] Error: incorrect sector file size!\n");
		return -1;
	}

	u64 start_sector = strtoll(_start_sector, NULL, 0);
	u64 num_sectors;

	//Setup sector count.
	if (_num_sectors == NULL)
		num_sectors = (sector_file_size / 0x200);
	else
		num_sectors = strtoll(_num_sectors, NULL, 0);

	//Check sector count.
	if (num_sectors > (sector_file_size / 0x200) )
	{
		printf("[*] Error: num sectors too big!\n");
		return -1;
	}

	//Check output file and create new one if not existed.
	FILE* out = fopen(_file_out, "rb");
	if (out == NULL)
	{
		FILE* newfile = fopen(_file_out, "wb");
		fclose(newfile);
	}
	else
		fclose(out);

	//Do the task.
	if (do_encrypt == FALSE)
	{
		decrypt_all_sectors(_file_out, _file_in, start_sector, num_sectors, ata_k1, ata_k2, edec_k1, edec_k2, is_phat, is_vflash);
		printf("[*] Sector file successfully decrypted.\n");
	}
	else
	{
		encrypt_all_sectors(_file_out, _file_in, start_sector, num_sectors, ata_k1, ata_k2, edec_k1, edec_k2, is_phat, is_vflash);
		printf("[*] Sector file successfully encrypted.\n");
	}

	time_t t2 = time(NULL);
	double spent = difftime(t2,t1);
	printf("[*] Time spent: %.f seconds\n", spent );
	
	return 0;
}
