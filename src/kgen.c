/*
* Copyright (c) 2012 by naehrwert
* This file is released under the GPLv2.
*/

#include "types.h"
#include "aes.h"

void generate_ata_keys(u8 *eid_root_key, u8 *eid_root_iv, u8 *ata_data_seed, u8 *ata_tweak_seed, u8 *data_key_dst, u8 *tweak_key_dst)
{
	aes_context aes_ctxt;
	u8 iv[0x10];

	//Generate ATA data key.
	aes_setkey_enc(&aes_ctxt, eid_root_key, 0x100);
	memcpy(iv, eid_root_iv, 0x10);
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0x20, iv, ata_data_seed, data_key_dst);
	
	//Generate ATA tweak key.
	aes_setkey_enc(&aes_ctxt, eid_root_key, 0x100);
	memcpy(iv, eid_root_iv, 0x10);
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0x20, iv, ata_tweak_seed, tweak_key_dst);
}

void generate_encdec_keys(u8 *eid_root_key, u8 *eid_root_iv, u8 *encdec_data_seed, u8 *encdec_tweak_seed, u8 *data_key_dst, u8 *tweak_key_dst)
{
	aes_context aes_ctxt;
	u8 iv[0x10];

	//Generate encdec_k1.
	aes_setkey_enc(&aes_ctxt, eid_root_key, 0x100);
	memcpy(iv, eid_root_iv, 0x10);
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0x20, iv, encdec_data_seed, data_key_dst);
	
	//Generate encdec_k3.
	aes_setkey_enc(&aes_ctxt, eid_root_key, 0x100);
	memcpy(iv, eid_root_iv, 0x10);
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0x20, iv, encdec_tweak_seed, tweak_key_dst);
}
