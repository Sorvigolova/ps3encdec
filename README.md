# EncDec Device emulator
========================

Tool to decrypt / encrypt PS3 Storage Data

==> Usage <==

ps3encdec.exe [-h] [-e] [-v] [-p] [-a] [-s START_SECTOR] [-n NUM_SECTORS]

                     [eid_root_key_file] [sector_file] <out_file>

positional arguments:

		eid_root_key_file
		
		sector_file
		
		out_file

optional arguments:

		-h, --help           			 show this help message and exit
		
		-e, --encrypt        			 encrypt data instead of decrypt
		
		-v, --vflash         			 vflash/eflash region
		
		-p, --phat           			 phat console

		-a, --arcade         			 arcade console
		
		-s START_SECTOR, --start-sector	 START_SECTOR
		
										 sector start index, used for crypto only
										 
		-n NUM_SECTORS, --num-sectors	 NUM_SECTORS
		
										 sector count


==> Command exaples <==

ps3encdec -p -n 0x200 eid_root_key hdd.bin hdd.dec       // to decrypt 0x200 sectors of PS3 FAT hdd backup

ps3encdec -v -s 8 eid_root_key vflash.bin vflash.dec     // to decrypt the whole vflash backup of PS3-Slim

ps3encdec -p -v -s 0x7800 eid_root_key eflash.bin        // to decrypt the whole eflash to out.bin (FAT PS3)

ps3encdec -e -p -v -s 0x7800 eid_root_key out.bin eflash // to encrypt decrypted eflash to eflash (FAT PS3)

==> Credits <==

Flat_z - The original Author of the Python solution.

ZecoXao - Tests, benchmarks, suggestions. Many Thanks to You.