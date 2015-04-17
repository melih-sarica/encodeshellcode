/* 
    * Written by Melih SARICA.
	 * Bad char bypass encoder (muts' way) for 32-bit x86. */

#define VERSION "0.1b"

#define MAX_INST_SET 2

#define PUSH_ESP_INST 0x54
#define POP_ESP_INST 0x5C

typedef struct
{
		char REG[4];
		unsigned char INST;
		char INST_T[4];
		unsigned char PUSH_INST;
		char PUSH_T[9];
		unsigned char POP_INST;
		char POP_T[9];
		unsigned char INST_ZERO;
		char INST_ZERO_T[4];
} inst_set_st;

FILE *of; /*Global var for later use.*/

