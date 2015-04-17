/* 
 * Written by Melih SARICA
 * Bad char bypass encoder (muts' way) for 32-bit x86. */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <byteswap.h>
#include <unistd.h>
#include <limits.h>

#include "encodeshellcode.h"

inst_set_st inst_set[MAX_INST_SET];

unsigned char verbose=0;

uint32_t rand_with_av_chars(unsigned char *chs, int chcount)
{
uint32_t t, t2=0;
int i;
unsigned char ch;
	for(i=0;i<4;i++)
	{
		t=rand()%chcount;
		ch=*(chs+t);
		t=(unsigned char)ch;
		if(verbose) printf("%02X ", t);
		t2<<=8;
		t2+=t;
	}
	if(verbose) printf("\n");
return t2;
}

int sc(unsigned char *chs, int chcount, unsigned char ch)
{
int s;
	for(s=0;s<chcount;s++) if(*(chs+s)==ch) return 1;
return 0;
}

int check_non_av_chars(unsigned char *chs, int chcount, uint32_t target)
{
uint32_t t;
int i;
unsigned char ch;
	if(verbose) printf("Checking: %08X\n", target);
	for(i=0;i<4;i++)
	{
		t=target&0x000000FF;
		ch=(unsigned char)t;
		if(!sc(chs, chcount, ch))
		{
			if(verbose) printf("Failed because of '%02X'\n", ch);
			return 1;
		}
		target>>=8;
	}
return 0;
}

void print_inst(unsigned char inst, uint32_t mcode, char *reg, char *inst_t)
{
	if(mcode)
	{
		printf("%02X %08X\t%s %s,%08X\n", inst, __bswap_32(mcode), inst_t, reg, mcode);
		fprintf(of, "%c", inst);
		fwrite((uint32_t *)&mcode, sizeof(mcode), 1, of);
	}
	else
	{
		printf("%02X\t\t%s\n", inst, inst_t);
		fprintf(of, "%c", inst);
	}
}

void encode_inst(unsigned char *chs, int chcount, uint32_t target, int es)
{
uint32_t a, b, c;
	if(verbose) printf("Trying to find next necessary values for %08X...\n", target);
	do
	{
		a=rand_with_av_chars(chs, chcount);
		b=rand_with_av_chars(chs, chcount);
		if(strcmp(inst_set[es].INST_T, "SUB")==0)
		{
			if(verbose) printf("Using SUB instruction...\n");
			c=0-target-a-b;	/*SUB instruction*/
		}
		else if(strcmp(inst_set[es].INST_T, "ADD")==0)
		{
		     if(verbose) printf("Using ADD instruction...\n");
		     c=target-a-b;	/*ADD instruction*/
		}
		else /*Add more instructions later*/
		{
			perror("Invalid instruction set loaded.");
			abort();
		}
	}
	while(check_non_av_chars(chs, chcount, c));
	if(verbose) printf("Found solution:\n");
	/* Encoded instructions */
	print_inst(inst_set[es].INST, a, inst_set[es].REG, inst_set[es].INST_T);
	print_inst(inst_set[es].INST, b, inst_set[es].REG, inst_set[es].INST_T);
	print_inst(inst_set[es].INST, c, inst_set[es].REG, inst_set[es].INST_T);
}

void encode_shellcode(unsigned char *chs, int chcount, uint32_t target, int es, uint32_t z1, uint32_t z2)
{
	/* Pre instructions */
	print_inst(inst_set[es].INST_ZERO, z1, inst_set[es].REG, inst_set[es].INST_ZERO_T);
	print_inst(inst_set[es].INST_ZERO, z2, inst_set[es].REG, inst_set[es].INST_ZERO_T);
	/*Encode instructions*/
	encode_inst(chs, chcount, target, es);
	/* Post instructions */
	print_inst(inst_set[es].PUSH_INST, 0, inst_set[es].REG, inst_set[es].PUSH_T);
}

int encode_file(unsigned char *chs, int chcount, char *ef_name, int encoding_set, char *outputfile, uint32_t offset)
{
FILE *ef;
uint32_t target, z1, z2, final_size;
int r;
uint32_t ef_offset;
	ef=fopen(ef_name, "rb");
	if(ef==NULL)
	{
		perror("encode_file");
		return -1;
	}
	fseek(ef, 0L, SEEK_END);
	final_size=ftell(ef)/4*26+19;
	printf("Final shellcode size will be %d bytes.\n", final_size);
	ef_offset=ftell(ef)-sizeof(target);
	fseek(ef, ef_offset, SEEK_SET);
	print_inst(PUSH_ESP_INST, 0, inst_set[encoding_set].REG, "PUSH ESP");
	print_inst(inst_set[encoding_set].POP_INST, 0, inst_set[encoding_set].REG, inst_set[encoding_set].POP_T);
	
	encode_inst(chs, chcount, offset, encoding_set);
	
	print_inst(inst_set[encoding_set].PUSH_INST, 0, inst_set[encoding_set].REG, inst_set[encoding_set].PUSH_T);
	print_inst(POP_ESP_INST, 0, inst_set[encoding_set].REG, "POP ESP");

	if(verbose) printf("Generating numbers for zeroing registers...\n");
	while(1)
	{
		z1=rand_with_av_chars(chs, chcount);
		z2=rand_with_av_chars(chs, chcount);
		if(strcmp(inst_set[encoding_set].INST_ZERO_T, "AND")==0)
		{
			if(!(z1&z2)) break;
		}
		/*For other possibilities (sub eax,eax; xor ebx,ebx...) add code here...*/
		else
		{
			perror("Invalid instruction set loaded for zeroing registers.\n");
			abort();
		}
	}
	if(verbose) printf("Encoding shell...\n");
	while(ef_offset>=0)
	{
		r=fread(&target, 1, sizeof(target), ef);
		if(!r) break;
		encode_shellcode(chs, chcount, target, encoding_set, z1, z2);
		if(ef_offset>=sizeof(target))
		{
			ef_offset-=sizeof(target);
			fseek(ef, ef_offset, SEEK_SET);
		}
		else if(ef_offset)
		{
			printf("Warning: %u more bytes required for padding.\n", (uint32_t)(sizeof(target)-ef_offset));
			break;
		}
		else break;
	}
	fclose(ef);
return 0;
}

void load_inst(void)
{
	strcpy(inst_set[0].REG, "EAX");
	inst_set[0].INST=0x2D;
	inst_set[0].PUSH_INST=0x50;
	inst_set[0].POP_INST=0x58;
	strcpy(inst_set[0].INST_T, "SUB");
	strcpy(inst_set[0].PUSH_T, "PUSH EAX");
	strcpy(inst_set[0].POP_T, "POP EAX");
	inst_set[0].INST_ZERO=0x25;
	strcpy(inst_set[0].INST_ZERO_T, "AND");

	strcpy(inst_set[1].REG, "EAX");
	inst_set[1].INST=0x05;
	inst_set[1].PUSH_INST=0x50;
	inst_set[1].POP_INST=0x58;
	strcpy(inst_set[1].INST_T, "ADD");
	strcpy(inst_set[1].PUSH_T, "PUSH EAX");
	strcpy(inst_set[1].POP_T, "POP EAX");
	inst_set[1].INST_ZERO=0x25;
	strcpy(inst_set[1].INST_ZERO_T, "AND");

	/*Expand this opcode list with sub eax,eax; xor ebx,ebx and others...*/
}

int set_available(unsigned char *chs, int chcount, int set)
{
	if(!sc(chs, chcount, inst_set[set].INST)) return 0;
	if(!sc(chs, chcount, inst_set[set].PUSH_INST)) return 0;
	if(!sc(chs, chcount, inst_set[set].POP_INST)) return 0;
	if(!sc(chs, chcount, inst_set[set].INST_ZERO)) return 0;
	if(!sc(chs, chcount, PUSH_ESP_INST)) return 0;
	if(!sc(chs, chcount, POP_ESP_INST)) return 0;
return 1;
}

void help(void)
{
	printf("Required arguments:\n"\
	"\t-a <file>            : Available chars file.\n"\
	"\t-s <file>            : Shellcode file.\n"\
	"\t-o <file>            : Output file for new shellcode.\n"\
	"Optional arguments:\n"\
	"\t-i <instruction set> : Instruction set to use. (0=auto (default), 1=first, 2=second, etc.) (%d instruction sets available.)\n"\
	"\t-t <offset>          : Offset from ESP.\n"\
	"\t-v                   : Verbose/debug mode.\n"\
	"\t-h                   : This help.\n", MAX_INST_SET);
}

int main(int argc, char **argv)
{
unsigned char chs[256], ch;
char avcharsfile[NAME_MAX], shellfile[NAME_MAX], outputfile[NAME_MAX];
int chcount, c, set=0;
uint32_t offset=0;
FILE *fp;
	printf("\nShellcode encoder using the (offensive security) muts' way. (v%s)\nWritten by Melih SARICA.\n\n", VERSION);
	memset(avcharsfile, 0, sizeof avcharsfile);
	memset(shellfile, 0, sizeof shellfile);
	memset(outputfile, 0, sizeof outputfile);
	while((c=getopt(argc, argv, "a:s:vt:o:i:h"))!=-1)
	switch(c)
	{
		case 'a':
			strncpy(avcharsfile, optarg, sizeof(avcharsfile)-1);
			break;
		case 's':
			strncpy(shellfile, optarg, sizeof(shellfile)-1);
			break;
		case 'v':
			verbose=1;
			break;
		case 'o':
			strncpy(outputfile, optarg, sizeof(outputfile)-1);
			break;
		case 'i':
			set=atoi(optarg);
			break;
		case 't':
			sscanf(optarg, "%u", &offset);
			break;
		default:
			help();
			return -3;
	}
	if(!strlen(avcharsfile) || !strlen(shellfile) || !strlen(outputfile) || set<0 || set>MAX_INST_SET)
	{
		help();
		return -4;
	}
	of=fopen(outputfile, "w+b");
	if(of==NULL)
	{
		perror(outputfile);
		return -6;
	}
	if(verbose)
	{
		printf("Available chars file: [%s]\n", avcharsfile);
		printf("Shellcode file:       [%s]\n", shellfile);
		printf("Output file:          [%s]\n", outputfile);
		printf("Verbose:              [%d]\n", verbose);
		printf("Instruction set:      [%d]\n", set);
		printf("Offset:               [%u / 0x%08X]\n", offset, offset);
	}
	fp=fopen(avcharsfile, "rb");
	if(fp==NULL)
	{
		perror(avcharsfile);
		fclose(of);
		return -1;
	}
	load_inst();
	srand(time(NULL));
	memset(chs, 0, sizeof chs);
	for(chcount=0;chcount<256;chcount++)
	{
		ch=fgetc(fp);
		if(feof(fp)) break;
		chs[chcount]=ch;
	}
	fclose(fp);
	printf("%d characters loaded.\n", chcount);
	if(--set==-1)
	{
		for(c=0;c<MAX_INST_SET;c++)
		{
			if(set_available(chs, chcount, c))
			{
				set=c;
				break;
			}
		}
	}
	if(set==-1)
	{
		printf("Sorry, character set is too restrictive in \"%s\". Try populating available character set or the instruction set.\n", avcharsfile);
		return -5;
	}
	if(verbose) printf("Instruction set %d will be used.\n", set+1);
	if(encode_file(chs, chcount, shellfile, set, outputfile, offset)<0) return -2;
	fclose(of);
	printf("Encoding successfully completed.\n");
return 0;
}

