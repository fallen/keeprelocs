#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#undef DEBUG
#define MEM_DISCARDABLE (0x02000000)

typedef struct _IMAGE_SECTION_HEADER
{
	char Name[8];
	union
	{
		uint32_t PhysicalAddress;
		uint32_t VirtualSize;
	} Misc;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;
} __attribute__((__packed__))  IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

struct MZHeader
{
	uint16_t Signature;  // MZ or 0x5A4D
	uint8_t ignored[58]; // we don't care about this part
	uint32_t PeHeaderStart; // starting address of PE Header
} __attribute__((__packed__));

typedef struct _IMAGE_DATA_DIRECTORY
{
	uint16_t VirtualAddress;
	uint16_t Size;
} __attribute__((__packed__))  IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

/*
 * offset of NumberOfRvaAndSizes in 64 bit header: 108
 * offset of DataDirectory in 64: 112
 * offset of NumberOfRvaAndSizes in 32 bit header: 92
 * offset of DataDirectory in 32: 96
*/

struct OptionalPeHeader
{
	uint16_t Magic;
	union {
		struct {
			uint8_t ignored[90];
			uint32_t NumberOfRvaAndSizes; // number of following Directory entries
			IMAGE_DATA_DIRECTORY DataDirectory[];
		} __attribute__((__packed__)) _32;
		struct {
			uint8_t ignored[106];
			uint32_t NumberOfRvaAndSizes; // number of following Directory entries
			IMAGE_DATA_DIRECTORY DataDirectory[];
		} __attribute__((__packed__)) _64;
	};
} __attribute__((__packed__));

// 1 byte aligned
struct PeHeader
{
	uint32_t mMagic; // PE\0\0 or 0x00004550
	uint16_t mMachine;
	uint16_t mNumberOfSections;
	uint32_t mTimeDateStamp;
	uint32_t mPointerToSymbolTable;
	uint32_t mNumberOfSymbols;
	uint16_t mSizeOfOptionalHeader;
	uint16_t mCharacteristics;
} __attribute__((__packed__));

int main(int argc, char **argv)
{
	char *filename;
	int fd;
	char *mem;
	struct stat st;
	off_t len;
	int ret;
	struct MZHeader *mz;
	struct PeHeader *pe;
	struct OptionalPeHeader *ope;

	if (argc < 2)
	{
		printf("usage: %s <PE file>\n", argv[0]);
		return -1;
	}

	filename = argv[1];

	fd = open(filename, O_RDWR);
	if (fd < 0) {
		printf("Could not open file %s: %s\n", filename, strerror(errno));
		return -1;
	}

	ret = fstat(fd, &st);
	if (ret < 0) {
		perror("Error while getting PE file length");
		return -1;
	}

	len = st.st_size;
	mem = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	if (mem == MAP_FAILED) {
		perror("Failed to mmap PE file");
		return -1;
	}

	mz = (struct MZHeader *)mem;
	if (mz->Signature != 0x5A4D) { // "MZ"
		printf("file has incorrect MZ header 0x%02x instead of 0x5a4d\n", mz->Signature);
		return -1;
	}

	pe = (struct PeHeader *)(mem + mz->PeHeaderStart);
	if (strncmp((char *)&pe->mMagic, "PE\0\0", 4)) {
		printf("file has incorrect PE header magic %08x instead of 0x00004550\n", pe->mMagic);
		return -1;
	}

	if (pe->mSizeOfOptionalHeader == 0) {
		printf("file has empty OptionalHeader\n");
		return -1;
	}

	ope = (struct OptionalPeHeader * )((uint8_t *)pe + sizeof(*pe));

	IMAGE_SECTION_HEADER *section = (IMAGE_SECTION_HEADER *)((void *)ope + pe->mSizeOfOptionalHeader);
	for (unsigned int section_id = 0; section_id < pe->mNumberOfSections; section_id++, section++)
	{
#ifdef DEBUG
		printf("section %s\n", section->Name);
#endif
		if (strncmp(section->Name, ".reloc", strlen(".reloc")))
			continue;

		printf(".reloc section characteristics: %08x\n", section->Characteristics);
		if (section->Characteristics & MEM_DISCARDABLE)
			printf("MEM_DISCARDABLE flag found! Dropping it.\n");
		section->Characteristics &= ~(MEM_DISCARDABLE);
	}

	munmap(mem, len);
	close(fd);

	printf("Ok!\n");
	return 0;
}
