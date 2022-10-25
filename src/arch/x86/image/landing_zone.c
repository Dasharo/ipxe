
FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/segment.h>
#include <ipxe/cpuid.h>
#include <ipxe/acpi.h>
#include <ipxe/hash_df.h>
#include <ipxe/sha1.h>
#include <ipxe/sha256.h>
#include <landing_zone.h>

struct sl_header {
	u16 lz_entry_point;
	u16 bootloader_data_offset;
	u16 lz_info_offset;
} __attribute__ (( packed ));

struct lz_info {
	u8  uuid[16];
	u32 version;
	u16 msb_key_algo;
	u8  msb_key_hash[];
} __attribute__ (( packed ));

const unsigned char
lz_header_uuid[16] = { 0x78, 0xf1, 0x26, 0x8e, 0x04, 0x92, 0x11, 0xe9,
                       0x83, 0x2a, 0xc8, 0x5b, 0x76, 0xc4, 0xcc, 0x02 };

struct drtm_t {
	struct acpi_header hdr;
	u64 DL_Entry_Base;
	u64 DL_Entry_Length;
	u32 DL_Entry32;
	u64 DL_Entry64;
	u64 DLME_Exit;
	u64 Log_Area_Start;
	u32 Log_Area_Length;
	u64 Architecture_Dependent;
	u32 DRT_Flags;
	u8  var_len_fields[];
} __attribute__ (( packed ));

#define LZ_TAG_CLASS_MASK		0xF0

/* Tags with no particular class */
#define LZ_TAG_NO_CLASS			0x00
#define LZ_TAG_END				0x00
#define LZ_TAG_UNAWARE_OS		0x01
#define LZ_TAG_TAGS_SIZE		0x0F	/* Always first */

/* Tags specifying kernel type */
#define LZ_TAG_BOOT_CLASS		0x10
#define LZ_TAG_BOOT_LINUX		0x10
#define LZ_TAG_BOOT_MB2			0x11

/* Tags specific to TPM event log */
#define LZ_TAG_EVENT_LOG_CLASS	0x20
#define LZ_TAG_EVENT_LOG		0x20
#define LZ_TAG_HASH				0x21

struct lz_tag_hdr {
	u8 type;
	u8 len;
} __attribute__ (( packed ));

struct lz_tag_tags_size {
	struct lz_tag_hdr hdr;
	u16 size;
} __attribute__ (( packed ));

struct lz_tag_boot_linux {
	struct lz_tag_hdr hdr;
	u32 zero_page;
} __attribute__ (( packed ));

struct lz_tag_boot_mb2 {
	struct lz_tag_hdr hdr;
	u32 mbi;
	u32 kernel_entry;
	u32 kernel_size;
} __attribute__ (( packed ));

struct lz_tag_evtlog {
	struct lz_tag_hdr hdr;
	u32 address;
	u32 size;
} __attribute__ (( packed ));

struct lz_tag_hash {
	struct lz_tag_hdr hdr;
	u16 algo_id;
	u8 digest[];
} __attribute__ (( packed ));


static physaddr_t target;

/**
 * Update LZ header
 *
 * @v image		LZ file
 * @v zeropage	Address of zero page
 */
int lz_set ( struct image *image, userptr_t zeropage, userptr_t tgt, int proto ) {
	target = user_to_phys ( tgt, 0 );
	int rc;

	DBGC ( image, "LZ %p is being copied to 0x%lx (0x%lx user)\n",
	       image, target, tgt );

	if ( ( rc = prep_segment ( tgt, image->len, SLB_SIZE ) ) != 0 ) {
		DBGC ( image, "LZ %p could not prepare segment: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}

	memcpy_user ( tgt, 0, image->data, 0, image->len );

	struct sl_header *sl_hdr = ( struct sl_header *) tgt;
	struct lz_tag_tags_size *tags = ( struct lz_tag_tags_size *)
	                                ( tgt + sl_hdr->bootloader_data_offset );

	/* Tags header */
	tags->hdr.type = LZ_TAG_TAGS_SIZE;
	tags->hdr.len = sizeof(struct lz_tag_tags_size);
	tags->size = sizeof(struct lz_tag_tags_size);

	/* Hashes of LZ */
	{
		u8 buff[SHA256_CTX_SIZE];  /* SHA1_CTX_SIZE is smaller */
		struct lz_tag_hash *h = ((void *)tags) + tags->size;
		h->hdr.type = LZ_TAG_HASH;
		h->hdr.len = sizeof(struct lz_tag_hash) + SHA256_DIGEST_SIZE;
		h->algo_id = 0x000B;
		sha256_algorithm.init ( buff );
		sha256_algorithm.update ( buff, (void *) tgt,
		                          sl_hdr->bootloader_data_offset );
		sha256_algorithm.final ( buff, h->digest );
		tags->size += h->hdr.len;

		h = ((void *)tags) + tags->size;
		h->hdr.type = LZ_TAG_HASH;
		h->hdr.len = sizeof(struct lz_tag_hash) + SHA1_DIGEST_SIZE;
		h->algo_id = 0x0004;
		sha1_algorithm.init ( buff );
		sha1_algorithm.update ( buff, (void *) tgt,
		                        sl_hdr->bootloader_data_offset );
		sha1_algorithm.final ( buff, h->digest );
		tags->size += h->hdr.len;
	}

	/* Boot protocol data */
	DBGC ( image, "LZ %p writing zeropage address: 0x%lx\n", image,
	       user_to_phys ( zeropage, 0 ) );

	switch (proto) {
		case LZ_PROTO_LINUX_BOOT:
		{
			struct lz_tag_boot_linux *b = ((void *)tags) + tags->size;
			b->hdr.type = LZ_TAG_BOOT_LINUX;
			b->hdr.len = sizeof(struct lz_tag_boot_linux);
			b->zero_page = user_to_phys ( zeropage, 0 );
			tags->size += b->hdr.len;
			break;
		}
		case LZ_PROTO_MULTIBOOT2:
		{
			struct lz_tag_boot_mb2 *b = ((void *)tags) + tags->size;
			physaddr_t *args = (physaddr_t *)zeropage;
			b->hdr.type = LZ_TAG_BOOT_MB2;
			b->hdr.len = sizeof(struct lz_tag_boot_mb2);
			b->mbi = user_to_phys ( zeropage, 0 );
			b->kernel_entry = args[0];
			b->kernel_size = args[1];
			tags->size += b->hdr.len;
			break;

		}
		default:
			return 1;
	}

	/* DRTM Event log address and size */
	struct drtm_t *drtm = ( struct drtm_t *)
	                      acpi_find ( ACPI_SIGNATURE ('D', 'R', 'T', 'M'), 0 );

	if ( drtm != UNULL ) {
		DBGC ( image, "ACPI DRTM table at %p (0x%lx physical)\n",
		       drtm, user_to_phys ( ( userptr_t ) drtm, 0 ) );

		struct lz_tag_evtlog *e = ((void *)tags) + tags->size;
		e->hdr.type = LZ_TAG_EVENT_LOG;
		e->hdr.len = sizeof(struct lz_tag_evtlog);
		e->address = drtm->Log_Area_Start;
		e->size = drtm->Log_Area_Length;
		tags->size += e->hdr.len;
	}

	/* Mark end of tags */
	struct lz_tag_hdr *end = ((void *)tags) + tags->size;
	end->type = LZ_TAG_END;
	end->len = sizeof(struct lz_tag_hdr);
	tags->size += end->len;

	return 0;
}

/**
 * Execute Landing Zone image
 *
 * @v image		LZ image
 * @ret rc		Return status code
 */
static int lz_exec ( struct image *image ) {
	uint64_t tsc;
	if ( ! target ) {
		DBGC ( image, "LZ %p: no target address (unsupported kernel type?)\n",
		       image );
		return -ENOSYS;
	};

	/* TODO: remove hardcoded values */
	/* Set APs in wait-for-SIPI state */
	*((volatile uint32_t *)phys_to_user( 0xfee00300ULL )) = 0x000c0500;

	/*
	 * AMD APM states that:
	 * "(...) a fixed delay of no more than 1000 processor cycles may be
	 * necessary before executing SKINIT to ensure reliable sensing of
	 * APIC INIT state by the SKINIT."
	 *
	 * If this value is too low, initial PCR17 values will have the value
	 * as if zero-lenght block of data was measured:
	 * 31A2DC4C22F9C5444A41625D05F95898E055F750  SHA1
	 * 1C9ECEC90E28D2461650418635878A5C91E49F47586ECF75F2B0CBB94E897112  SHA256
	 *
	 * Tests show that 1000 is not enough, even when lowest-performance
	 * P-state is assumed. 2^16 seems to be the lowest power of 2 which
	 * works.
	 */
	asm volatile ( "rdtsc\n\t"
	               "add $0x00010000, %%eax\n\t"
	               "adc $0, %%edx\n\t"
	               "mov %%eax, (%0)\n\t"
	               "mov %%edx, 4(%0)\n\t"
	               :: "r" ( &tsc) : "eax", "edx", "memory");

	/* Relinquish all TPM localities */
	*((volatile uint8_t *)phys_to_user(0xFED40000ULL)) = 0x20;
	*((volatile uint8_t *)phys_to_user(0xFED41000ULL)) = 0x20;
	*((volatile uint8_t *)phys_to_user(0xFED42000ULL)) = 0x20;
	*((volatile uint8_t *)phys_to_user(0xFED43000ULL)) = 0x20;
	*((volatile uint8_t *)phys_to_user(0xFED44000ULL)) = 0x20;

	DBGC ( image, "LZ %p performing SKINIT with eax=0x%lx now\n.\n.\n.", image,
	       target );

	asm volatile ( "1: rdtsc\n\t"
	               "cmp %%edx, 4(%%ecx)\n\t"
	               "ja 1b\n\t"
	               "cmp %%eax, (%%ecx)\n\t"
	               "ja 1b\n\t"
	               "mov %%ebx, %%eax\n\t"
	               "skinit"
	               :: "c" ( &tsc ), "b" ( target ) : "memory" );

	/* There is no way for the image to return, since we provide
	 * no return address.
	 */
	DBGC ( image, "LZ %p SKINIT returned\n", image );
	assert ( 0 );

	return -ECANCELED; /* -EIMPOSSIBLE */
}

/**
 * Probe Landing Zone image
 *
 * @v image		LZ file
 * @ret rc		Return status code
 */
static int lz_probe ( struct image *image ) {
	int rc;
	struct sl_header sl_hdr;
	struct lz_info lzi;
	uint32_t eax, ebx, ecx, edx;

	cpuid ( CPUID_AMD_CHECK, 0, &eax, &ebx, &ecx, &edx );
	if ( eax < CPUID_AMD_FEATURES || ebx != 0x68747541 ||
	     ecx != 0x444D4163 || edx != 0x69746E65 ) {
		DBGC ( image, "Not an AMD processor\n" );
		return -ENOEXEC;
	}

	cpuid ( CPUID_AMD_FEATURES, 0, &eax, &ebx, &ecx, &edx );
	if ( !( ecx & ( 1 << 12 ) ) ) {
		DBGC ( image, "Processor doesn't support SKINIT instruction\n" );
		return -ENOEXEC;
	}

	if ( image->len > SLB_SIZE ) {
		DBGC ( image, "LZ %p too big for Landing Zone\n",
		       image );
		return -ENOEXEC;
	}
	copy_from_user ( &sl_hdr, image->data, 0, sizeof ( sl_hdr ) );
	copy_from_user ( &lzi, image->data, sl_hdr.lz_info_offset, sizeof ( lzi ) );

	rc = memcmp ( lzi.uuid, lz_header_uuid, sizeof ( lz_header_uuid ) );

	if ( rc == 0 ) {
		image_set_name ( image, "landing_zone" );
		return rc;
	}

	return -ENOEXEC;
}

/** Landing Zone image type */
struct image_type lz_image_type __image_type ( PROBE_NORMAL ) = {
	.name = "landing_zone",
	.probe = lz_probe,
	.exec = lz_exec,
};
