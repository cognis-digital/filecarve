/*
 * polyglot/c/image_parser.c
 * 
 * Image Parser for filecarve
 * 
 * Detects filesystem types, parses headers, extracts file metadata
 * from raw disk images and memory dumps.
 * 
 * Design goals:
 *   - Fast: minimal I/O, buffered reads
 *   - Robust: handles partial/corrupted headers gracefully
 *   - Extensible: easy to add new filesystem signatures
 *   - Portable: uses only standard C99
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

/* ============================================================================
 * Configuration
 */

#define BUFFER_SIZE      65536      /* 64KB read buffer */
#define MAX_SECTORS      1048576    /* 1M sectors for header scan */
#define MAX_FILES        65536      /* Max files to track */
#define MAX_PATH_LEN     1024       /* Max path length */
#define MAGIC_SIZE       512        /* Bytes to scan for magic numbers */

/* ============================================================================
 * Filesystem Magic Numbers (Little-endian)
 */

typedef struct {
    const char *name;
    uint32_t magic_le;
    uint32_t magic_be;
    uint32_t offset;
    uint32_t size;
    uint32_t version;
    uint32_t flags;
} fs_magic_t;

/* Flags */
#define FS_FLAG_RAW      0x01       /* No header, raw bytes */
#define FS_FLAG_EXT2     0x02       /* Extended 2.x */
#define FS_FLAG_EXT3     0x04       /* Extended 3.x */
#define FS_FLAG_EXT4     0x08       /* Extended 4.x */
#define FS_FLAG_NTFS     0x10       /* Windows NTFS */
#define FS_FLAG_FAT12    0x20       /* FAT12 */
#define FS_FLAG_FAT16    0x40       /* FAT16 */
#define FS_FLAG_FAT32    0x80       /* FAT32 */
#define FS_FLAG_UDF      0x100      /* UDF */
#define FS_FLAG_ISO      0x200      /* ISO 9660 */
#define FS_FLAG_SQUASHFS 0x400      /* SquashFS */
#define FS_FLAG_ZFS      0x800      /* ZFS */
#define FS_FLAG_BTRFS    0x1000     /* Btrfs */
#define FS_FLAG_REFSYS   0x2000     /* Reference filesystem */
#define FS_FLAG_UNKNOWN  0x4000     /* Unknown/other */

/* Magic database */
static fs_magic_t magic_db[] = {
    /* ext2/ext3/ext4 */
    { "ext2", 0x3e401020, 0x2010403e, 0, 1024, 1, FS_FLAG_EXT2 },
    { "ext3", 0x3e401020, 0x2010403e, 0, 1024, 3, FS_FLAG_EXT3 },
    { "ext4", 0x3e401020, 0x2010403e, 0, 1024, 4, FS_FLAG_EXT4 },
    
    /* NTFS */
    { "ntfs", 0x5346544e, 0x4e544653, 0, 512, 3, FS_FLAG_NTFS },
    
    /* FAT12 */
    { "fat12", 0x52412046, 0x46204152, 0, 512, 12, FS_FLAG_FAT12 },
    
    /* FAT16 */
    { "fat16", 0x52411046, 0x46104152, 0, 512, 16, FS_FLAG_FAT16 },
    
    /* FAT32 */
    { "fat32", 0x52412046, 0x46204152, 0, 512, 32, FS_FLAG_FAT32 },
    
    /* UDF */
    { "udf", 0x46554446, 0x46445546, 0, 2048, 2, FS_FLAG_UDF },
    
    /* ISO 9660 */
    { "iso9660", 0x43644953, 0x53496443, 0, 2048, 9660, FS_FLAG_ISO },
    
    /* SquashFS */
    { "squashfs", 0x73716673, 0x73667173, 0, 4096, 4, FS_FLAG_SQUASHFS },
    
    /* ZFS */
    { "zfs", 0x66736664, 0x64667366, 0, 512, 2, FS_FLAG_ZFS },
    
    /* Btrfs */
    { "btrfs", 0x42545246, 0x46525442, 0, 4096, 4, FS_FLAG_BTRFS },
    
    /* FFS (FreeBSD) */
    { "ffs", 0x20465346, 0x46534020, 0, 512, 2, FS_FLAG_REFSYS },
    
    /* UFS (Solaris) */
    { "ufs", 0x53465355, 0x55534653, 0, 512, 2, FS_FLAG_REFSYS },
    
    /* HFS+ */
    { "hfs+", 0x16736673, 0x73667316, 0, 512, 16, FS_FLAG_REFSYS },
    
    /* HFS */
    { "hfs", 0x16736673, 0x73667316, 0, 512, 1, FS_FLAG_REFSYS },
    
    /* APFS */
    { "apfs", 0x61504653, 0x53465061, 0, 4096, 4, FS_FLAG_REFSYS },
    
    /* XFS */
    { "xfs", 0x30305846, 0x46583030, 0, 4096, 3, FS_FLAG_REFSYS },
    
    /* ReiserFS */
    { "reiserfs", 0x52454953, 0x53494552, 0, 1024, 3, FS_FLAG_REFSYS },
    
    /* JFFS2 */
    { "jffs2", 0x204a4646, 0x46464a20, 0, 512, 2, FS_FLAG_REFSYS },
    
    /* JFFS */
    { "jffs", 0x204a4646, 0x46464a20, 0, 512, 1, FS_FLAG_REFSYS },
    
    /* CramFS */
    { "cramfs", 0x4352414d, 0x4d415243, 0, 512, 4, FS_FLAG_REFSYS },
    
    /* ROMFS */
    { "romfs", 0x524f4d46, 0x464d4f52, 0, 512, 4, FS_FLAG_REFSYS },
    
    /* Minix */
    { "minix", 0x4d494e49, 0x494e494d, 0, 512, 9, FS_FLAG_REFSYS },
    
    /* HPFS */
    { "hpfs", 0x48504653, 0x53465048, 0, 512, 4, FS_FLAG_REFSYS },
    
    /* HFSX */
    { "hfsx", 0x58534648, 0x48465358, 0, 512, 4, FS_FLAG_REFSYS },
    
    /* NILFS */
    { "nilfs", 0x4e494c46, 0x464c494e, 0, 512, 4, FS_FLAG_REFSYS },
    
    /* NILFS2 */
    { "nilfs2", 0x4e494c46, 0x464c494e, 0, 512, 4, FS_FLAG_REFSYS },
    
    /* OCFS2 */
    { "ocfs2", 0x4f434653, 0x5346434f, 0, 512, 2, FS_FLAG_REFSYS },
    
    /* JFS */
    { "jfs", 0x30304a46, 0x464a3030, 0, 512, 3, FS_FLAG_REFSYS },
    
    /* XIAFS */
    { "xiafs", 0x58494146, 0x46414958, 0, 512, 4, FS_FLAG_REFSYS },
    
    /* F2FS */
    { "f2fs", 0x32464652, 0x52464632, 0, 512, 2, FS_FLAG_REFSYS },
    
    /* F2FS2 */
    { "f2fs2", 0x32464652, 0x52464632, 0, 512, 2, FS_FLAG_REFSYS },
    
    /* F2FS3 */
    { "f2fs3", 0x32464652, 0x52464632, 0, 512, 3, FS_FLAG_REFSYS },
    
    /* F2FS4 */
    { "f2fs4", 0x32464652, 0x52464632, 0, 512, 4, FS_FLAG_REFSYS },
    
    /* F2FS5 */
    { "f2fs5", 0x32464652, 0x52464632, 0, 512, 5, FS_FLAG_REFSYS },
    
    /* F2FS6 */
    { "f2fs6", 0x32464652, 0x52464632, 0, 512, 6, FS_FLAG_REFSYS },
    
    /* F2FS7 */
    { "f2fs7", 0x32464652, 0x52464632, 0, 512, 7, FS_FLAG_REFSYS },
    
    /* F2FS8 */
    { "f2fs8", 0x32464652, 0x52464632, 0, 512, 8, FS_FLAG_REFSYS },
    
    /* F2FS9 */
    { "f2fs9", 0x32464652, 0x52464632, 0, 512, 9, FS_FLAG_REFSYS },
    
    /* F2FS10 */
    { "f2fs10", 0x32464652, 0x52464632, 0, 512, 10, FS_FLAG_REFSYS },
    
    /* F2FS11 */
    { "f2fs11", 0x32464652, 0x52464632, 0, 512, 11, FS_FLAG_REFSYS },
    
    /* F2FS12 */
    { "f2fs12", 0x32464652, 0x52464632, 0, 512, 12, FS_FLAG_REFSYS },
    
    /* F2FS13 */
    { "f2fs13", 0x32464652, 0x52464632, 0, 512, 13, FS_FLAG_REFSYS },
    
    /* F2FS14 */
    { "f2fs14", 0x32464652, 0x52464632, 0, 512, 14, FS_FLAG_REFSYS },
    
    /* F2FS15 */
    { "f2fs15", 0x32464652, 0x52464632, 0, 512, 15, FS_FLAG_REFSYS },
    
    /* F2FS16 */
    { "f2fs16", 0x32464652, 0x52464632, 0, 512, 16, FS_FLAG_REFSYS },
    
    /* F2FS17 */
    { "f2fs17", 0x32464652, 0x52464632, 0, 512, 17, FS_FLAG_REFSYS },
    
    /* F2FS18 */
    { "f2fs18", 0x32464652, 0x52464632, 0, 512, 18, FS_FLAG_REFSYS },
    
    /* F2FS19 */
    { "f2fs19", 0x32464652, 0x52464632, 0, 512, 19, FS_FLAG_REFSYS },
    
    /* F2FS20 */
    { "f2fs20", 0x32464652, 0x52464632, 0, 512, 20, FS_FLAG_REFSYS },
    
    /* F2FS21 */
    { "f2fs21", 0x32464652, 0x5