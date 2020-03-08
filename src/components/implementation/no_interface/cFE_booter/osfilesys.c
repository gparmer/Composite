#include "osfilesys.h"
#include "tar.h"

struct fs    filesystems[MAX_NUM_FS];
struct fs *  openfs = &filesystems[0];
struct fsobj files[MAX_NUM_FILES];
struct fd    fd_tbl[OS_MAX_NUM_OPEN_FILES + 1];

/*
 * Notes on this version:
 * It provides all of the functionality required by the cFE and more.  It does
 * not fully satisfy all of the requirements for posix in general. It passes all
 * of cFE's unit tests, and all of the testing and debugging I have thrown at it
 *
 * Beware when using struct dirent and struct stat.  As a temporary measure,
 * they are currently generated to comply with glibc rather than musl.
 *
 * Future plans:
 *  - Compile cFE with musl and fix stat and dirent structures
 *  - modularize into a bare bones filesystem library
 *  - Refactor rest of code into posix compatible filesystem built on bare bones fs
 *
 */

/******************************************************************************
** fsobj Level Methods
******************************************************************************/

/* checks if a file descriptor is valid and in use */
int32
chk_fd(int32 FD)
{
	struct fd *filedes;

	if (FD > OS_MAX_NUM_OPEN_FILES) return OS_FS_ERR_INVALID_FD;
	if (FD <= 0) return OS_FS_ERR_INVALID_FD;

	filedes = &fd_tbl[FD];
	if (!filedes->file) return OS_FS_ERR_INVALID_FD;
	if (filedes->ino == 0 || filedes->file->ino == 0) return OS_FS_ERR_INVALID_FD;
	assert(filedes->ino == filedes->file->ino);
	return OS_FS_SUCCESS;
}

/* finds the next free file */
uint32
file_get_new(struct fsobj **o)
{
	uint32 count = 0;
	while (count < MAX_NUM_FILES && files[count].ino) { count++; }
	if (count == MAX_NUM_FILES) return OS_FS_ERROR;
	*o = &files[count];

	/* ino needs to be unique and nonzero, so ino is defined as index+1 */
	**o = (struct fsobj){.ino = count + 1};
	return OS_FS_SUCCESS;
}

uint32
file_insert(struct fsobj *o, char *path)
{
	assert(o && path && openfs);

	/* paths should always begin with '/' but we do not need it here */
	if (path[0] != '/') return OS_FS_ERR_PATH_INVALID;
	path++;

	if (!openfs->root) {
		if (strcmp(o->name, path) != 0) return OS_FS_ERR_PATH_INVALID;
		openfs->root = o;
		return OS_FS_SUCCESS;
	}
	assert(openfs->root->ino);
	struct fsobj *cur = openfs->root;

	/* token is the current directory in path */
	char path_temp[OS_MAX_PATH_LEN * 2];
	strcpy(path_temp, path);
	const char delim[2] = "/";
	char *     token    = strtok(path_temp, delim);

	if (strcmp(token, cur->name) != 0) return OS_FS_ERR_PATH_INVALID;

	/* loop terminates when it finds a place to put o or determines path is invalid */
	while (1) {
		if (token == NULL) { return OS_FS_ERR_PATH_INVALID; }
		assert(cur->name);

		/* if there is no child, then insert as child */
		if (!cur->child) {
			/* if the next part of the path is not o->name or there is a part after it, bad path */
			token = strtok(NULL, delim);
			if (strcmp(token, o->name) != 0 || strtok(NULL, delim) != NULL) {
				return OS_FS_ERR_PATH_INVALID;
			}

			o->parent  = cur;
			cur->child = o;
			o->next    = NULL;
			o->prev    = NULL;
			return OS_FS_SUCCESS;
		}
		cur   = cur->child;
		token = strtok(NULL, delim);

		/* precondition: cur is the first in a non-empty list of children
		 * postcondition: cur is an ancestor of o or o has been inserted in list
		 * while cur is not ancestor of o
		 */
		while (strcmp(token, cur->name) != 0) {
			if (cur->next == NULL) {
				/* if the next part of the path is o->name or there is a part after it, bad path */
				if (strcmp(token, o->name) != 0 || strtok(NULL, delim) != NULL) {
					return OS_FS_ERR_PATH_INVALID;
				}
				/* insert o as the last child in a linked list of children */
				cur->next = o;
				o->prev   = cur;
				o->parent = cur->parent;
				o->next   = NULL;
				return OS_FS_SUCCESS;
			}
			cur = cur->next;
		}
	}
	PANIC("Unreachable Statement");
	return 0;
}

/* Internally, FDs are considered unused when ino == 0 */
static int32
fd_get(int32 ino)
{
	struct fd *filedes;
	uint32     count = 1;

	while (count <= OS_MAX_NUM_OPEN_FILES + 1 && fd_tbl[count].ino != 0) { count++; }
	if (count == OS_MAX_NUM_OPEN_FILES + 1) return OS_FS_ERROR;

	filedes         = &fd_tbl[count];
	filedes->ino    = ino;
	filedes->access = NONE;
	return count;
}

int32
file_open(char *path, enum fs_permissions permission)
{
	int32         FD;
	struct fsobj *file;
	struct fd *   filedes;

	assert(openfs);
	if (!openfs->root) return OS_FS_ERROR;
	if (!path) return OS_FS_ERR_INVALID_POINTER;

	file = file_find(path);
	if (!file) return OS_FS_ERR_PATH_INVALID;
	if (file->type != FSOBJ_FILE) return OS_FS_ERROR;

	/* get a new fd */
	FD = fd_get(file->ino);
	if (FD == OS_FS_ERROR) { return OS_FS_ERR_NO_FREE_FDS; }

	filedes = &fd_tbl[FD];

	filedes->access                        = permission;
	filedes->file                          = file;
	filedes->position.file_pos.open_part   = file->file_part;
	filedes->position.file_pos.file_offset = 0;
	filedes->position.file_pos.part_offset = 0;
	file->refcnt++;
	return FD;
}

int32
file_close(int32 FD)
{
	int32 ret = chk_fd(FD);
	if (ret != OS_FS_SUCCESS) return OS_FS_ERROR;

	struct fd *filedes = &fd_tbl[FD];
	if (filedes->ino == 0) return OS_FS_ERROR;

	uint32 index = filedes->ino - 1;
	assert(files[index].refcnt > 0);
	files[index].refcnt--;
	filedes->ino = 0;
	return OS_FS_SUCCESS;
}

int32
file_close_by_name(char *path)
{
	int           i;
	struct fsobj *file = file_find(path);

	for (i = 0; i < OS_MAX_NUM_OPEN_FILES + 1; i++) {
		if (fd_tbl[i].file == file) {
			assert(fd_tbl[i].ino = file->ino);
			file_close(i);
			return OS_FS_SUCCESS;
		}
	}
	return OS_FS_ERROR;
}

/* converts from the cFE defined permission constants to internal permission type
 * unknown permissions return NONE, cFE should treat none as an error
 */
enum fs_permissions
permission_cFE_to_cos(uint32 permission)
{
	switch (permission) {
	case OS_READ_WRITE:
		return READ & WRITE;
	case OS_WRITE_ONLY:
		return WRITE;
	case OS_READ_ONLY:
		return READ;
	default:
		PANIC("Invalid permission from cFE");
	}
	PANIC("unreachable statement");
	return 0;
}

uint32
permission_cos_to_cFE(enum fs_permissions permission)
{
	switch (permission) {
	case READ &WRITE:
		return OS_READ_WRITE;
	case WRITE:
		return OS_WRITE_ONLY;
	case READ:
		return OS_READ_ONLY;
	default:
		PANIC("Invalid permission in existing file");
	}
	PANIC("unreachable statement");
	return 0;
}

int32
path_exists(const char *path)
{
	int32 ret = path_isvalid(path);
	if (ret != OS_FS_SUCCESS) return ret;
	if (file_find((char *)path) == NULL) return OS_FS_ERROR;
	return OS_FS_SUCCESS;
}

int32
path_isvalid(const char *path)
{
	if (path == NULL) return OS_FS_ERR_INVALID_POINTER;
	if (strlen(path) > OS_MAX_PATH_LEN) return OS_FS_ERR_PATH_TOO_LONG;
	if (strlen(path_to_name((char *)path)) > OS_MAX_FILE_NAME) return OS_FS_ERR_NAME_TOO_LONG;
	if (path[0] != '/') return OS_FS_ERR_PATH_INVALID;
	assert(openfs);

	if (openfs->root) {
		assert(openfs->root->name);
		if (memcmp(openfs->root->name, path + 1, strlen(openfs->root->name))) { return OS_FS_ERR_PATH_INVALID; }
	}
	return OS_FS_SUCCESS;
}

int32
path_translate(char *virt, char *local)
{
	int32 ret;

	if (!virt || !local) return OS_FS_ERR_INVALID_POINTER;
	ret = path_isvalid(virt);
	if (ret != OS_FS_SUCCESS) return ret;
	if (!openfs->root) return OS_FS_ERR_PATH_INVALID;
	ret = path_exists(virt);
	if (ret != OS_FS_SUCCESS) return ret;
	strcpy(local, virt);
	return OS_FS_SUCCESS;
}

/******************************************************************************
** f_part Level Methods
******************************************************************************/

uint32
part_get_new(struct f_part **part)
{
	*part = (void *)memmgr_heap_page_alloc();

	assert(part != NULL);
	(*part)->next = NULL;
	(*part)->prev = NULL;
	(*part)->file = NULL;
	(*part)->data = (char *)*part + sizeof(struct f_part);
	return OS_FS_SUCCESS;
}

int32
file_read(int32 FD, void *buffer, uint32 nbytes)
{
	if (!buffer) return OS_FS_ERR_INVALID_POINTER;
	int32 ret = chk_fd(FD);
	if (ret != OS_FS_SUCCESS) return ret;

	struct fd *filedes = &fd_tbl[FD];

	struct fsobj *o = filedes->file;
	assert(o->refcnt >= 1);
	if (o->type != FSOBJ_FILE) return OS_FS_ERR_INVALID_FD;
	struct file_position *position = &filedes->position.file_pos;
	struct f_part *       part     = position->open_part;

	/* nbytes > number of bytes left in file, only number left are read */
	if (nbytes > o->size - position->file_offset) { nbytes = o->size - position->file_offset; }

	if (nbytes == OS_FS_SUCCESS) return 0;
	uint32 bytes_to_read = nbytes;

	if (o->memtype == DYNAMIC) {
		while (1) {
			/* read_size is the length of a continuous segment to be read from */
			uint32 read_size = F_PART_DATA_SIZE - position->file_offset;
			part             = position->open_part;
			assert(part);

			if (bytes_to_read > read_size) {
				memcpy(buffer, &part->data[position->part_offset], read_size);

				buffer += read_size;
				bytes_to_read -= read_size;
				position->file_offset += read_size;

				if (!part->next) {
					position->part_offset = F_PART_DATA_SIZE;
					return nbytes - bytes_to_read;
				}
				position->open_part   = part->next;
				position->part_offset = 0;

			} else if (bytes_to_read == read_size) {
				memcpy(buffer, &part->data[position->part_offset], read_size);
				position->file_offset += read_size;
				if (!part->next) {
					position->part_offset = F_PART_DATA_SIZE;
					return nbytes;
				}
				position->open_part   = part->next;
				position->part_offset = 0;
				return nbytes;

				/* bytes_to_read < the continuous space left on f_part */
			} else {
				memcpy(buffer, position->open_part->data + position->part_offset, bytes_to_read);
				position->part_offset += bytes_to_read;
				position->file_offset += bytes_to_read;
				return nbytes;
			}
		}
	} else if (o->memtype == STATIC) {
		memcpy(buffer, &part->data[position->file_offset], bytes_to_read);
		position->part_offset += bytes_to_read;
		position->file_offset += bytes_to_read;
		return nbytes;
	} else {
		PANIC("Memtype is neither static nor dynamic");
	}

	PANIC("Unreachable Statement");
	return 0;
}

int32
file_write(int32 FD, void *buffer, uint32 nbytes)
{
	int32  ret;
	uint32 bytes_to_write;
	uint32 bytes_remaining;

	if (!buffer) return OS_FS_ERR_INVALID_POINTER;
	ret = chk_fd(FD);
	if (ret != OS_FS_SUCCESS) return ret;

	struct fd *           filedes  = &fd_tbl[FD];
	struct fsobj *        o        = filedes->file;
	struct file_position *position = &filedes->position.file_pos;

	if (o->refcnt < 1) return OS_FS_ERROR;
	if (o->memtype == STATIC) return OS_FS_ERROR;
	if (o->type == FSOBJ_DIR) return OS_FS_ERROR;
	if (nbytes == 0) return 0;

	bytes_to_write  = nbytes;
	bytes_remaining = F_PART_DATA_SIZE - position->part_offset;

	/* while there are enough bytes to be written to fill a f_part */
	while (bytes_to_write > bytes_remaining) {
		memcpy(position->open_part->data + position->part_offset, buffer, bytes_remaining);
		position->file_offset += bytes_remaining;
		buffer += bytes_remaining;
		bytes_to_write -= bytes_remaining;
		position->part_offset = 0;
		if (position->open_part->next == NULL) {
			struct f_part *part;
			part_get_new(&part);
			part->file                = o;
			part->next                = NULL;
			part->prev                = position->open_part;
			position->open_part->next = part;
		}

		position->open_part = position->open_part->next;
		bytes_remaining     = F_PART_DATA_SIZE - position->part_offset;
	}
	/* bytes_to_write < bytes_remaining */
	memcpy(position->open_part->data, buffer, bytes_to_write);
	position->part_offset += bytes_to_write;
	position->file_offset += bytes_to_write;
	if (o->size < position->file_offset) { o->size = position->file_offset; }
	return nbytes;
}

struct fsobj *
file_find(char *path)
{
	char          path_temp[OS_MAX_PATH_LEN * 2];
	const char    delim[2] = "/";
	char *        token;
	struct fsobj *cur;

	assert(path);
	/* paths should always begin with '/' dir names do not */
	if (path[0] != '/') return NULL;
	path++;

	/* token is the current directory in path */
	strcpy(path_temp, path);
	token = strtok(path_temp, delim);

	if (!openfs || !openfs->root) return NULL;
	cur = openfs->root;
	assert(cur && cur->name);
	if (strcmp(token, cur->name) != 0) return NULL;

	while (1) {
		/* iterate through linked list of children until ancestor is found */
		while (strcmp(token, cur->name) != 0) {
			if (!cur->next) return NULL;
			cur = cur->next;
		}
		token = strtok(NULL, delim);
		if (token == NULL) return cur;
		if (!cur->child) return NULL;
		cur = cur->child;
	}
	PANIC("Unreachable Statement");
	return NULL;
}

int32
file_create(char *path, enum fs_permissions permission)
{
	struct fsobj *o;

	assert(path);

	if (file_get_new(&o) != OS_FS_SUCCESS) return OS_FS_ERROR;
	o->name       = path_to_name(path);
	o->type       = FSOBJ_FILE;
	o->size       = 0;
	o->permission = permission;
	o->memtype    = DYNAMIC;

	struct f_part *part;
	part_get_new(&part);

	o->file_part = part;
	part->file   = o;
	part->data   = (char *)part + sizeof(struct f_part);
	if (file_insert(o, path) != OS_FS_SUCCESS) {
		o->ino = 0;
		return OS_FS_ERR_PATH_INVALID;
	}
	return file_open(path, permission);
}

int32
file_remove(char *path)
{
	struct fsobj *file = file_find(path);

	if (!file) return OS_FS_ERR_PATH_INVALID;
	file_rm(file);
	return OS_FS_SUCCESS;
}

int32
file_rename(char *old_filename, char *new_filename)
{
	struct fsobj *file = file_find(old_filename);

	if (!file) return OS_FS_ERR_PATH_INVALID;
	file->name = path_to_name(new_filename);
	return OS_FS_SUCCESS;
}

/* This is part of but not a full posix implementation,
 * stat has a lot of fields not applicable to us
 */
int32
file_stat(char *path, os_fstat_t *filestats)
{
	struct fsobj *file = file_find(path);

	if (!file) return OS_FS_ERROR;
	*filestats =
	  (os_fstat_t){.st_dev = 0, .st_ino = file->ino, .st_size = file->size, .st_blksize = F_PART_DATA_SIZE};

	if (file->type == FSOBJ_FILE) { filestats->st_mode = S_IFREG; }
	if (file->type == FSOBJ_DIR) { filestats->st_mode = S_IFDIR; }

	return OS_FS_SUCCESS;
}

int32
file_lseek(int32 FD, int32 offset, uint32 whence)
{
	uint32 target_offset = 0;
	int32  ret           = chk_fd(FD);

	if (ret != OS_FS_SUCCESS) return ret;

	struct fd *           filedes  = &fd_tbl[FD];
	struct fsobj *        o        = filedes->file;
	struct file_position *position = &filedes->position.file_pos;

	/* wasnt sure if it should be legal to pass negative offset, went with yes */
	if (whence == SEEK_SET) {
		if (offset < 0) return OS_FS_ERROR;
		target_offset = offset;
	} else if (whence == SEEK_CUR) {
		if (offset + (int32)position->file_offset < 0) return OS_FS_ERROR;
		target_offset = offset + position->file_offset;
	} else if (whence == SEEK_END) {
		if (offset + (int32)position->file_offset < 0) return OS_FS_ERROR;
		target_offset = offset + o->size;
	} else {
		return OS_FS_ERROR;
	}

	/* you cannot write past the end of a static file */
	if (target_offset > o->size && o->memtype == STATIC) { return OS_FS_ERROR; }

	position->open_part   = o->file_part;
	position->file_offset = 0;

	while (target_offset - position->file_offset > F_PART_DATA_SIZE) {
		/* seeking past the end of a file writes zeros until that position */
		if (position->open_part->next == NULL) {
			struct f_part *part;
			part_get_new(&part);
			part->file                = o;
			part->next                = NULL;
			part->prev                = position->open_part;
			position->open_part->next = part;
		}
		position->open_part = position->open_part->next;
		position->file_offset += F_PART_DATA_SIZE;
	}
	position->file_offset += target_offset % F_PART_DATA_SIZE;
	position->part_offset = target_offset % F_PART_DATA_SIZE;

	if (position->file_offset > o->size) { o->size = position->file_offset; }
	return target_offset;
}

int32
file_cp(char *src, char *dest)
{
	int32       fd_src;
	int32       fd_dest;
	int32       to_copy;
	int32       read_size, write_size;
	static char copy_buffer[F_PART_DATA_SIZE];

	fd_src = file_open(src, READ);
	if (chk_fd(fd_src) != OS_FS_SUCCESS) return fd_src;

	/* if the dest already exists, overwrite it */
	fd_dest = file_open(dest, WRITE);
	if (chk_fd(fd_dest) == OS_FS_SUCCESS) {
		/* writing size to zero effectivly deletes all the old data */
		fd_tbl[fd_dest].file->size = 0;
	} else {
		fd_dest = file_create(dest, fd_tbl[fd_src].file->permission);
	}
	if (chk_fd(fd_dest) != OS_FS_SUCCESS) return fd_dest;

	to_copy    = fd_tbl[fd_src].file->size;
	read_size  = 0;
	write_size = 0;

	/* TODO: copy buffer is aggressively not thread safe, take a lock */
	while (to_copy > 0) {
		if (to_copy > (int32)F_PART_DATA_SIZE) {
			read_size = F_PART_DATA_SIZE;
		} else {
			read_size = to_copy;
		}
		read_size  = file_read(fd_src, copy_buffer, read_size);
		write_size = file_write(fd_dest, copy_buffer, read_size);
		if (read_size == 0 || write_size != read_size) return OS_FS_ERROR;
		to_copy -= write_size;
	}

	file_close(fd_src);
	file_close(fd_dest);

	return OS_FS_SUCCESS;
}

int32
file_mv(char *src, char *dest)
{
	struct fsobj *file = file_find(src);

	if (!file) return OS_FS_ERROR;

	if (file->next) { file->next->prev = file->prev; }
	if (file->prev) { file->prev->next = file->next; }
	if (file->parent->child == file) { file->parent->child = file->next; }

	file->name = path_to_name(dest);
	if (file_insert(file, dest) != OS_FS_SUCCESS) return OS_FS_ERROR;
	return OS_FS_SUCCESS;
}

/*
 * currently returns name and in path field
 * perhaps it would be a good idea to track path in fsobj
 * but it looks like cFE uses this only to check is fd is valid
 */
int32
file_FDGetInfo(int32 FD, OS_FDTableEntry *fd_prop)
{
	struct fd *filedes;
	int32      ret = chk_fd(FD);

	if (ret != OS_FS_SUCCESS) return OS_FS_ERR_INVALID_FD;

	filedes = &fd_tbl[FD];
	if (filedes->ino == 0) return OS_FS_ERR_INVALID_FD;

	fd_prop->OSfd = FD;
	memcpy(&fd_prop->Path, filedes->file->name, strlen(filedes->file->name));
	fd_prop->User    = 0;
	fd_prop->IsValid = 1;
	return OS_FS_SUCCESS;
}


/******************************************************************************
** Dirent Level Methods
******************************************************************************/

int32
dir_open(char *path)
{
	int32                FD;
	struct fsobj *       file;
	struct fd *          filedes;
	struct dir_position *position;

	file = file_find(path);
	if (!file) return 0;
	if (file->ino == 0) return 0;
	if (file->type != FSOBJ_DIR) return 0;

	FD = fd_get(file->ino);
	if (FD > OS_MAX_NUM_OPEN_FILES + 1 || FD <= 0) return 0;
	file->refcnt++;

	filedes         = &fd_tbl[FD];
	filedes->access = READ;
	filedes->file   = file;

	position           = &filedes->position.dir_pos;
	position->open_dir = file;
	position->cur      = file;
	position->status   = NORMAL;

	return FD;
}

uint32
dir_close(int32 FD)
{
	struct fd *filedes;

	if (FD > OS_MAX_NUM_OPEN_FILES + 1 || FD <= 0) return OS_FS_ERROR;
	filedes = &fd_tbl[FD];

	filedes->ino = 0;
	return OS_FS_SUCCESS;
}

void
dir_rewind(int32 FD)
{
	struct fd *filedes;

	if (FD >= OS_MAX_NUM_OPEN_FILES || FD <= 0) return;
	filedes = &fd_tbl[FD];

	if (filedes->ino == 0) return;
	if (filedes->file->type != FSOBJ_DIR) return;

	/* cur == open_dir indicates that stream is in initial position, prior to first read */
	filedes->position.dir_pos.cur    = filedes->position.dir_pos.open_dir;
	filedes->position.dir_pos.status = NORMAL;
}

os_dirent_t *
dir_read(int32 FD)
{
	struct fd *  filedes;
	os_dirent_t *dir;

	if (FD > OS_MAX_NUM_OPEN_FILES + 1 || FD <= 0) return NULL;
	filedes = &fd_tbl[FD];

	if (filedes->ino == 0) return NULL;
	if (filedes->file->type != FSOBJ_DIR) return NULL;

	dir = &filedes->position.dir_pos.dirent;

	switch (filedes->position.dir_pos.status) {
	case NORMAL:
		break;

	case END_OF_STREAM:
		return NULL;

	case PARENT_DIR_LINK:
		filedes->position.dir_pos.cur    = NULL;
		filedes->position.dir_pos.status = END_OF_STREAM;
		return NULL;

	case CUR_DIR_LINK:
		strcpy(dir->d_name, "..");
		dir->d_ino                       = 0;
		filedes->position.dir_pos.status = PARENT_DIR_LINK;
		return dir;
	}

	if (filedes->position.dir_pos.cur == filedes->position.dir_pos.open_dir) {
		filedes->position.dir_pos.cur = filedes->position.dir_pos.open_dir->child;
	} else {
		filedes->position.dir_pos.cur = filedes->position.dir_pos.cur->next;
	}

	if (!filedes->position.dir_pos.cur) {
		filedes->position.dir_pos.status = CUR_DIR_LINK;
		strcpy(dir->d_name, ".");
		dir->d_ino = 0;
	} else {
		strcpy(dir->d_name, filedes->position.dir_pos.cur->name);
		dir->d_ino = filedes->position.dir_pos.cur->ino;
	}

	return (os_dirent_t *)dir;
}

int32
file_mkdir(char *path)
{
	struct fsobj *o;

	assert(path);

	if (file_get_new(&o)) return OS_FS_ERR_DRIVE_NOT_CREATED;
	o->name   = path_to_name(path);
	o->type   = FSOBJ_DIR;
	o->next   = NULL;
	o->prev   = NULL;
	o->parent = NULL;
	o->child  = NULL;
	o->size   = 0;
	if (file_insert(o, path) != OS_FS_SUCCESS) return OS_FS_ERR_PATH_INVALID;
	return OS_FS_SUCCESS;
}

int32
file_rmdir(char *path)
{
	struct fsobj *root;
	struct fsobj *cur;

	assert(path);

	root = file_find(path);
	cur  = root;
	if (!root) return OS_FS_ERROR;

	while (root->child) {
		/* if cur is the last leaf in a list */
		if (!cur->next && !cur->child) {
			if (cur->prev != NULL) {
				assert(cur->prev->next == cur);
				cur = cur->prev;
				file_rm(cur->next);
			} else {
				assert(cur->parent->child == cur);
				cur = cur->parent;
				file_rm(cur->child);
			}
		} else if (cur->child != NULL) {
			cur = cur->child;
		} else {
			cur = cur->next;
		}
	}
	file_rm(root);
	return OS_FS_SUCCESS;
}

int32
file_rm(struct fsobj *o)
{
	/* TODO, pass an error back out of library if someone implicitly tries to close open file */
	/* assert(o->refcnt == 0); */
	assert(o && o->child == NULL);
	/* if o is first in list of children, update parent link to it */
	if (o->prev == NULL && o->parent) {
		assert(o->parent->child == o);
		/* if next = null this still works */
		o->parent->child = o->next;
	}

	/* update link from prev still work if next or prev = null */
	if (o->prev) {
		assert(o->prev->next == o);
		o->prev->next = o->next;
	}
	/* update link from next */
	if (o->next) {
		assert(o->next->prev == o);
		o->next->prev = o->prev;
	}
	/* there should now be no links within the fs to o
	 * we do not do deallocate file data but we do reuse fsobj
	 */
	*o = (struct fsobj){.name = NULL};

	return OS_FS_SUCCESS;
}

/* close all of the open FDs associated with file */
int32
file_close_by_ino(int32 ino)
{
	int i;
	for (i = 1; i <= OS_MAX_NUM_OPEN_FILES; i++) {
		if (fd_tbl[i].ino == ino) { file_close(i); }
	}
	return OS_FS_SUCCESS;
}

/******************************************************************************
** fs Level Methods
******************************************************************************/

uint32
fs_mount(char *devname, char *mountpoint)
{
	uint32 i;

	assert(devname);

	for (i = 0; i < MAX_NUM_FS && filesystems[i].devname != NULL; i++) {
		if (!strcmp(filesystems[i].devname, devname)) {
			/* This is a bad hack that I have not found a solution to
			 * basically mount should fail if already mounted
			 * but to load tar I need to pre-mount the first filesystem
			 */
			if (strcmp(mountpoint, "/ram") && filesystems[i].root) return OS_FS_ERROR;
			struct fsobj *o;
			if (file_get_new(&o)) return OS_FS_ERROR;
			filesystems[i].mountpoint = mountpoint;
			openfs                    = &filesystems[i];
			if (!filesystems[i].root) { file_mkdir(mountpoint); }
			assert(strcmp(openfs->mountpoint, mountpoint) == 0);
			return OS_FS_SUCCESS;
		}
	}
	return OS_FS_ERROR;
}

uint32
fs_unmount(char *mountpoint)
{
	uint32 i;

	assert(mountpoint);
	for (i = 0; i < MAX_NUM_FS && filesystems[i].mountpoint != NULL; i++) {
		if (mountpoint != NULL && !strcmp(filesystems[i].mountpoint, mountpoint)) {
			filesystems[i].mountpoint = NULL;
			return OS_FS_SUCCESS;
		}
	}
	return OS_FS_ERROR;
}

uint32
fs_init(char *devname, char *volname, uint32 blocksize, uint32 numblocks)
{
	uint32 count = 0, ret = 0;

	if (!devname) return OS_FS_ERR_INVALID_POINTER;
	if (blocksize == 0 || numblocks == 0) return OS_FS_ERROR;
	if (strlen(devname) >= OS_FS_DEV_NAME_LEN || strlen(volname) >= OS_FS_VOL_NAME_LEN) return OS_FS_ERROR;

	while (count < MAX_NUM_FS && filesystems[count].devname) { count++; }
	if (count == MAX_NUM_FS) return OS_FS_ERR_DEVICE_NOT_FREE;

	filesystems[count] = (struct fs){.devname    = devname,
	                                 .volname    = volname,
	                                 .mountpoint = "",
	                                 .blocksize  = blocksize,
	                                 .numblocks  = numblocks,
	                                 .root       = NULL};

	openfs = &filesystems[count];
	return OS_FS_SUCCESS;
}

int32
fs_remove(char *devname)
{
	uint32 i;

	if (!devname) return OS_FS_ERR_INVALID_POINTER;

	for (i = 0; i < MAX_NUM_FS && filesystems[i].devname != NULL; i++) {
		if (devname && filesystems[i].devname && !strcmp(filesystems[i].devname, devname)) {
			filesystems[i].devname    = NULL;
			filesystems[i].volname    = NULL;
			filesystems[i].mountpoint = NULL;
			filesystems[i].blocksize  = 0;
			filesystems[i].numblocks  = 0;
			filesystems[i].root       = NULL;
			return OS_FS_SUCCESS;
		}
	}
	return OS_FS_ERROR;
}

int32
fs_get_drive_name(char *PhysDriveName, char *MountPoint)
{
	uint32 i;
	for (i = 0; i < MAX_NUM_FS && filesystems[i].devname != NULL; i++) {
		if (filesystems[i].mountpoint && !strcmp(filesystems[i].mountpoint, MountPoint)) {
			char *new_name = "Ram FS\n";
			memcpy(PhysDriveName, new_name, strlen(new_name));
			return OS_FS_SUCCESS;
		}
	}
	return OS_FS_ERROR;
}

int32
fs_get_info(os_fsinfo_t *filesys_info)
{
	uint32 i, count = 0;

	filesys_info->MaxFds = MAX_NUM_FILES;
	for (i = 0; i < MAX_NUM_FILES; i++) {
		if (files[i].ino == 0) count++;
	}
	filesys_info->FreeFds    = count;
	filesys_info->MaxVolumes = MAX_NUM_FS;
	for (i = 0, count = 0; i < MAX_NUM_FS; i++) {
		if (!filesystems[i].devname) count++;
	}
	filesys_info->FreeVolumes = count;
	return OS_FS_SUCCESS;
}
