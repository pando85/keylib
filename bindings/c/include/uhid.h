#include <stdint.h>

int uhid_open();
int uhid_read_packet(int, char*);
int uhid_write_packet(int, char*, size_t);
void uhid_close(int);
