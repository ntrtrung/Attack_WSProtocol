#ifndef _SERVER_LIB_H_
#define _SERVER_LIB_H_

int create_server(char *ip);
int run_server(int newfd, uint32_t random_t, uint32_t key)
void close_server(int newfd);

#endif
