#ifndef _TINYPROXY_FTP_H_
#define _TINYPROXY_FTP_H_ 1

extern int connect_ftp(struct conn_s *connptr, struct request_s *request,
		       char *errbuf, size_t errbufsize);
extern int send_and_receive(int fd, const char *cmd, char *buf, size_t buflen);
extern ssize_t add_to_buffer_formatted(struct buffer_s *buffptr,
				       unsigned char *inbuf, size_t buflen,
				       struct conn_s *connptr);
extern ssize_t add_ftpdir_header(struct conn_s *connptr);
extern int send_ftp_response(struct conn_s *connptr);

#endif
