FIND_PACKAGE(BISON)
FIND_PACKAGE(FLEX)

BISON_TARGET(GRAMMAR grammar.y  ${CMAKE_CURRENT_BINARY_DIR}/grammar.c)
FLEX_TARGET(SCANNER scanner.l ${CMAKE_CURRENT_BINARY_DIR}/scanner.c)
ADD_FLEX_BISON_DEPENDENCY(SCANNER GRAMMAR)

ADD_EXECUTABLE(tinyproxy
	${BISON_GRAMMAR_OUTPUTS}
	${FLEX_SCANNER_OUTPUTS}
	acl.c
	anonymous.c
	proctitle.c
	buffer.c
	child.c
	conns.c
	daemon.c
	hashmap.c
	heap.c
	ftp.c
	htmlerror.c
	http_message.c
	log.c
	network.c
	reqs.c
	sock.c
	stats.c
	text.c
	tinyproxy.c
	utils.c
	writev.c
	vector.c
	filter.c
)
