#include "cFE_util.h"

#include "gen/osapi.h"
#include "gen/common_types.h"

/*
 * Networking API
 */
int32
OS_SocketOpen(uint32 *sock_id, OS_SocketDomain_t Domain, OS_SocketType_t Type)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketClose(uint32 sock_id)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketBind(uint32 sock_id, const OS_SockAddr_t *Addr)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketConnect(uint32 sock_id, const OS_SockAddr_t *Addr, int32 timeout)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketAccept(uint32 sock_id, uint32 *connsock_id, OS_SockAddr_t *Addr, int32 timeout)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketRecvFrom(uint32 sock_id, void *buffer, uint32 buflen, OS_SockAddr_t *RemoteAddr, int32 timeout)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketSendTo(uint32 sock_id, const void *buffer, uint32 buflen, const OS_SockAddr_t *RemoteAddr)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketGetIdByName(uint32 *sock_id, const char *sock_name)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketGetInfo(uint32 sock_id, OS_socket_prop_t *sock_prop)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketAddrInit(OS_SockAddr_t *Addr, OS_SocketDomain_t Domain)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketAddrToString(char *buffer, uint32 buflen, const OS_SockAddr_t *Addr)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketAddrFromString(OS_SockAddr_t *Addr, const char *string)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketAddrGetPort(uint16 *PortNum, const OS_SockAddr_t *Addr)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_SocketAddrSetPort(OS_SockAddr_t *Addr, uint16 PortNum)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

/*
 * OS_NetworkGetID is currently [[deprecated]] as its behavior is
 * unknown and not consistent across operating systems.
 */
int32
OS_NetworkGetID(void)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}

int32
OS_NetworkGetHostName(char *host_name, uint32 name_len)
{
	PANIC("Unimplemented method!"); /* TODO: Implement me! */
	return 0;
}
