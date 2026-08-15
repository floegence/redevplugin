//go:build windows

package resourceio

// Winsock reports an oversized datagram as WSAEMSGSIZE from ReadMsgUDP.
func datagramTruncated(int) bool { return false }
