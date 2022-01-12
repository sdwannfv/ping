// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || linux || solaris
// +build darwin linux solaris

package ipv4

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/net/internal/iana"
	"golang.org/x/net/internal/socket"

	"golang.org/x/sys/unix"
)

func marshalPacketInfo(b []byte, cm *ControlMessage) []byte {
	m := socket.ControlMessage(b)
	m.MarshalHeader(iana.ProtocolIP, unix.IP_PKTINFO, sizeofInetPktinfo)
	if cm != nil {
		pi := (*inetPktinfo)(unsafe.Pointer(&m.Data(sizeofInetPktinfo)[0]))
		if ip := cm.Src.To4(); ip != nil {
			copy(pi.Spec_dst[:], ip)
		}
		if cm.IfIndex > 0 {
			pi.setIfindex(cm.IfIndex)
		}
	}
	return m.Next(sizeofInetPktinfo)
}

func parsePacketInfo(cm *ControlMessage, b []byte) {
	pi := (*inetPktinfo)(unsafe.Pointer(&b[0]))
	cm.IfIndex = int(pi.Ifindex)
	if len(cm.Dst) < net.IPv4len {
		cm.Dst = make(net.IP, net.IPv4len)
	}
	copy(cm.Dst, pi.Addr[:])
}

func marshalTimeStamp(b []byte, cm *ControlMessage) []byte {
	m := socket.ControlMessage(b)
	m.MarshalHeader(unix.SOL_SOCKET, unix.SO_TIMESTAMP, 16)
	if cm != nil {
		tv := (*timeVal)(unsafe.Pointer(&m.Data(16)[0]))
		tv.tvSec = cm.Tv.Unix()
		tv.tvUsec = cm.Tv.UnixMicro() % 1000000
	}
	return m.Next(16)
}

func parseTimeStamp(cm *ControlMessage, b []byte) {
	tv := (*timeVal)(unsafe.Pointer(&b[0]))
	cm.Tv = time.Unix(tv.tvSec, tv.tvUsec*1000)
	fmt.Printf("tv_sec %d, tv_usec %d\n", tv.tvSec, tv.tvUsec)
}
