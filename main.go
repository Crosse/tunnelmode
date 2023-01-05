package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_tunnel.h#L12
	SIOCGETTUNNEL = unix.SIOCDEVPRIVATE + 0
	SIOCCHGTUNNEL = unix.SIOCDEVPRIVATE + 3
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <interface> <mode>\n", os.Args[0])
		os.Exit(1)
	}

	iface := os.Args[1]
	proto, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot convert %s to a number: %v\n", os.Args[2], err)
		os.Exit(1)
	}
	if proto > math.MaxUint8 {
		fmt.Fprintf(os.Stderr, "mode/proto must be less than %d\n", math.MaxUint8)
	}

	if err = setInterfaceProto(iface, uint8(proto)); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func setInterfaceProto(iface string, proto uint8) error {
	if len(iface) >= unix.IFNAMSIZ {
		return fmt.Errorf("interface name too long")
	}

	// can't use unix.Ifreq because it doesn't expose a way to set the data to a pointer.
	ifreq := struct {
		ifr_name [unix.IFNAMSIZ]byte
		ifr_data [24]byte
	}{}
	copy(ifreq.ifr_name[:], iface)

	p := struct {
		name        [unix.IFNAMSIZ]byte
		link        int32
		proto       uint8
		encap_limit uint8
		hop_limit   uint8
		flowinfo    uint32
		flags       uint32
		laddr       [16]byte
		raddr       [16]byte
		i_flags     uint16
		o_flags     uint16
		i_key       uint32
		o_key       uint32
	}{}

	*(*uintptr)(unsafe.Pointer(&ifreq.ifr_data[:8][0])) = uintptr(unsafe.Pointer(&p))

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return fmt.Errorf("socket(): %w\n", err)
	}
	defer syscall.Close(fd)

	r, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		SIOCGETTUNNEL,
		uintptr(unsafe.Pointer(&ifreq)),
	)
	if r < 0 || errno != 0 {
		return fmt.Errorf("ioctl(SIOCGETTUNNEL): %w", syscall.Errno(errno))
	}

	p.proto = proto

	r, _, errno = syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		SIOCCHGTUNNEL,
		uintptr(unsafe.Pointer(&ifreq)),
	)

	if r < 0 || errno != 0 {
		return fmt.Errorf("ioctl(SIOCCHGTUNNEL): %w", syscall.Errno(errno))
	}

	return nil
}
