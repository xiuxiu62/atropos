package tun

type Device interface {
	Read(buf []byte) (n int, err error)
	Write(buf []byte) (n int, err error)
	Close() error
	Name() string
}

type Descriptor struct {
	Name string
	CIDR string
}

// func Open(desc Descriptor) (Device, error) {
// 	return open(desc)
// }
