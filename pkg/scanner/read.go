package scanner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/KrauzX/vibeguard/pkg/rules"
)

var errBinaryFile = errors.New("binary file")

const pooledBufferLimit = 1 << 20

var bufferPool = sync.Pool{New: func() any {
	buf := make([]byte, 0, 64*1024)
	return &buf
}}

var foldPool = sync.Pool{New: func() any {
	buf := make([]byte, 0, 64*1024)
	return &buf
}}

func readInto(file *os.File, buf []byte, size, maxSize int64) ([]byte, error) {
	if int64(cap(buf)) < size {
		buf = make([]byte, 0, size+1)
	}

	for {
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}

		n, err := file.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]

		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return nil, err
		}
		if int64(len(buf)) > maxSize {
			return nil, fmt.Errorf("file exceeds %d byte limit", maxSize)
		}
	}
}

func foldFor(active []*rules.Rule, content []byte) ([]byte, *[]byte) {
	for _, r := range active {
		if !r.FoldAnchors() {
			continue
		}
		buf := foldPool.Get().(*[]byte)
		return foldInto(*buf, content), buf
	}

	return nil, nil
}
