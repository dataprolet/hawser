package pool

import (
	"sync"
)

// BufferSize is the default buffer size for streaming operations
const BufferSize = 4096

// bufferPool is a sync.Pool for reusing byte buffers in high-throughput operations
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, BufferSize)
		return &buf
	},
}

// GetBuffer returns a buffer from the pool
func GetBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool
func PutBuffer(buf *[]byte) {
	if buf == nil {
		return
	}
	// Only return buffers of the expected size to the pool
	if cap(*buf) == BufferSize {
		bufferPool.Put(buf)
	}
}
