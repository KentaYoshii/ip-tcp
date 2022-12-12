package socket

type CircularBuffer struct {
	buffer []byte
	len    uint32
}

/*
* This function creates a circular buffer
 */
func CreateCircularBuffer(len uint32) *CircularBuffer {
	return &CircularBuffer{
		buffer: make([]byte, len),
		len:    len,
	}
}

/*
* This function puts data in the circular buffer at index
* This assumes that the data is less than the max capacity of the buffer
 */

func (cb *CircularBuffer) Put(data []byte, index uint32) {
	dataLen := uint32(len(data))
	convertedIndex := index % cb.len

	if convertedIndex+dataLen > cb.len {
		// data is split
		overflow := convertedIndex + dataLen - cb.len
		copy(cb.buffer[convertedIndex:], data[:dataLen-overflow])
		copy(cb.buffer[:overflow], data[dataLen-overflow:])
	} else {
		// data is contiguous
		copy(cb.buffer[convertedIndex:convertedIndex+uint32(dataLen)], data)
	}
}

/*
 * This function gets data in the circular buffer at index range
 */
func (cb *CircularBuffer) Get(index uint32, size uint32) []byte {
	if size == 0 {
		return []byte{}
	}

	// convert to circular buffer indices
	convertedIndex := index % cb.len
	if convertedIndex+size > cb.len {
		// data is split
		data := cb.buffer[convertedIndex:]
		overflowIndex := convertedIndex + size - cb.len
		data = append(data, cb.buffer[:overflowIndex]...)
		return data
	} else {
		// data is contiguous
		return cb.buffer[convertedIndex : convertedIndex+size]
	}
}
