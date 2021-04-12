package star

///////////////////////////////////////////////////////////////////////////////
/********************************** FileID ***********************************/
///////////////////////////////////////////////////////////////////////////////

// The FileID type is a fixed-length byte array which should serve as a UUID
// for each file.
type FileID [9]byte

// Is the FileID an unspecified file?
func (id FileID) IsUnspeecifiedFileID() bool {
	var tmp FileID
	return tmp == id
}

// Formats a FileID into a print-friendly string
func (id FileID) String() string {
	return SqrtedString(id[:], "/")
}
