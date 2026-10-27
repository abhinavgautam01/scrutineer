package worker

import "os"

func openSourceFile(root *os.Root, path string) (*os.File, error) {
	info, err := root.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	// A runner can replace the checked file with a FIFO before the open.
	f, err := root.OpenFile(path, os.O_RDONLY|sourceReadFlags, 0)
	if err != nil {
		return nil, err
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		return nil, os.ErrInvalid
	}
	return f, nil
}
