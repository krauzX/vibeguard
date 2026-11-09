package output

import (
	"bufio"
	"errors"
	"io"
	"os"
)

// StdoutPath is the output path that writes a report to standard output.
const StdoutPath = "-"

// createReport streams a report to path, treating "-" as standard output so
// reports can be piped without an intermediate file.
func createReport(path string, write func(io.Writer) error) error {
	if path == StdoutPath {
		buffered := bufio.NewWriter(os.Stdout)
		if err := write(buffered); err != nil {
			return err
		}
		return buffered.Flush()
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}

	buffered := bufio.NewWriter(file)
	if err := write(buffered); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := buffered.Flush(); err != nil {
		return errors.Join(err, file.Close())
	}

	return file.Close()
}
