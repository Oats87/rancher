package planner

import (
	"errors"
	"fmt"
)

// errWaiting will cause a re-enqueue of the object being processed
type errWaiting string

func (e errWaiting) Error() string {
	return string(e)
}

// errWaitingf renders an error of type errWaiting that will cause a re-enqueue of the object being processed
func errWaitingf(format string, a ...interface{}) errWaiting {
	return errWaiting(fmt.Sprintf(format, a...))
}

func IsErrWaiting(err error) bool {
	var errWaiting errWaiting
	return errors.As(err, &errWaiting)
}

// errIgnore will not cause a re-enqueue of the object being processed
type errIgnore string

func (e errIgnore) Error() string {
	return string(e)
}

// errIgnoref renders an error of type errIgnore that will cause a re-enqueue of the object being processed
func errIgnoref(format string, a ...interface{}) errIgnore {
	return errIgnore(fmt.Sprintf(format, a...))
}

// ignoreErrors accepts two errors. If the err is type errIgnore, it will return (err, nil) if firstIgnoreErr is nil or (firstIgnoreErr, nil).
// Otherwise, it will simply return (firstIgnoreErr, err)
func ignoreErrors(firstIgnoreError error, err error) (error, error) {
	var errIgnore errIgnore
	if errors.As(err, &errIgnore) {
		if firstIgnoreError == nil {
			return err, nil
		}
		return firstIgnoreError, nil
	}
	return firstIgnoreError, err
}
