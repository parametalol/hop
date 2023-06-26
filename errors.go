package main

import (
	"errors"
	"fmt"
)

var errMissingArguments error = errors.New("missing arguments")
var errNoSuchCommand error = errors.New("no such command")

func wrapErr(err error, command string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", command, err)
}

func checkCommand(args, command string) error {
	c, ok := help[command]
	var err error
	if !ok {
		err = errNoSuchCommand
	} else if args == "" && c[0] != "" {
		err = errMissingArguments
	}
	return wrapErr(err, command)
}
