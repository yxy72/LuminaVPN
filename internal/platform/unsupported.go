//go:build !darwin && !windows

package platform

import "errors"

func Supported() bool { return false }
func Discover() (Network, error) {
	return Network{}, errors.New("native networking is enabled on macOS only in this preview")
}

func Candidates() (string, string, error) { return "", "", errors.New("native networking unavailable") }
func ForeignVPN() bool                    { return false }
func CheckConflicts(Network) error        { return errors.New("native networking unavailable") }
