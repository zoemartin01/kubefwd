package fwdhost

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/txn2/txeh"
)

// BackupHostFile will write a backup of the pre-modified host file
// the users home directory, if it does already exist.
func BackupHostFile(hostFile *txeh.Hosts) (string, error) {
	homeDirLocation, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Create a backup filename based on the original file path
	var backupHostsPath string
	if hostFile.WriteFilePath == "/etc/hosts" {
		backupHostsPath = homeDirLocation + "/hosts.original"
	} else {
		// For custom hosts files, create backup with a sanitized name
		backupHostsPath = homeDirLocation + "/kubefwd_hosts_backup_" + sanitizeFilename(hostFile.WriteFilePath)
	}
	if _, err := os.Stat(backupHostsPath); os.IsNotExist(err) {
		from, err := os.Open(hostFile.WriteFilePath)
		if err != nil {
			return "", err
		}
		defer func() { _ = from.Close() }()

		to, err := os.OpenFile(backupHostsPath, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer func() { _ = to.Close() }()

		_, err = io.Copy(to, from)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Backing up your original hosts file %s to %s\n", hostFile.WriteFilePath, backupHostsPath), nil
	}

	return fmt.Sprintf("Original hosts backup already exists at %s\n", backupHostsPath), nil
}

// sanitizeFilename converts a file path to a safe filename for backup purposes
func sanitizeFilename(path string) string {
	// Get base filename and replace unsafe characters
	base := filepath.Base(path)
	if base == "." || base == "/" || base == "" {
		base = "custom_hosts"
	}
	
	// Replace path separators and other unsafe characters with underscores
	unsafe := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", " "}
	sanitized := base
	for _, char := range unsafe {
		sanitized = strings.ReplaceAll(sanitized, char, "_")
	}
	
	return sanitized + ".original"
}
