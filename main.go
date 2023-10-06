//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"
)

func Usage() {
	exe := filepath.Base(os.Args[0])
	fmt.Printf("change the owner of a file/folder on Windows. Requires Admin privileges (for SeRestorePrivilege).\n")
	fmt.Printf("Usage: %s -p <path to file/folder> -d [<domain>|.] (optional) -u <user or group name>\n", exe)
	flag.PrintDefaults()
	fmt.Printf(`
	examples:
	
	%s c:\file.txt -d . -u Administrator (local user "Administrator")
	%s c:\file.txt -u mydomain\john.doe (domain user)
	%s c:\file.txt -u "john.doe@mydomain.com" (domain user)
	%s c:\file.txt -u "NT AUTHORITY\Authenticated Users" (well known group)
	%s c:\file.txt -d . -u "my-local-group" (local group)
	%s c:\file.txt -u "BUILTIN\Administrators" (local Administrators group on Windows installed in English)
	%s c:\file.txt -u "BUILTIN\Administratoren" (local Administrators group on Windows installed in German)
	
	`, exe, exe, exe, exe, exe, exe, exe)
}

func LookupAccountType(t uint32) string {
	switch t {
	case 1:
		return "User"
	case 2:
		return "Group"
	case 3:
		return "Domain"
	case 4:
		return "Alias"
	case 5:
		return "WellKnownGroup"
	case 6:
		return "DeletedAccount"
	case 7:
		return "Invalid"
	case 8:
		return "Unknown"
	case 9:
		return "Computer"
	case 10:
		return "Label"
	default:
		return "ErrorInvalid"

	}
}

func enablePrivilege(priv string) error {
	return togglePrivilege(priv, false)
}

func disablePrivilege(priv string) error {
	return togglePrivilege(priv, true)
}

func togglePrivilege(priv string, disable bool) error {
	var t windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &t); err != nil {
		return err
	}

	var luid windows.LUID

	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(priv), &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValueW failed, error: %v", err)
	}

	ap := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}

	ap.Privileges[0].Luid = luid

	if disable {
		ap.Privileges[0].Attributes = 0
	} else {
		ap.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	}

	if err := windows.AdjustTokenPrivileges(t, false, &ap, 0, nil, nil); err != nil {
		return fmt.Errorf("AdjustTokenPrivileges failed, error: %v", err)
	}

	return nil
}

func LookupAccount(sid string) (u string, d string, t uint32, err error) {
	sidS, err := syscall.StringToSid(sid)
	if err != nil {
		return "", "", 0, err
	}

	u, d, t, err = sidS.LookupAccount("")
	if err != nil {
		return "", "", 0, err
	}

	return
}

func readOwner(path string) (*windows.SID, error) {
	var owner *windows.SID
	var secDesc windows.Handle

	err := api.GetNamedSecurityInfo(
		path,
		api.SE_FILE_OBJECT,
		api.OWNER_SECURITY_INFORMATION,
		&owner,
		nil,
		nil,
		nil,
		&secDesc,
	)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(secDesc)
	return owner, nil

}

func chown(path string, domain string, user string) error {

	SidAdminUser, _, _, err := windows.LookupSID(domain, user)
	if err != nil {
		return err
	}

	// some docs/examples tell that "SeTakeOwnershipPrivilege" should be used
	// but it seems with that not all SIDs work for setting owner
	// (well known groups did work for me, individual users didn't)
	err = enablePrivilege("SeRestorePrivilege")
	if err != nil {
		return err
	}

	err = api.SetNamedSecurityInfo(
		path,
		api.SE_FILE_OBJECT,
		api.OWNER_SECURITY_INFORMATION,
		SidAdminUser,
		nil,
		0,
		0,
	)

	if err != nil {
		return err
	}

	err = disablePrivilege("SeRestorePrivilege")
	if err != nil {
		return err
	}

	return nil

}

func main() {

	flag.Usage = Usage

	var path string
	var domain string
	var username string

	flag.StringVar(&path, "p", "", "path")
	flag.StringVar(&domain, "d", "", `domain (use "." for local, omit for auto search)`)
	flag.StringVar(&username, "u", "", "owner (user or group name)")

	flag.Parse()

	if path == "" {
		fmt.Fprintln(os.Stderr, "ERR - no path provided")
		flag.Usage()
		os.Exit(1)
	}

	if username == "" {
		fmt.Fprintln(os.Stderr, "ERR - no owner (user or group name) provided")
		flag.Usage()
		os.Exit(1)
	}

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not get local hostname")
	}

	if domain == "." {
		username = hostname + `\` + username

	}

	prevOwner, err := readOwner(path)
	prevSid := prevOwner.String()

	if err != nil {
		fmt.Fprintf(os.Stderr, `ERROR: Could not read previous owner for "%s" to %s\%s: %s`+"\n", path, domain, username, err.Error())
		os.Exit(1)
	}

	pu, pd, pt, err := LookupAccount(prevSid)
	if err != nil {
		fmt.Fprintf(os.Stderr, `WARN: Could not parse previous owner for "%s" to %s\%s: %s`+"\n", path, domain, username, err.Error())
	}

	fmt.Fprintf(os.Stderr, `INFO: prv owner of "%s": %s - %s\%s (%s)`+"\n", path, prevSid, pd, pu, LookupAccountType(pt))

	err = chown(path, domain, username)
	if err != nil {
		fmt.Fprintf(os.Stderr, `ERROR: Could not change owner for "%s" to %s\%s: %s`+"\n", path, domain, username, err.Error())
		os.Exit(1)
	}
	newOwner, err := readOwner(path)
	newSid := newOwner.String()
	if err != nil {
		fmt.Fprintf(os.Stderr, `ERROR: Could not read previous owner for "%s" to %s\%s: %s`+"\n", path, domain, username, err.Error())
		os.Exit(1)
	}

	nu, nd, nt, err := LookupAccount(newSid)
	if err != nil {
		fmt.Fprintf(os.Stderr, `WARN: Could not parse new owner for "%s" to %s\%s: %s`+"\n", path, domain, username, err.Error())
	}

	fmt.Fprintf(os.Stderr, `INFO: new owner of "%s": %s - %s\%s (%s)`+"\n", path, newSid, nd, nu, LookupAccountType(nt))

}
