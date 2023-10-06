# ownerly

chown for windows

CLI tool to change the owner of a file/folder on Windows. Requires Admin privileges (for SeRestorePrivilege).

## usage
```
ownerly.exe -p <path to file/folder> -d [<domain>|.] (optional) -u <user or group name>

  -d string
        domain (use "." for local, omit for auto search)
  -p string
        path
  -u string
        owner (user or group name)
```

## examples

local user "Administrator"

```
ownerly.exe c:\file.txt -d . -u Administrator
```

domain user
```
ownerly.exe c:\file.txt -u mydomain\john.doe
```

domain user
```
ownerly.exe c:\file.txt -u "john.doe@mydomain.com"
```

well known group
```
ownerly.exe c:\file.txt -u "NT AUTHORITY\Authenticated Users"
```

local group
```
ownerly.exe c:\file.txt -d . -u "my-local-group"
```

local Administrators group on Windows installed in English
```
ownerly.exe c:\file.txt -u "BUILTIN\Administrators"
```

local Administrators group on Windows installed in German
```
ownerly.exe c:\file.txt -u "BUILTIN\Administratoren"
```