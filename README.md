# pam_biometrics

PAM module for Touch ID and Face ID authentication.

## Options

| Argument | Description |
| -------- | ----------- |
| timeout=*seconds* | Sets the timeout for the authentication prompt |
| prompt=*text* | Sets the prompt text (TouchID only) |
| disableonssh | disables the module in SSH environments |
| allowwatch | Allows Apple Watch authentication (macOS only) |

## Examples

```conf
# /etc/pam.d/sudo
# sudo: auth account password session
auth       sufficient     pam_biometrics.so
auth       required       pam_unix.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```

```conf
# /etc/pam.d/sshd
# sshd: auth account password session
auth       required       pam_biometrics.so timeout=30 prompt=Find\ your\ phone\ ijdot
auth       required       pam_unix.so try_first_pass
account    required       pam_nologin.so
# account    required       pam_sacl.so sacl_service=ssh
account    required       pam_unix.so
password   required       pam_unix.so
session    required       pam_permit.so
# session    required       pam_launchd.so
```
