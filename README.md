# OpenSSL Hook

## Build and Example
1. `yum install openssl-devel` for `centos/rhel/fedora` or `apt install libssl-dev` for `debian/ubuntu/kali`

2. `make`

3. 
```shell
LD_PRELOAD=\`pwd\`/libhook.so HOOK_LOG=/dev/stderr openssl enc -in /proc/cpuinfo -out test.bin -e -aes-256-cbc -pass pass:123123 -p -v`
This will encrypt `/proc/cpuinfo` and output to `test.bin`, You can see some log from log.
```

> Default log file is `hooklog.log`

## Example

```shell
root@localhost:~/pt # LD_PRELOAD=`pwd`/libhook.so HOOK_LOG=/dev/stderr openssl enc -in /proc/cpuinfo -out test.bin -e -aes-256-cbc -pass pass:123123 -p -v
[HOOK] redirect session 0xb0f2 output to /dev/stderr
[HOOK][b0f2][hook_init][   INIT] ===================
[HOOK][b0f2][EVP_CipherInit_ex][   FUNC]
[HOOK][b0f2][EVP_CipherInit_ex][ (null)] Encrypt
[HOOK][b0f2][EVP_CipherInit_ex][    key]
[HOOK][b0f2][EVP_CipherInit_ex][     iv]
[HOOK][b0f2][EVP_CipherInit_ex][   FUNC]
[HOOK][b0f2][EVP_CipherInit_ex][ (null)] Encrypt
[HOOK][b0f2][EVP_CipherInit_ex][    key] 90fadbd9920cc9e67fc61430b72903682c331cb1f3369f93590248bfc8302078
[HOOK][b0f2][EVP_CipherInit_ex][     iv] acf90f44411ebe8c8de4d877158e21e1f4a4b0b18fe40f2b4060b8
salt=F4A4B0B18FE40F2B
key=90FADBD9920CC9E67FC61430B72903682C331CB1F3369F93590248BFC8302078
iv =ACF90F44411EBE8C8DE4D877158E21E1
bytes read   :    3892
bytes written:    3920
```
## InspiredBy

https://github.com/gaul/awesome-ld-preload

https://github.com/sebcat/openssl-hook
