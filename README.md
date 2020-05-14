# dtrace_nfsstats
Dtrace script for NFS Server requests per Client IP
Tested on FreeNAS 11.2

This is my first Dtrace script and is supplied as-is, use at your own risk.


Many thanks to @FreeBSDFrau, Base on her Dtrace oneliner below.

sudo dtrace -n 'inline string SA2IP[char data[14]] = strjoin(strjoin(strjoin(lltostr(data[2] & 0xFF), "."), strjoin(lltostr(data[3] & 0xFF), ".")), strjoin(strjoin(lltostr(data[4] & 0xFF), "."), lltostr(data[5] & 0xFF))); fbt:kernel:nfsrvd_read:entry, fbt:kernel:nfsrvd_write:entry { @[probefunc, SA2IP[args[0]->nd_nam->sa_data]] = count() }'


