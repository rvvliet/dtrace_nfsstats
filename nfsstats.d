#!/usr/sbin/dtrace -s
/*
 * NFS Server read/write requests by Client IP
 * Create by Richard van Vliet
 *
 * Tested on FreeNAS 11.2
 * 
 * Made possible by twitter example of @FreeBSDFrau
 */

#pragma D option quiet

/* Convert sockaddr to readable IP */
inline string SA2IP[char data[14]] = 
	strjoin(strjoin(strjoin(lltostr(data[2] & 0xFF), "."), 
		strjoin(lltostr(data[3] & 0xFF), ".")), 
		strjoin(strjoin(lltostr(data[4] & 0xFF), "."), 
			lltostr(data[5] & 0xFF))
		);


dtrace:::BEGIN
{
	printf("Tracing NFS Server requests...  Hit Ctrl-C to end.\n");
}

fbt:kernel:nfsrvd_read:entry, fbt:kernel:nfsrvd_write:entry
{
	@count[SA2IP[args[0]->nd_nam->sa_data], probefunc] = count()
}

tick-2sec
{
	#printf("%-16s %16s\n", "CLIENT", "COUNT");
	#printa("%-16s %-16s\n", @);
	printa(@count);
}


dtrace:::END
{
	#trunc(@, 10);
	#printf("TOP 10 NFS Client requests :\n\n");
	#printf("%-16s %16s\n", "CLIENT", "COUNT");
	#printa("%-16s %-16s\n", @count);
	printa(@count);
}

