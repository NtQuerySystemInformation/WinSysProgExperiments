Hook entrypoint function:

I got this idea from reversing Qakbot stager (but this is done in a 32 bit environment)
I want to do it for a 64 bit env.

The process of execution mainly will:
	1.-Create process and suspend main thread.
	2.-Map dll payload in remote process using sections, fix proper relocations for the remote process so it is easier to calculate addresses.
	3.-Calculate the address of the Hook Function in the relocated Dll.
		-Length disassembler for this purpose.
	4.Patch the bytes with WPM/VirtualProtect.