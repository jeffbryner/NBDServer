Windows:
    Automatic driver loading: 
	    Get pmem executable: 
            http://code.google.com/p/volatility/source/browse/branches/scudette/tools/windows/winpmem/#winpmem%2Fexecutable%2FRelease
        Load driver: 
            winpmem_1.4.exe -l
        
    

    Manually loading the driver: 
	    from: 
		    http://code.google.com/p/volatility/source/browse/branches/scudette/tools/windows/winpmem/binaries/
	    download either: 
		    winpmem_x64.sys
		    winpmem_x86.sys
	    depending on your target platform.

	    #create a windows service using sc: 
	    #(note the spaces after the parameters ex: type= kernel)
	    sc create pmem type= kernel start= demand binPath= "c:\nbdserver\winpmem_32.sys"
	    [SC] CreateService SUCCESS	

	    #Check the config
	    sc qc pmem
	    [SC] GetServiceConfig SUCCESS

	    SERVICE_NAME: pmem
        	    TYPE               : 1   KERNEL_DRIVER
        	    START_TYPE         : 3   DEMAND_START
        	    ERROR_CONTROL      : 0   IGNORE
        	    BINARY_PATH_NAME   : \??\C:\nbdserver\winpmem_32.sys
        	    LOAD_ORDER_GROUP   :
        	    TAG                : 0
        	    DISPLAY_NAME       : pmem
        	    DEPENDENCIES       :
        	    SERVICE_START_NAME :	


Once installed:	
	# make sure it's running: 
	sc query pmem
	sc start pmem

	#start the nbd server pointing it to the special \\.\pmem file provided by the windows service: 
		NBDServer.exe -c 10.200.1.1 -f \\.\pmem
		
Linux forensic workstation: 
	#connect to the server: 
		nbd-client 10.200.1.11 60000 /dev/nbd1 -b 1024
	#dump memory: 
		dd if=/dev/nbd1 bs=1024 of=mem.dd
	#disconnect: 
		nbd-client -d /dev/nbd1
	#analyze the memory dump: 
		python ./vol.py -f mem.dd --profile=WinXPSP2x86 pslist
