# WinSysProgExperiments: Windows system programming experiments (User Mode)

Experiments to learn more about Windows Internals,
Most projects here will be focused towards OOP in Modern C++.

Main objectives:

-Services, registry, file system API. 
    -Known techniques for evading (Alternate data streams, Service for persistance)
    
-Process/thread internals and Memory management:
      -Thread pool, Sections, Mapped files (PE).
      -Loader initialization hooking.

-IPC and syncronization primitives (Pipes, shared mem, events, mailslots, etc).
     -Basic server-client communication.

-Exception handling (SEH/VEH): Redirect execution with the Dridex way. 

-COM/RPC, Security API: 
      -Mainly privilege escalation.
