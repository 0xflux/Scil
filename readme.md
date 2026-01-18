# System Call Integrity Layer (SCIL)

You can check my blog series out on this [here](https://fluxsec.red/introducing-system-call-integrity-layer)!

The System Call Integrity Layer (SCIL) is designed to be a subsystem within the Kernel which allows an EDR from 
Userland to hook System Calls via Alt Syscalls. The EDR can mark which processes are to be hooked, and can designate
only particular System Service Numbers to hook.

## Demo

Demo of logging syscalls:

<video controls src="img/preview_1.mp4" title="System Call Integrity Layer logging demo"></video>

## Architecture

Architecturally the ideal secure solution to this would look as follows:

![SCIL](img/scil_sk_arch.svg)

The SCIL subsystem then has two main functions when it is in motion:

1) Log system calls and parameters (this is essentially a similar feed to **Events Tracing for Windows: Threat Intelligence**).
2) For processes / system calls which require **deep inspection**:
   1) Suspend the system call temporarily via a synchronisation object.
   2) Communicate with the userland EDR application (EDR no longer in the kernel for this) notifying of a **Pending Syscall Object** (PSO). I haven't yet designed exactly what PSOs will contain / point to.
   3) The user-mode EDR application can then do EDR things it would ordinarily do in **ntdll** etc before allowing a syscall to dispatch.
   4) If the EDR ok's it, signal back to the SCIL subsystem to release the synchronisation object, which allows the syscall to continue dispatching.

The subsystem in practice would also need short-circuits in the event the EDR user-land handler of the malfunctioning / taking too long. Any such cases can then still have telemetry ingest to the EDR via point 1 above with the signal emission. This process in practice would look as follows (for this I am not using [VBS](https://connormcgarr.github.io/hvci/)):

![System Call Integrity Layer](img/scil_micro_architecture.svg)