//! An API to be called from user-mode - this will be dealt with via IOCTLs, but if Msft implemented
//! this then it could be done as system calls.

// /// Registers an address to notify the driver of if a write event takes place, such as with
// /// nt
// /// actually im not sure there is much point as the userland app can record this themselves and check
// /// on return...?
// pub fn register_address_write_hook(
//     //..
//     ) {

//     }
