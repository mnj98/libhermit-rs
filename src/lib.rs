//! First version is derived and adapted for HermitCore from
//! Philipp Oppermann's excellent series of blog posts (<http://blog.phil-opp.com/>)
//! and Eric Kidd's toy OS (<https://github.com/emk/toyos-rs>).

#![warn(rust_2018_idioms)]
#![warn(unsafe_op_in_unsafe_fn)]
#![warn(clippy::transmute_ptr_to_ptr)]
#![allow(clippy::missing_safety_doc)]
#![allow(incomplete_features)]
#![feature(abi_x86_interrupt)]
#![feature(allocator_api)]
#![feature(atomic_mut_ptr)]
#![feature(asm_const)]
#![feature(const_mut_refs)]
#![feature(linked_list_cursors)]
#![feature(naked_functions)]
#![feature(new_uninit)]
#![feature(specialization)]
#![feature(core_intrinsics)]
#![feature(alloc_error_handler)]
#![feature(vec_into_raw_parts)]
#![feature(drain_filter)]
#![feature(strict_provenance)]
#![feature(is_some_and)]
#![no_std]
#![cfg_attr(target_os = "none", feature(custom_test_frameworks))]
#![cfg_attr(target_os = "none", cfg_attr(test, test_runner(crate::test_runner)))]
#![cfg_attr(
	target_os = "none",
	cfg_attr(test, reexport_test_harness_main = "test_main")
)]
#![cfg_attr(target_os = "none", cfg_attr(test, no_main))]

#[cfg(all(feature = "newlib", feature = "pci"))]
compile_error!("feature \"newlib\" and feature \"pci\" cannot be enabled at the same time");

// EXTERNAL CRATES
#[macro_use]
extern crate alloc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate log;
#[cfg(not(target_os = "none"))]
#[macro_use]
extern crate std;
#[cfg(target_arch = "aarch64")]
extern crate aarch64;
#[cfg(target_arch = "x86_64")]
extern crate x86;

//extern crate time;

use alloc::alloc::Layout;
use core::alloc::GlobalAlloc;
#[cfg(feature = "smp")]
use core::hint::spin_loop;
#[cfg(feature = "smp")]
use core::sync::atomic::{AtomicU32, Ordering};

use arch::percore::*;
use mm::allocator::LockedHeap;

#[cfg(target_arch = "aarch64")]
use qemu_exit::QEMUExit;

pub(crate) use crate::arch::*;
pub(crate) use crate::config::*;
pub use crate::syscalls::*;

/* start of includes for DB sockets */
//use time::PreciseTime;

use crate::net::executor::block_on;
use crate::net::{AsyncSocket, Handle};
pub use alloc::vec::Vec;
use hashbrown::HashMap;
use core::str;
use alloc::string::String;
use wyhash::wyhash;
use core::{
    ptr,
    sync::atomic::{AtomicU8, Ordering::Relaxed},
};
/* end of include for DB socket */

// Used for integration test status.
#[doc(hidden)]
pub use arch::kernel::is_uhyve as _is_uhyve;

#[macro_use]
mod macros;

#[macro_use]
mod logging;

mod arch;
mod collections;
mod config;
mod console;
mod drivers;
mod env;
pub mod errno;
mod mm;
#[cfg(feature = "tcp")]
mod net;
#[cfg(target_os = "none")]
mod runtime_glue;
mod scheduler;
mod synch;
mod syscalls;

hermit_entry::define_entry_version!();

#[doc(hidden)]
pub fn _print(args: ::core::fmt::Arguments<'_>) {
	use core::fmt::Write;
	crate::console::CONSOLE.lock().write_fmt(args).unwrap();
}

#[cfg(test)]
#[cfg(target_os = "none")]
#[no_mangle]
extern "C" fn runtime_entry(_argc: i32, _argv: *const *const u8, _env: *const *const u8) -> ! {
	println!("Executing hermit unittests. Any arguments are dropped");
	test_main();
	sys_exit(0);
}

//https://github.com/rust-lang/rust/issues/50297#issuecomment-524180479
#[cfg(test)]
pub fn test_runner(tests: &[&dyn Fn()]) {
	println!("Running {} tests", tests.len());
	for test in tests {
		test();
	}
	sys_exit(0);
}

#[cfg(target_os = "none")]
#[test_case]
fn trivial_test() {
	println!("Test test test");
	panic!("Test called");
}

#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Interface to allocate memory from system heap
///
/// # Errors
/// Returning a null pointer indicates that either memory is exhausted or
/// `size` and `align` do not meet this allocator's size or alignment constraints.
///
#[cfg(target_os = "none")]
pub(crate) extern "C" fn __sys_malloc(size: usize, align: usize) -> *mut u8 {
	let layout_res = Layout::from_size_align(size, align);
	if layout_res.is_err() || size == 0 {
		warn!(
			"__sys_malloc called with size {:#x}, align {:#x} is an invalid layout!",
			size, align
		);
		return core::ptr::null::<*mut u8>() as *mut u8;
	}
	let layout = layout_res.unwrap();
	let ptr = unsafe { ALLOCATOR.alloc(layout) };

	trace!(
		"__sys_malloc: allocate memory at {:#x} (size {:#x}, align {:#x})",
		ptr as usize,
		size,
		align
	);

	ptr
}

/// Shrink or grow a block of memory to the given `new_size`. The block is described by the given
/// ptr pointer and layout. If this returns a non-null pointer, then ownership of the memory block
/// referenced by ptr has been transferred to this allocator. The memory may or may not have been
/// deallocated, and should be considered unusable (unless of course it was transferred back to the
/// caller again via the return value of this method). The new memory block is allocated with
/// layout, but with the size updated to new_size.
/// If this method returns null, then ownership of the memory block has not been transferred to this
/// allocator, and the contents of the memory block are unaltered.
///
/// # Safety
/// This function is unsafe because undefined behavior can result if the caller does not ensure all
/// of the following:
/// - `ptr` must be currently allocated via this allocator,
/// - `size` and `align` must be the same layout that was used to allocate that block of memory.
/// ToDO: verify if the same values for size and align always lead to the same layout
///
/// # Errors
/// Returns null if the new layout does not meet the size and alignment constraints of the
/// allocator, or if reallocation otherwise fails.
#[cfg(target_os = "none")]
pub(crate) extern "C" fn __sys_realloc(
	ptr: *mut u8,
	size: usize,
	align: usize,
	new_size: usize,
) -> *mut u8 {
	unsafe {
		let layout_res = Layout::from_size_align(size, align);
		if layout_res.is_err() || size == 0 || new_size == 0 {
			warn!(
			"__sys_realloc called with ptr {:#x}, size {:#x}, align {:#x}, new_size {:#x} is an invalid layout!",
			ptr as usize, size, align, new_size
		);
			return core::ptr::null::<*mut u8>() as *mut u8;
		}
		let layout = layout_res.unwrap();
		let new_ptr = ALLOCATOR.realloc(ptr, layout, new_size);

		if new_ptr.is_null() {
			debug!(
			"__sys_realloc failed to resize ptr {:#x} with size {:#x}, align {:#x}, new_size {:#x} !",
			ptr as usize, size, align, new_size
		);
		} else {
			trace!(
				"__sys_realloc: resized memory at {:#x}, new address {:#x}",
				ptr as usize,
				new_ptr as usize
			);
		}
		new_ptr
	}
}

/// Interface to deallocate a memory region from the system heap
///
/// # Safety
/// This function is unsafe because undefined behavior can result if the caller does not ensure all of the following:
/// - ptr must denote a block of memory currently allocated via this allocator,
/// - `size` and `align` must be the same values that were used to allocate that block of memory
/// ToDO: verify if the same values for size and align always lead to the same layout
///
/// # Errors
/// May panic if debug assertions are enabled and invalid parameters `size` or `align` where passed.
#[cfg(target_os = "none")]
pub(crate) extern "C" fn __sys_free(ptr: *mut u8, size: usize, align: usize) {
	unsafe {
		let layout_res = Layout::from_size_align(size, align);
		if layout_res.is_err() || size == 0 {
			warn!(
				"__sys_free called with size {:#x}, align {:#x} is an invalid layout!",
				size, align
			);
			debug_assert!(layout_res.is_err(), "__sys_free error: Invalid layout");
			debug_assert_ne!(size, 0, "__sys_free error: size cannot be 0");
		} else {
			trace!(
				"sys_free: deallocate memory at {:#x} (size {:#x})",
				ptr as usize,
				size
			);
		}
		let layout = layout_res.unwrap();
		ALLOCATOR.dealloc(ptr, layout);
	}
}

#[cfg(target_os = "none")]
extern "C" {
	static mut __bss_start: usize;
}

#[no_mangle]
extern "C" fn db_tcp_stream_read(socket: &AsyncSocket ,buffer:&mut [u8] ) -> Result<usize, ()> {
    //let socket = AsyncSocket::from(handle);
	//block_on(socket.read(buffer), None)?.map_err(|_| ());
    //let buffer = unsafe { buf as &[u8] };
    let seed = 7;
    let len = buffer.len();
    if len > 3{


                //arch::output_message_buf(buffer);

                let buf = String::from_utf8(buffer.to_vec()).unwrap();
            /*    let buf = "POST / HTTP/1.1
    Host: 10.0.5.3:9975
User-Agent: curl/7.68.0
Accept: /
Content-Length: 8
Content-Type: application/x-www-form-urlencoded
SET:Hi world";
*/
                //arch::output_message_buf(b"got = = =   ");
                //arch::output_message_buf(buf.as_bytes());

                //arch::output_message_buf(b"\n\n ");
                let val = buf.split('\n');
                for v in val {
                    if v.contains("SET") {
                        //for k in v.split(':') {println!("{:#?}", k);}
                        //println!("key = {:#?}", v.split(':').nth(0).unwrap());
                        //println!("value = {:#?}", v.split(':').nth(1).unwrap());
                        /*
                        arch::output_message_buf(b"split val = ");
                        arch::output_message_buf(v.as_bytes());
                        arch::output_message_buf(b"\n\n\n");
                        */
                        let key = v.split(':').nth(1).unwrap().split(',').nth(0).unwrap();
                        let value = v.split(':').nth(1).unwrap().split(',').nth(1).unwrap();
                        let hash: i32 = wyhash(key.as_bytes(), seed) as i32;
                        db::set(hash, value.as_bytes());
                        let val = db::get(hash);
                       /* 
                        arch::output_message_buf(b"key =");
                        arch::output_message_buf(key.as_bytes());
                        arch::output_message_buf(b"\n\n\n");
                        arch::output_message_buf(b"value =");
                        arch::output_message_buf(&val[..]);
                        arch::output_message_buf(b"\n\n\n");
                        */
                        //let new_buf: &[u8] = b"HTTP/1.1 200 OK\nContent-Type: text/plain; charset=UTF-8\nContent-Length: 7\n\nStored\n";
                        let new_buf: &[u8] = b"HTTP/1.1 200 OK\nContent-Type: text/plain; charset=UTF-8\nContent-Length: 7\n\nSTORED\n";
                        let write: usize = block_on(socket.write(new_buf), None).unwrap().unwrap();
                        
                    } else if v.contains("GET") {
                        let key = v.split(':').nth(1).unwrap();
                        //let value = v.split(':').nth(1).unwrap().split(',').nth(1).unwrap();
                        let hash: i32 = wyhash(key.as_bytes(), seed) as i32;
                        let val = db::get(hash);
                        /*
                        arch::output_message_buf(b"key =");
                        arch::output_message_buf(key.as_bytes());
                        arch::output_message_buf(b"\n\n\n");
                        arch::output_message_buf(b"value =");
                        arch::output_message_buf(&val[..]);
                        arch::output_message_buf(b"\n\n\n");
                        */
                        let result = str::from_utf8(&val[..]).unwrap();

                        let text = format!("HTTP/1.1 200 OK\nContent-Type: text/plain; charset=UTF-8\nContent-Length: {}\n\n{}\n", val.len() + 1, result);
                        let new_buf: &[u8] = text.as_bytes();
                        //let new_buf: &[u8] = b"HTTP/1.1 200 OK\nContent-Type: text/plain; charset=UTF-8\nContent-Length: 8\n\nINVALID\n";
                        //arch::output_message_buf(new_buf);
                        let write: usize = block_on(socket.write(new_buf), None).unwrap().unwrap();

                    } 
                    /*else {
                        let new_buf: &[u8] = b"HTTP/1.1 200 OK\nContent-Type: text/plain; charset=UTF-8\nContent-Length: 8\n\nINVALID\n";
                        let write: usize = block_on(socket.write(new_buf), None).unwrap().unwrap();
                    }*/
                }
                //db::set(3, buffer);
                //let got: Vec<u8> = db::get(3);
                //for i in 0..len{arch::output_message_byte(got[i]);}
                //arch::output_message_buf(b" from key ");
                //arch::output_message_byte('3' as u8);
                //arch::output_message_buf(b"\n");
                //arch::output_message_buf(b"buffer is");
                //arch::output_message_buf(buffer);
                
    }
    core::prelude::v1::Ok(len)
}

/// Entry point of a kernel thread, which initialize the libos
#[cfg(target_os = "none")]
extern "C" fn initd(_arg: usize) {
	extern "C" {
		#[cfg(not(test))]
		fn runtime_entry(argc: i32, argv: *const *const u8, env: *const *const u8) -> !;
		#[cfg(feature = "newlib")]
		fn init_lwip();
		#[cfg(feature = "newlib")]
		fn init_rtl8139_netif(freq: u32) -> i32;
	}

	// initialize LwIP library for newlib-based applications
	#[cfg(feature = "newlib")]
	unsafe {
		init_lwip();
		init_rtl8139_netif(processor::get_frequency() as u32);
	}

	if env::is_uhyve() {
		// Initialize the uhyve-net interface using the IP and gateway addresses specified in hcip, hcmask, hcgateway.
		info!("HermitCore is running on uhyve!");
	} else {
		info!("HermitCore is running on common system!");
	}

	// Initialize Drivers
	#[cfg(not(feature = "newlib"))]
	arch::init_drivers();
	#[cfg(feature = "tcp")]
	crate::net::init();

	syscalls::init();

	// Get the application arguments and environment variables.
	#[cfg(not(test))]
	let (argc, argv, environ) = syscalls::get_application_parameters();

	// give the IP thread time to initialize the network interface
	core_scheduler().reschedule();

	#[cfg(not(test))]
    unsafe {
        //let start = PreciseTime::now();
        //let end = PreciseTime::now();
        loop{
                let socket = AsyncSocket::new();
                let port: u16 = 1234;
                //info!("Opening port {:?}", port);
                let (addr, port) =  block_on(socket.accept(port), None).unwrap().unwrap();
                //info!("addr: {:?}", addr);
                //start = PreciseTime::now();
                let microseconds = arch::processor::get_timer_ticks() + arch::get_boot_time();
                let mut buffer: &mut [u8] = &mut [0; 500];
                let read: usize = block_on(socket.read(buffer), None).unwrap().unwrap();
                //const read: *const usize = rd as *const usize;
                //info!("SIZEEEEEEEEEEE: {}", read);
                //const rd: u8 = read;
                /*let cache: &mut [u8] = &mut [0; read];
                    cache[0..read].copy_from_slice(&buffer[0..read]);
                    cache[read] = 0;
                    */
                db_tcp_stream_read(&socket, buffer);
                //let buf = buffer as *mut u32;
                //scheduler::PerCoreScheduler::spawn(db_tcp_stream_read, *buffer as usize, scheduler::task::NORMAL_PRIO, 0, USER_STACK_SIZE);
                //info!("read {:?} bytes", read);
                //TODO: add parsing and database code
                //info!("read: {:?}", buffer);
                //let new_buf: &[u8] = b"HTTP/1.1 200 OK\nContent-Type: text/plain; charset=UTF-8\nContent-Length: 12\n\nFROM-KERNEL\n";
                //let write: usize = block_on(socket.write(new_buf), None).unwrap().unwrap();
                //end = PreciseTime::now();
                let microseconds1 = arch::processor::get_timer_ticks() + arch::get_boot_time();

                info!("execution time = {} useconds \n", (microseconds1 - microseconds));
        }
		// And finally start the application.
		runtime_entry(argc, argv, environ)
	}
/*	unsafe {
		// And finally start the application.
		runtime_entry(argc, argv, environ)
	}
*/
	#[cfg(test)]
	test_main();
}

#[cfg(feature = "smp")]
fn synch_all_cores() {
	static CORE_COUNTER: AtomicU32 = AtomicU32::new(0);

	CORE_COUNTER.fetch_add(1, Ordering::SeqCst);

	while CORE_COUNTER.load(Ordering::SeqCst) != kernel::get_possible_cpus() {
		spin_loop();
	}
}

/// Entry Point of HermitCore for the Boot Processor
#[cfg(target_os = "none")]
fn boot_processor_main() -> ! {
	// Initialize the kernel and hardware.
	arch::message_output_init();
	unsafe {
		logging::init();
	}

	info!("Welcome to HermitCore-rs {}", env!("CARGO_PKG_VERSION"));
	info!("Kernel starts at {:#x}", env::get_base_address());
	info!("BSS starts at {:#x}", unsafe {
		&__bss_start as *const usize as usize
	});
	info!(
		"TLS starts at {:#x} (size {} Bytes)",
		env::get_tls_start(),
		env::get_tls_memsz()
	);

	arch::boot_processor_init();
	#[cfg(target_arch = "aarch64")]
	{
		info!("The current hermit-kernel is only implemented up to this point on aarch64.");
		if env::is_uhyve() {
			syscalls::init();
			syscalls::__sys_shutdown(0);
		} else {
			info!("Attempting to exit via QEMU.");
			info!("This requires that you passed the `-semihosting` option to QEMU.");
			let exit_handler = qemu_exit::AArch64::new();
			exit_handler.exit_success();
		}

		// Compiles up to here - loop prevents linker errors
		loop {}
	}
	scheduler::add_current_core();

	if !env::is_uhyve() {
		arch::boot_application_processors();
	}

	#[cfg(feature = "smp")]
	synch_all_cores();

	#[cfg(feature = "pci")]
	info!("Compiled with PCI support");
	#[cfg(feature = "acpi")]
	info!("Compiled with ACPI support");
	#[cfg(feature = "fsgsbase")]
	info!("Compiled with FSGSBASE support");
	#[cfg(feature = "smp")]
	info!("Compiled with SMP support");

	// Start the initd task.
	scheduler::PerCoreScheduler::spawn(initd, 0, scheduler::task::NORMAL_PRIO, 0, USER_STACK_SIZE);

	let core_scheduler = core_scheduler();
	// Run the scheduler loop.
	core_scheduler.run();
}

/// Entry Point of HermitCore for an Application Processor
#[cfg(all(target_os = "none", feature = "smp"))]
fn application_processor_main() -> ! {
	arch::application_processor_init();
	scheduler::add_current_core();

	info!("Entering idle loop for application processor");

	synch_all_cores();

	let core_scheduler = core_scheduler();
	// Run the scheduler loop.
	core_scheduler.run();
}
