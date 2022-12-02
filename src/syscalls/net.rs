use crate::net::executor::block_on;
use crate::net::{AsyncSocket, Handle};
use crate::DEFAULT_KEEP_ALIVE_INTERVAL;
use crate::arch;
use httparse::{Error, Request, Status, EMPTY_HEADER};
pub use alloc::vec::Vec;
use hashbrown::HashMap;
use core::str;
use alloc::string::String;

use smoltcp::socket::TcpSocket;
use smoltcp::time::Duration;
use smoltcp::wire::IpAddress;
use wyhash::wyhash;

#[no_mangle]
pub fn sys_tcp_stream_connect(ip: &[u8], port: u16, timeout: Option<u64>) -> Result<Handle, ()> {
	let socket = AsyncSocket::new();
	block_on(socket.connect(ip, port), timeout.map(Duration::from_millis))?.map_err(|_| ())
}

#[no_mangle]
pub fn sys_tcp_stream_read(handle: Handle, buffer: &mut [u8]) -> Result<usize, ()> {
    let socket = AsyncSocket::from(handle);
	block_on(socket.read(buffer), None)?.map_err(|_| ());
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
                arch::output_message_buf(b"got = = =   ");
                arch::output_message_buf(buf.as_bytes());

                arch::output_message_buf(b"\n\n ");
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
                        arch::output_message_buf(b"key =");
                        arch::output_message_buf(key.as_bytes());
                        arch::output_message_buf(b"\n\n\n");
                        arch::output_message_buf(b"value =");
                        arch::output_message_buf(&val[..]);
                        arch::output_message_buf(b"\n\n\n");

                        
                    } else if v.contains("POP") {
                        arch::output_message_buf(b"key =");
                        arch::output_message_buf(v.split(':').nth(1).unwrap().split(',').nth(0).unwrap().as_bytes());
                        arch::output_message_buf(b"\n\n\n");
                        arch::output_message_buf(b"value =");
                        arch::output_message_buf(v.split(':').nth(1).unwrap().split(',').nth(1).unwrap().as_bytes());
                        arch::output_message_buf(b"\n\n\n");
                    }
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

#[no_mangle]
pub fn sys_tcp_stream_write(handle: Handle, buffer: &[u8]) -> Result<usize, ()> {
	let socket = AsyncSocket::from(handle);
	block_on(socket.write(buffer), None)?.map_err(|_| ())
}

#[no_mangle]
pub fn sys_tcp_stream_close(handle: Handle) -> Result<(), ()> {
	let socket = AsyncSocket::from(handle);
	block_on(socket.close(), None)?.map_err(|_| ())
}

//ToDo: an enum, or at least constants would be better
#[no_mangle]
pub fn sys_tcp_stream_shutdown(handle: Handle, how: i32) -> Result<(), ()> {
	match how {
		0 /* Read */ => {
			trace!("Shutdown::Read is not implemented");
			Ok(())
		},
		1 /* Write */ => {
			sys_tcp_stream_close(handle)
		},
		2 /* Both */ => {
			sys_tcp_stream_close(handle)
		},
		_ => {
			panic!("Invalid shutdown argument {}", how);
		},
	}
}

#[no_mangle]
pub fn sys_tcp_stream_set_read_timeout(_handle: Handle, _timeout: Option<u64>) -> Result<(), ()> {
	Err(())
}

#[no_mangle]
pub fn sys_tcp_stream_get_read_timeout(_handle: Handle) -> Result<Option<u64>, ()> {
	Err(())
}

#[no_mangle]
pub fn sys_tcp_stream_set_write_timeout(_handle: Handle, _timeout: Option<u64>) -> Result<(), ()> {
	Err(())
}

#[no_mangle]
pub fn sys_tcp_stream_get_write_timeout(_handle: Handle) -> Result<Option<u64>, ()> {
	Err(())
}

#[deprecated(since = "0.1.14", note = "Please don't use this function")]
#[no_mangle]
pub fn sys_tcp_stream_duplicate(_handle: Handle) -> Result<Handle, ()> {
	Err(())
}

#[no_mangle]
pub fn sys_tcp_stream_peek(_handle: Handle, _buf: &mut [u8]) -> Result<usize, ()> {
	Err(())
}

/// If set, this option disables the Nagle algorithm. This means that segments are
/// always sent as soon as possible, even if there is only a small amount of data.
/// When not set, data is buffered until there is a sufficient amount to send out,
/// thereby avoiding the frequent sending of small packets.
#[no_mangle]
pub fn sys_tcp_set_no_delay(handle: Handle, mode: bool) -> Result<(), ()> {
	let mut guard = crate::net::NIC.lock();
	let nic = guard.as_nic_mut().map_err(drop)?;
	let socket = nic.iface.get_socket::<TcpSocket<'_>>(handle);
	socket.set_nagle_enabled(!mode);

	Ok(())
}

#[no_mangle]
pub fn sys_tcp_stream_set_nonblocking(_handle: Handle, mode: bool) -> Result<(), ()> {
	// non-blocking mode is currently not support
	// => return only an error, if `mode` is defined as `true`
	if mode {
		Err(())
	} else {
		Ok(())
	}
}

#[no_mangle]
pub fn sys_tcp_stream_set_tll(_handle: Handle, _ttl: u32) -> Result<(), ()> {
	Err(())
}

#[no_mangle]
pub fn sys_tcp_stream_get_tll(_handle: Handle) -> Result<u32, ()> {
	Err(())
}

#[cfg(feature = "tcp")]
#[no_mangle]
pub fn sys_tcp_stream_peer_addr(handle: Handle) -> Result<(IpAddress, u16), ()> {
	let mut guard = crate::net::NIC.lock();
	let nic = guard.as_nic_mut().map_err(drop)?;
	let socket = nic.iface.get_socket::<TcpSocket<'_>>(handle);
	socket.set_keep_alive(Some(Duration::from_millis(DEFAULT_KEEP_ALIVE_INTERVAL)));
	let endpoint = socket.remote_endpoint();

	Ok((endpoint.addr, endpoint.port))
}

#[cfg(feature = "tcp")]
#[no_mangle]
pub fn sys_tcp_listener_accept(port: u16) -> Result<(Handle, IpAddress, u16), ()> {
	let socket = AsyncSocket::new();
	let (addr, port) = block_on(socket.accept(port), None)?.map_err(|_| ())?;

	Ok((socket.inner(), addr, port))
}
