Procedure to Build:

1. Create a workspace

		$ mkdir workspace

		$ cd workspace

2. Clone the rusty-hermit repository

		$ git clone https://github.com/hermitcore/rusty-hermit.git

3. Go to the rusty-hermit folder and Clone our unikernel repository

		$ cd rusty-hermit

		$ git clone https://github.com/mnj98/libhermit-rs.git

4. Checkout the os_unikernel branch

		$ cd libhermit-rs

		$ cd git checkout os_unikernel

5. Build the unikernel

		$ cd ../examples/httpd/

		$ cargo build -Z build-std=std,core,alloc,panic_abort --target x86_64-unknown-hermit


Procedure to test:

1. Create a tap interface

		$ sudo ip tuntap add tap10 mode tap

		$ sudo ip addr add 10.0.5.1/24 broadcast 10.0.5.255 dev tap10

		$ sudo ip link set dev tap10 up

		$ sudo bash -c 'echo 1 > /proc/sys/net/ipv4/conf/tap10/proxy_arp'

2. Launch the unikernel using QEMU

		$ sudo qemu-system-x86_64 -cpu qemu64,apic,fsgsbase,rdtscp,xsave,fxsr -enable-kvm -display none -smp 1 -m 1G -serial stdio -device isa-debug-exit,iobase=0xf4,iosize=0x04 -kernel rusty-loader-x86_64 -initrd ./target/x86_64-unknown-hermit/debug/httpd -netdev tap,id=net0,ifname=tap10,script=no,downscript=no,vhost=on -device virtio-net-pci,netdev=net0,disable-legacy=on

3. Run the following commands in another terminal
	
	a. SET operation
	
	
		$ curl --interface tap10 10.0.5.3:1234 -d "SET:os,cs5204:"
	
	
	b. GET operation
		
	
		$ curl --interface tap10 10.0.5.3:1234 -d "GET:os:"
