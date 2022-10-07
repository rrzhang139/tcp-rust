use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use trust::tcp;

struct TcpState {}

// keep conn state from quad to a tcp state.
//  tcp.rs will have state
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dest: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    // create a new tun interface via the tun_tap crate. We can receive messages from tun0 (192.168.0.1)
    let mut nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        // converting the array stream buf from the tun interface into native endian integer
        // Frame format:
        //  First 2 bytes: Flags
        //  Third and Fourth Byte: Proto
        //  Rest: Raw Protocol (IP, IPV6, etc) frame
        // let flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let proto = u16::from_be_bytes([buf[2], buf[3]]); // proto = 0x0800 = IPv4 packet
        // if proto != 0x0800 {
        //     // no ipv4
        //     continue;
        // }

        // Packet format: [   IP Header    |      TCP Header     |     payload    ]
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dest = iph.destination_addr();
                let proto = iph.protocol();
                if proto != 0x06 {
                    // not tcp
                    continue;
                }

                // read buf up to nbytes, which is total size of the packet + header
                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        use std::collections::hash_map::Entry;
                        // if we get a packet, we ALWAYS deal with them. assume every port is listening. none CLOSED
                        // either receive SYN, send an ACK
                        // either we get closed on other side, or send ACK to establish connection
                        let data = iph.slice().len() + tcph.slice().len();
                        //when we get tcp packet
                        // if already quad, create a reference to state. If not, creates a new one
                        // a mutable ref to a state

                        match connections.entry(Quad {
                            src: (src, tcph.source_port()),
                            dest: (dest, tcph.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => {
                                c.get_mut()
                                    .on_packet(&mut nic, iph, tcph, &buf[data..nbytes])?;
                                // point where headers stop to the rest of packet is the content of packet
                            }
                            Entry::Vacant(e) => {
                                if let Some(c) = tcp::Connection::accept(
                                    &mut nic,
                                    iph,
                                    tcph,
                                    &buf[data..nbytes],
                                )? {
                                    e.insert(c);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring non ipv4 header {:?}", e);
            }
        }
    }
    Ok(())
}
