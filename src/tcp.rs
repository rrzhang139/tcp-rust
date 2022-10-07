use std::{io, time};

pub enum State {
    SynRecvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    // if it means the connection is not established yet, then its NOT synchronized. SynRecvd is not est since sender has not gotten an ack back yet after receiver accepts
    fn is_synchronized(&mut self) -> bool {
        match *self {
            Self::SynRecvd => false,
            Self::Estab | Self::FinWait1 | Self::TimeWait | Self::FinWait2 => true,
        }
    }
}

// TCB: state that must be kept for every connection. Deals with seq numbers and acks
// IN SEND BUFFER
// send sequence space: the bytes of data we have sent. Points in that data stream: 1) UNA what we have sent but not ack 2) where we send next time we send 3) window: how much we are allowed to send
// contains: initial seq number
// how much we are allowed to send = the amount we have sent but not ack + size of window
// IN RECEIVE BUFFER
//recv sequence space
// 1) NEXT: what we expect to be next byte to recv 2) window
// contains: initial seq number
pub struct Connection {
    // NEED TO KEEP STATE FOR EVERY CONNECTION
    state: State, //state the connection is in
    // keep all bytes a user wants to write, remove them as needed
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header, // we use the same ip header everytime
    tcp: etherparse::TcpHeader, // buffer tcp header
}

struct SendSequenceSpace {
    // send unacknowledged
    una: u32,
    // send next
    nxt: u32,
    // send window
    wnd: u16,
    // send urgent pointer
    up: bool,
    // segment sequence number used for last window update
    w1l: usize,
    // segment acknowledgment number used for last window update
    w2l: usize,
    // initial send sequence number
    iss: u32,
}

// Buffer, TCB
struct RecvSequenceSpace {
    // recv next
    nxt: u32,
    // recv window.
    wnd: u16,
    // recv urgent pointer
    up: bool,
    // initial recv sequence number
    iss: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        eprintln!(
            "{}:{} -> {}:{} {}b of tcp",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len()
        );

        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
            state: State::SynRecvd, // we received a SYN from the command we sent "nc IP ..."
            send: SendSequenceSpace {
                // decide on what we are sending them: send seq space
                iss,
                una: iss,
                nxt: iss,
                wnd,
                up: false,
                w1l: 0,
                w2l: 0,
            },
            recv: RecvSequenceSpace {
                // keep track of sender info SINCE WE ARE RECEIVER
                nxt: tcph.sequence_number() + 1, // we received the syn, so we increment nxt for them
                wnd: tcph.window_size(),         // track other sides window
                iss: tcph.sequence_number(),
                up: false,
            },
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
            //create a new ipv4 header, to send an ack back to port.
            // there is no payload
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                0x06,
                [
                    iph.destination()[0],
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            ),
        };
        c.tcp.syn = true; // sending own syn
        c.tcp.ack = true; // acking our syn
                          // setting ip payload to be size of tcp header len

        c.write(nic, &[])?;
        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        // send the packets out
        // buffer
        let mut buf = [0u8; 1500];
        // write headers
        self.tcp.sequence_number = self.send.nxt; // the next sequence number the other side should expect
        self.tcp.acknowledgment_number = self.recv.nxt;

        //cant write out more than size of buffer
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + payload.len() as usize,
        );
        self.ip
            .set_payload_len(size - self.ip.header_len() as usize);

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");

        use std::io::Write;
        // create slice of entire buffer
        let mut unwritten = &mut buf[..]; // need a & to a slice
                                          // we make it mutable since a slice is &str,
        self.ip.write(&mut unwritten); // write ip header in buf. This also
        self.tcp.write(&mut unwritten); // write tcp header in buf. IP header before tcp since IP is layer above
        let payload_bytes = unwritten.write(payload)?; // writing as much of payload we can to buf. Might not be whole payload
        let unwritten = unwritten.len(); // the size left we have unwritten
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32); // add payload bytes to seq number to expect next
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false; // reset syn bit back to false
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false; // reset fin bit back to false
        }
        nic.send(&buf[..buf.len() - unwritten]); // write headers ip and tcp
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // TCB: valid segment check. bytes in packet including SYN are within the range of things we are willing to accept
        // we check the first byte in seg
        // RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND
        // or check last byte in seg. If one of them contains something in the window, we will accept those bytes so sender doesnt have to send again.
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        // EX: say segment was only 1 byte in beginning, but rcv.nxt is past it so its not within, but we check with last byte to make sure whole segment got received, and it is past the nxt. Therefore, we accept it.
        // same thing if the last byte is past the window, so its expired, but the segment beginnign is within, so its valid!
        //
        // if segment seq # is less than nxt, then it means we already accepted it.
        // if rcv.nxt + rcv.wnd is the end slot where we expire the seq # potential to be received. So if less than seq #, we reject
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        }
        if tcph.syn() {
            slen += 1;
        }
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        // check if segment length is 0
        let okay = if slen == 0 {
            // must be an ack and segment be 0
            if self.recv.wnd == 0 {
                // only valid if the next seq num to rec is the seq in the segment. This is exception for rst and URG manips
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !Self::is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !Self::is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !Self::is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            eprint!("NOT OKAY");
            self.write(nic, &[]);
            return Ok(());
        }

        //we recieved at least one byte, next we expect to receive is the seq num of first byte + length of seg == next seq number
        self.recv.nxt = seqn.wrapping_add(slen); // TODO: if not acceptable, send ack
                                                 // TODO: make sure this gets acked

        if !tcph.ack() {
            // if the ACK bit is off drop the segment and return
            return Ok(());
        }

        //only do ack check for SynRecvd and Estab
        let ackn = tcph.acknowledgment_number();
        // if connection is already established, you need to change state
        if let State::SynRecvd = self.state {
            // receiver received a syn, so sender can establish by sending back an ack to finish handshake
            if Self::is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have acked our syn, since we detected at least 1 acked byte, and we have only sent one byte (the syn)
                self.state = State::Estab;
            } else {
                // TODO: RST <SEQ=SEG.ACK><CTL=RST>
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            // state is already established and no more syns
            // acceptable ack check. Every packet has a ack. Valid ack depends if its within a window allowing new reception. oldest unacknowledge < ack num <= next seq num to send
            // next seq num to send cannot be less than ack, bc you havent sent it yet so how do u get ack in future
            // SND.UNA < SEG.ACK =< SND.NEXT
            // wrapping_add: just add 1 bc nxt is inclusive and if it overflows we wrap. We add 1 to it bc our checks dont check inclusivity
            if !Self::is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                return Ok(());
            }
            self.send.una = ackn; // basically acknowledge the prev una
                                  // TODO
            assert!(data.is_empty());

            if let State::Estab = self.state {
                eprintln!("ESTABISHED");
                dbg!(tcph.fin());
                dbg!(self.tcp.fin);

                // TODO: needs to be stored in retransmission queue. Set for last data packet that is sent out
                // terminate the connection!
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }

        if let State::FinWait1 = self.state {
            // check have ack for syn initialy sent and fin we sent following it.
            // una should be the byte following that
            dbg!(self.send.una);
            dbg!(self.send.iss);
            if self.send.una == self.send.iss + 1 {
                // our FIN has been acked!
                self.state = State::FinWait2;
            }
        }

        // check fin bit
        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // done with connection!
                    // they ack our finish
                    eprintln!("Fin reset?");
                    dbg!(self.tcp.fin);
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => {}
            }
        }

        // if let State::FinWait2 = self.state {
        //     // if receiver gets tcp with fin and state is in FinWait1, we need to send ack back
        //     // if theres any data in packet and its not final packet, we just dont do anything
        //     if !tcph.fin() || !data.is_empty() {
        //         unimplemented!();
        //     }
        //     // must have acked our fin, since we detected at least 1 acked byte, and we have only sent one byte (the fin)
        //     // Case 2: TCP receives FIN from network. Return an ACK and tell them conn is closing.
        //     // must receive a fin
        //     self.tcp.fin = false;
        //     self.write(nic, &[]); // ack that fin
        //     self.state = State::Closing;
        // }

        Ok(())
    }

    fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
        use std::cmp::Ordering;
        match start.cmp(&x) {
            Ordering::Equal => return false,
            Ordering::Less => {
                // we have:
                //    |----------s-------x----------|
                //  x is between S and E iff !(S <= E <= x)
                //    |----------s-------x----E------|
                //    |-------E---s-------x----------|
                //  but not in these cases
                //    |----------s---E----x----------|
                //    |----------s-------x----------|
                //               ^E
                //    |----------s-------x----------|
                //                       ^E
                if end >= start && end < x {
                    return false;
                }
            }
            Ordering::Greater => {
                // E MUST be LESS than S and MORE than X
                // X < E < S
                if end >= x && end < start {
                } else {
                    return false;
                }
            }
        }
        true
    }
}
