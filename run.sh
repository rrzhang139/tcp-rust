#!/bin/bash
# export CARGO_TARGET_DIR=/home/vagrant/trust/target
# sudo ip addr flush dev tun0 # if RNET Exists
# HOW TO SEND PING PACKET:  ping -I tun0 192.168.0.2
# HOW TO FIJND PID OF PROCESS: pgrep -af target
# sudo ip tuntap add mode tun tun0
# nc 192.168.0.2 443
cargo b --release
ext=$?
if [[ $ext -ne 0 ]]; then
	exit $ext
fi
sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/release/main
$CARGO_TARGET_DIR/release/main &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid