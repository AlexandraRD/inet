# remove any namespaces (just in case the script was interrupted previously)
sudo ip netns del net0
sudo ip netns del net1

# create namespaces
sudo ip netns add net0
sudo ip netns add net1

# create a virtual ethernet interface in each namespace, assign IP addresses to them
# and bring them up
sudo ip link add veth0 netns net0 type veth peer name veth1 netns net1
sudo ip netns exec net0 ip addr add 192.168.2.1 dev veth0
sudo ip netns exec net1 ip addr add 192.168.2.2 dev veth1
sudo ip netns exec net0 ip link set veth0 up
sudo ip netns exec net1 ip link set veth1 up

# add routes
sudo ip netns exec net0 route add -net 192.168.2.0 netmask 255.255.255.0 dev veth0
sudo ip netns exec net1 route add -net 192.168.2.0 netmask 255.255.255.0 dev veth1

# add delay+loss+corruption to veth0 interface
sudo ip netns exec net0 tc qdisc add dev veth0 root netem loss 1% corrupt 5% delay 10ms 1ms

# run both simulations
inet -u Cmdenv -f receiver.ini -c VethReceiver &
sleep 1
inet -u Cmdenv -f sender.ini -c VethSender
wait

# delete namespaces
sudo ip netns del net0
sudo ip netns del net1
