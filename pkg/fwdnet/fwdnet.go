package fwdnet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/txn2/kubefwd/pkg/fwdIp"
)

// ReadyInterface prepares a local IP address on
// the loopback interface.
func ReadyInterface(opts fwdIp.ForwardIPOpts) (net.IP, error) {

	ip, _ := fwdIp.GetIp(opts)

	// lo means we are probably on linux and not mac
	_, err := net.InterfaceByName("lo")
	if err == nil || runtime.GOOS == "windows" {
		// if no error then check to see if the ip:port are in use
		_, err := net.Dial("tcp", ip.String()+":"+opts.Port)
		if err != nil {
			return ip, nil
		}

		return ip, errors.New("ip and port are in use")
	}

	networkInterface, err := net.InterfaceByName("lo0")
	if err != nil {
		return net.IP{}, err
	}

	addrs, err := networkInterface.Addrs()
	if err != nil {
		return net.IP{}, err
	}

	// check the addresses already assigned to the interface
	for _, addr := range addrs {
		var expectedAddr string
		if ip.To4() != nil {
			// IPv4 addresses show up as x.x.x.x/8
			expectedAddr = ip.String() + "/8"
		} else {
			// IPv6 addresses show up as xxxx::x/128
			expectedAddr = ip.String() + "/128"
		}

		// found a match
		if addr.String() == expectedAddr {
			// found ip, now check for unused port
			conn, err := net.Dial("tcp", ip.String()+":"+opts.Port)
			if err != nil {
				return ip, nil
			}
			_ = conn.Close()
		}
	}

	// ip is not in the list of addrs for networkInterface
	cmd := "ifconfig"
	var args []string
	
	if ip.To4() != nil {
		args = []string{"lo0", "alias", ip.String(), "up"}
	} else {
		args = []string{"lo0", "inet6", ip.String() + "/128", "alias"}
	}
	
	if err := exec.Command(cmd, args...).Run(); err != nil {
		fmt.Printf("Cannot ifconfig lo0 %s\n", strings.Join(args[1:], " "))
		fmt.Println("Error: " + err.Error())
		os.Exit(1)
	}

	conn, err := net.Dial("tcp", ip.String()+":"+opts.Port)
	if err != nil {
		return ip, nil
	}
	_ = conn.Close()

	return net.IP{}, errors.New("unable to find an available IP/Port")
}

// RemoveInterfaceAlias can remove the Interface alias after port forwarding.
// if -alias command get err, just print the error and continue.
func RemoveInterfaceAlias(ip net.IP) {
	cmd := "ifconfig"
	var args []string
	
	// Use different syntax for IPv6 vs IPv4 removal
	if ip.To4() != nil {
		// IPv4: ifconfig lo0 -alias 127.1.27.1
		args = []string{"lo0", "-alias", ip.String()}
	} else {
		// IPv6: ifconfig lo0 inet6 fc00::1/128 -alias
		args = []string{"lo0", "inet6", ip.String() + "/128", "-alias"}
	}
	
	if err := exec.Command(cmd, args...).Run(); err != nil {
		// suppress for now
		// @todo research alternative to ifconfig
		// @todo suggest ifconfig or alternative
		// @todo research libs for interface management
		//fmt.Printf("Cannot ifconfig lo0 %s: %v\n", strings.Join(args[1:], " "), err)
	}
}
