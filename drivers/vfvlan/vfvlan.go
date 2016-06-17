package vfvlan

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/types"
	"github.com/vishvananda/netlink"
	"net"
	"os"
	//	"strings"
)

type networkTable map[string]*network
type endpointTable map[string]*endpoint

type network struct {
	id        string
	endpoints endpointTable
	config    *configuration
}

type endpoint struct {
	id      string
	mac     net.HardwareAddr
	addr    *net.IPNet
	addrv6  *net.IPNet
	srcName string
}

type configuration struct {
}

type driver struct {
	networks networkTable
	pfs      pf_map
}

type pf_map map[string][]string

func Init(dc driverapi.DriverCallback, config map[string]interface{}) error {
	c := driverapi.Capability{
		DataScope: datastore.LocalScope,
	}

	/*
	   	pci_path := "/sys/bus/pci/devices"

	   	file, err := os.Open(pci_path)

	   	pci_list, err := file.Readdir(0)

	   	if err != nil {
	   		logrus.Errorf(err.Error())
	   	}

	   	for _, value := range pci_list {
	   		logrus.Debugf("vfvlan" + value.Name())
	   		device_path := pci_path + value.Name() + "/"
	   		logrus.Debugf("vfvlan" + device_path)
	   		device_info, err := os.Open(device_path)
	   		if err != nil {
	   			logrus.Errorf("vfvlan" + err.Error())
	   		}

	   		device_info_files, err := device_info.Readdir(0)
	   		if err != nil {
	   			logrus.Errorf("vfvlan" + err.Error())
	   		}

	   		if err == nil {
	   			sriov_present := false
	   			bytes := make([]byte, 2)
	   			var sriov_numvfs_path string
	   			for _, value := range device_info_files {
	   				logrus.Debugf("vfvlan" + value.Name())
	   				if strings.Contains(value.Name(), "sriov_total") {
	   					sriov_present = true
	   					totalvfs_file_path := device_path + value.Name()
	   					logrus.Debugf("vfvlan" + totalvfs_file_path)
	   					totalvfs_file, _ := os.Open(totalvfs_file_path)
	   					if _, err := totalvfs_file.Read(bytes); err == nil {
	   						logrus.Debugf("vfvlan Num of vfs " + string(bytes))
	   					} else {
	   						logrus.Errorf("vfvlan  " + err.Error())
	   					}
	   				}

	   				if strings.Contains(value.Name(), "sriov_numvfs") {
	   					sriov_numvfs_path = device_path + value.Name()
	   				}
	   				logrus.Debugf(value.Name())
	   			}

	   			if sriov_present == true {
	                                   logrus.Debugf("vfvlan  " + sriov_numvfs_path)
	   				numvfs_file, _ := os.OpenFile(sriov_numvfs_path, os.O_RDWR, 0666)
	   				zero := []byte{48}
	   				numvfs_file.Write(zero)
	   				numvfs_file.Sync()
	   				numvfs_file.Write(bytes)  //this appends the count next to 0
	   			}
	   		}
	   	}
	*/

	pf_info := pf_map{}
	pf_path := "/sys/bus/pci/devices/0000:03:00.1"
	vf_path := "/sys/bus/pci/devices/0000:03:10.1"
	pf_info[pf_path] = append(pf_info[pf_path], vf_path)

	d := &driver{
		networks: networkTable{},
		pfs:      pf_info,
	}

	return dc.RegisterDriver("vfvlan", d, c)
}

func (d *driver) CreateNetwork(nid string, option map[string]interface{}, nInfo driverapi.NetworkInfo, ipV4Data, ipV6Data []driverapi.IPAMData) error {
	n := &network{
		id:        nid,
		endpoints: endpointTable{},
		config:    &configuration{},
	}

	d.networks[n.id] = n

	return nil
}

func (d *driver) NetworkAllocate(nid string, options map[string]string, ipV4Data, ipV6Data []driverapi.IPAMData) (map[string]string, error) {
	return nil, types.NotImplementedErrorf("not implemented")
}

func (d *driver) NetworkFree(nid string) error {
	return nil
}

func (d *driver) DeleteNetwork(nid string) error {
	return nil
}

func (d *driver) CreateEndpoint(nid, eid string, ifInfo driverapi.InterfaceInfo, options map[string]interface{}) error {

	ep := &endpoint{
		id:     eid,
		addr:   ifInfo.Address(),
		addrv6: ifInfo.AddressIPv6(),
		mac:    ifInfo.MacAddress(),
	}

	n, ok := d.networks[nid]
	if !ok {
		return fmt.Errorf("Network id %q passed is not found", nid)
	}

	logrus.Debugf("nid %q , eid passed is %q", nid, eid)

	n.endpoints[ep.id] = ep
	return nil
}

func (d *driver) DeleteEndpoint(nid, eid string) error {
	return nil
}

func (d *driver) EndpointOperInfo(nid, eid string) (map[string]interface{}, error) {
	return make(map[string]interface{}, 0), nil
}

func (d *driver) Join(nid, eid string, sboxKey string, jinfo driverapi.JoinInfo, options map[string]interface{}) error {
	n := d.networks[nid]
	logrus.Debugf("network id from the map %q", n.id)

	logrus.Debugf("eid passed is %q", eid)
	for key, value := range n.endpoints {
		logrus.Debugf("endpoint id in networks structure %q, %+v", key, *value)
	}

	ep, ok := n.endpoints[eid]

	if !ok {
		return fmt.Errorf("endpoint not found")
	}

	logrus.Debugf("nid %q , eid passed is %q", nid, eid)

	//tie a pf to a physical network - a single pf can accomodate multiple virtual LANs (vf vlan id)
	//physical network name can be passed as a label to the driver?? network create options
	//finding the interface name (ethX) can be made a function

	pf_path := "/sys/bus/pci/devices/0000:03:00.1"
	pf_interface := pf_path + "/net"
	pf_interface_info, _ := os.Open(pf_interface)
	pf_interface_info_dir, err := pf_interface_info.Readdir(0)
	var pf_interface_name string
	if err == nil {
		for _, value := range pf_interface_info_dir {
			pf_interface_name = value.Name()
		}
	}

	pf_link, _ := netlink.LinkByName(pf_interface_name)
	err = netlink.LinkSetVfVlan(pf_link, 0, 1300)

	vf_path, ok := d.pfs["/sys/bus/pci/devices/0000:03:00.1"]
	if !ok {
		logrus.Debugf("vfvlan - pf info not found in driver!!")
	}
	vf_interface := vf_path[0] + "/net"
	interface_info, _ := os.Open(vf_interface)
	interface_info_dir, err := interface_info.Readdir(0)
	if err == nil {
		for _, value := range interface_info_dir {
			ep.srcName = value.Name()
		}
	}

	//	ep.srcName = "eth2"

	//s := n.getSubnetforIPv4(ep.addr)

	v4gw, _, err := net.ParseCIDR("172.18.0.1")

	jinfo.SetGateway(v4gw)

	iNames := jinfo.InterfaceName()

	err = iNames.SetNames(ep.srcName, "eth")

	return err
}

func (d *driver) Leave(nid, eid string) error {
	return nil
}

func (d *driver) ProgramExternalConnectivity(nid, eid string, options map[string]interface{}) error {
	return nil
}

func (d *driver) RevokeExternalConnectivity(nid, eid string) error {
	return nil
}

func (d *driver) EventNotify(event driverapi.EventType, nid string, tableName string, key string, value []byte) {

}

func (d *driver) Type() string {
	return "vfvlan"
}

func (d *driver) DiscoverNew(dType discoverapi.DiscoveryType, data interface{}) error {
	return nil
}

func (d *driver) DiscoverDelete(dType discoverapi.DiscoveryType, data interface{}) error {
	return nil
}
