package vfvlan

import (
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/types"
	"github.com/vishvananda/netlink"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
        "bufio"
)

type networkTable map[string]*network
type endpointTable map[string]*endpoint

type network struct {
	id        string
	endpoints endpointTable
	config    *configuration
	driver    *driver
	dbIndex   uint64
	dbExists  bool
}

type endpoint struct {
	id      string
	mac     net.HardwareAddr
	addr    *net.IPNet
	addrv6  *net.IPNet
	srcName string
	config  endpointconfig
}

type configuration struct {
	phys_interface string
	pf             string
	vlanid         int
	phys_network   string
}

type vfinfo struct {
	bdf string
	id  int
}

type endpointconfig struct {
	vfinfo
}

type driver struct {
	networks networkTable
	pfs      pf_map
	store    datastore.DataStore
	sync.Mutex
}

type datastoreConfig struct {
	id         string
	phys_network string
	vlanid     int
}

type pf_map map[string][]vfinfo

const (
      network_to_interface_path = "/tmp/vfvlan/"
      sys_class_net_path = "/sys/class/net/"
      pci_devices_path = "/sys/bus/pci/devices/"
)

func Init(dc driverapi.DriverCallback, config map[string]interface{}) error {
	c := driverapi.Capability{
		DataScope: datastore.GlobalScope,
	}

	d := &driver{
		networks: networkTable{},
		pfs:      pf_map{},
	}
	var err error
	if data, ok := config[netlabel.GlobalKVClient]; ok {
		dsc, _ := data.(discoverapi.DatastoreConfigData)
		d.store, err = datastore.NewDataStoreFromConfig(dsc)
		if err != nil {
			logrus.Debugf("vfvlan  " + "failed to get a datastore")
		}
	}
	return dc.RegisterDriver("vfvlan", d, c)
}

func (d *driver) CreateNetwork(nid string, option map[string]interface{}, nInfo driverapi.NetworkInfo, ipV4Data, ipV6Data []driverapi.IPAMData) error {
	n := &network{
		id:        nid,
		endpoints: endpointTable{},
		config:    &configuration{},
                driver:    d,
	}

	// get parent interface
	// check if any network

	if opts, ok := option[netlabel.GenericData]; ok {
		optsMap := opts.(map[string]string)
		for label, value := range optsMap {
			switch label {
			case "phys_network":
				n.config.phys_network = value
				logrus.Debugf("vfvlan - phys network being used: %s", value)
			case "vlanid":
				vlanid, _ := strconv.Atoi(value)
				if (vlanid < 1) || (vlanid > 4094) {
					return fmt.Errorf("invalid vlan id (%d) passed to the vfvlan driver", vlanid)
				}
				n.config.vlanid = vlanid
				logrus.Debugf("vfvlan - vlanid being used for virtual network: %s", value)
			}
		}
	}

	_ = d.SetupInterface(n)
	n.storeUpdate()
	return nil
}

func (d *driver) SetupInterface(n *network) error {

	if n.config.phys_network == "" {
		return fmt.Errorf("Network creation should specify the physical interface")
	}

	mapping_path := network_to_interface_path + n.config.phys_network
	logrus.Debugf("vfvlan - mapping path : %s", mapping_path)

	mapping_file, err := os.Open(mapping_path)
	if err != nil {
		return fmt.Errorf("Error with opening Physical Network to interface Mapping file")
	}

        scanner := bufio.NewScanner(mapping_file)
        scanner.Scan()
        n.config.phys_interface = scanner.Text()

/*
	data := make([]byte, 50)
	_, err = mapping_file.Read(data)
	if err != nil {
		return fmt.Errorf("Error reading the Physical Network to interface Mapping file")
	}

	n.config.phys_interface = strings.TrimSpace(string(data))
*/
        logrus.Debugf("vfvlan - length of interface %d", len(n.config.phys_interface))
	logrus.Debugf("vfvlan - interface being used: %s", n.config.phys_interface)

	//find the pf path from the interface name
	interface_dev_path := sys_class_net_path + n.config.phys_interface + "/" + "device"
	logrus.Debugf("vfvlan - interface device path: %s", interface_dev_path)

	device_info, err := os.Readlink(interface_dev_path)
	logrus.Debugf("vfvlan - read link returned: %s", device_info)
	substrings := strings.SplitN(device_info, "/", 4)
	device_bdf := substrings[3]

	//update the n.config.pf_path
	n.config.pf = device_bdf


	d.Lock()
	d.networks[n.id] = n
	d.Unlock()

	d.Lock()
	defer d.Unlock()
	_, ok := d.pfs[n.config.pf]
	if ok {
		logrus.Debugf("physical interface is used by a different network")
		return nil
	} else {
		d.pfs[n.config.pf] = make([]vfinfo, 0)
	}

	// initialize the pf - write to the file sriov_num and load pci_stub on them
	err = d.initialize_pf(n.config.pf)

	if err != nil {
		logrus.Debugf(err.Error())
		return err
	}

	return nil
}

func (d *driver) getnetwork(nid string) *network {
	d.Lock()
	defer d.Unlock()

	n, ok := d.networks[nid]
	if !ok {
		n = d.getNetworkfromStore(nid)
		if n != nil {
			n.driver = d
			n.endpoints = endpointTable{}
			d.networks[nid] = n
			d.SetupInterface(n)
		}
	}

	return n
}

func (d *driver) getNetworkfromStore(nid string) *network {
	n := &network{id: nid}
	if err := d.store.GetObject(datastore.Key(n.Key()...), n); err != nil {
		return nil
	}
	return n
}

func (n *network) Key() []string {
	return []string{"vfvlan", "network", n.id}
}

func (n *network) KeyPrefix() []string {
	return []string{"vfvlan", "network"}
}

func (n *network) Index() uint64 {
	return n.dbIndex
}

func (n *network) SetIndex(index uint64) {
	n.dbIndex = index
	n.dbExists = true
}

func (n *network) Exists() bool {
	return n.dbExists
}

func (n *network) DataScope() string {
	return datastore.GlobalScope
}

func (n *network) Skip() bool {
	return false
}

func (n *network) Value() []byte {
	config := &datastoreConfig{
		id:           n.id,
		phys_network: n.config.phys_network,
		vlanid:       n.config.vlanid,
	}
	b, err := json.Marshal(config)
	if err != nil {
		return []byte{}
	}

	return b
}

func (n *network) SetValue(value []byte) error {
	var config datastoreConfig
	json.Unmarshal(value, &config)

	n.config = &configuration{}
	n.id = config.id
	n.config.phys_network = config.phys_network
	n.config.vlanid = config.vlanid
        return nil
}

func (n *network) storeUpdate() {
	if (n.driver.store == nil) {
           logrus.Errorf("vfvlan" + "driver store is nil")
           return
        }
        n.driver.store.PutObjectAtomic(n)
}

func (d *driver) initialize_pf(pf string) error {

        var totalvfs_path, numvfs_path, totalvfs string

	device_path := pci_devices_path + pf
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
		for _, value := range device_info_files {
			logrus.Debugf("vfvlan" + value.Name())
			if strings.Contains(value.Name(), "sriov_total") {
				sriov_present = true
				totalvfs_path = device_path + "/" + value.Name()
				logrus.Debugf("vfvlan" + totalvfs_file_path)
				totalvfs_file, _ := os.Open(totalvfs_path)
                                totalvfs_scanner := bufio.NewScanner(totalvfs_file)
                                if err := scanner.Err(), err != nil {
                                   return err
                                }
                                scanner.Scan()
                                totalvfs = scanner.Text()
                                logrus.Debugf("vfvlan Num of VFs " + totalvfs)
/*				if _, err := totalvfs_file.Read(bytes); err == nil {
					logrus.Debugf("vfvlan Num of vfs " + string(bytes))
				} else {
					logrus.Errorf("vfvlan  " + err.Error())
				}
*/
			}

			if strings.Contains(value.Name(), "sriov_numvfs") {
				numvfs_path = device_path + "/" + value.Name()
			}
			logrus.Debugf(value.Name())
		}

		if sriov_present == true {
			logrus.Debugf("vfvlan  " + sriov_numvfs_path)
                        err = write_and_validate_numvfs(numvfs_path, totalvfs)
                        if err != nil {
                           return err
                        }
/*			zero := []byte{48}
			numvfs_file.Write(zero)
			numvfs_file.Sync()
			numvfs_file.Seek(0, 0)
			numvfs_file.Write(bytes) //this appends the count next to 0
                        numvfs_file.Seek(0, 0)
                        numvfs_file.Read(in_bytes)
                        if strings.notequal(in_bytes, bytes) {
                           return fmt.Errorf("Failed to enable the VFs")
                        }
*/
		}
	}

	device_info.Close()

	device_info, err = os.Open(device_path)
	device_info_files, err = device_info.Readdir(0)
	if err == nil {
		for _, value := range device_info_files {
			if strings.Contains(value.Name(), "virtfn") {
				link, _ := os.Readlink(device_path + "/" + value.Name())
				substrings := strings.SplitN(link, "/", 2)
				device_bdf := substrings[1]
				vf_id_str := strings.TrimPrefix(value.Name(), "virtfn")
				vf_id, _ := strconv.Atoi(vf_id_str)
				vf_info := vfinfo{
					bdf: device_bdf,
					id:  vf_id,
				}
				d.pfs[pf] = append(d.pfs[pf], vf_info)
				logrus.Debugf("vfvlan" + device_bdf)
			}
		}
	}
	return nil
}

func write_and_validate_numvfs(numvfs_path string, count string) error {
     numvfs_file, err := os.OpenFile(numvfs_path, os.O_RDWR, 0666)
     defer numvfs_file.Close()

     writer := bufio.NewWriter(numvfs_file)
     scanner := bufio.NewScanner(numvfs_file)


     writer.WriteString("0") 
     writer.Flush()
     numvfs_file.Seek(0,0)
     writer.WriteString(count)
     numvfs_file.Seek(0,0)
     scanner.Scan()
     vfs_enabled := scanner.Text()
     if (strings.Equalfold(vfs_enabled, count) == false) {
        return fmt.Errorf("Failed to enable all VFs. Fallback to not using SR-IOv on this system")
     }
}


/*func (d *driver) getNetworks() []*network {
	d.Lock()
	defer d.Unlock()

	networks = make([]*network, len(d.networks))

	for _, value := range d.networks {
		networks = append(networks, value)
	}
	return networks
}*/

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
		config: endpointconfig{},
	}

	n := d.getnetwork(nid)
	if n == nil {
		return fmt.Errorf("Network id %q passed is not found", nid)
	}

	//find the interface pf from the network config
	pf := n.config.pf

	d.Lock()

	if len(d.pfs[pf]) == 0 {
		fmt.Errorf("All the vfs on this interface are currently in use")
	} else {
		ep.config.vfinfo = d.pfs[pf][0]
		d.pfs[pf] = d.pfs[pf][1:]
	}

	d.Unlock()

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
	pci_devices_path := "/sys/bus/pci/devices/"
	n := d.getnetwork(nid)
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

	pf_link, _ := netlink.LinkByName(n.config.phys_interface)
	err := netlink.LinkSetVfVlan(pf_link, ep.config.id, n.config.vlanid)

	vf_path := pci_devices_path + ep.config.bdf
	vf_interface := vf_path + "/net"
	interface_info, _ := os.Open(vf_interface)
	interface_info_dir, err := interface_info.Readdir(0)
	if err == nil {
		for _, value := range interface_info_dir {
			ep.srcName = value.Name()
			logrus.Debugf("vfvlan ep srcname %s", ep.srcName)
		}
	}

	//	ep.srcName = "eth2"

	//s := n.getSubnetforIPv4(ep.addr)

	//	v4gw, _, err := net.ParseCIDR("172.18.0.1")

	//	jinfo.SetGateway(v4gw)

	iNames := jinfo.InterfaceName()

	err = iNames.SetNames(ep.srcName, "eth")

	return err
}

func (d *driver) Leave(nid, eid string) error {
	n := d.networks[nid]
	logrus.Debugf("vfvlan - Leave network id from the map %q", n.id)

	logrus.Debugf("eid passed is %q", eid)

	ep, _ := n.endpoints[eid]
	logrus.Debugf("endpoint details  %+v", *ep)
	pf := n.config.pf

	d.Lock()
	d.pfs[pf] = append(d.pfs[pf], ep.config.vfinfo)
	d.Unlock()

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
	switch dType {
	case discoverapi.NodeDiscovery:
		_, ok := data.(discoverapi.NodeDiscoveryData)
		if !ok {
			logrus.Debugf("vfvlan wrong info on new node discovery")
		}
	default:
	}
	return nil
}

func (d *driver) DiscoverDelete(dType discoverapi.DiscoveryType, data interface{}) error {
	return nil
}
