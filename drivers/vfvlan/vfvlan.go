package vfvlan

import (
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/types"
	"net"
)

type networkTable map[string]*network
type endpointTable map[string]*endpoint

type network struct {
	id        string
	endpoints endpointTable
	config    *configuration
}

type endpoint struct {
	id     string
	mac    net.HardwareAddr
	addr   *net.IPNet
	addrv6 *net.IPNet
}

type configuration struct {
}

type driver struct {
	networks networkTable
}

func Init(dc driverapi.DriverCallback, config map[string]interface{}) error {
	c := driverapi.Capability{
		DataScope: datastore.LocalScope,
	}

	d := &driver{
		networks: networkTable{},
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
	return nil
}

func (d *driver) DeleteEndpoint(nid, eid string) error {
	return nil
}

func (d *driver) EndpointOperInfo(nid, eid string) (map[string]interface{}, error) {
	return make(map[string]interface{}, 0), nil
}

func (d *driver) Join(nid, eid string, sboxKey string, jinfo driverapi.JoinInfo, options map[string]interface{}) error {
	return nil
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
