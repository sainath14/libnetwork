package vfvlan

import (
      "net"
      "github.com/docker/libnetwork/datastore"
      "github.com/docker/libnetwork/discoverapi"
      "github.com/docker/libnetwork/driverapi"
      "github.com/docker/libnetwork/osl"
)

type networkTable map[string]*network


type network struct {
      id string
      endpoints endpointTable
      config *configuration
}

type driver struct {
      networks networkTable
}

func Init(dc driverapi.DriverCallback, config map[string]interface{}) error {
    c := driverapi.Capability{
           Datascope: datastore.LocalScope
    }

    d := &driver{
          networks: networkTable{},
    }

   dc.RegisterDriver("vfvlan", d, c)
}

func (d *driver) CreateNetwork (nid string, option map[string]interface{}, ipV4Data,ipV6Data []driverapi.IPAMData) error {

}
