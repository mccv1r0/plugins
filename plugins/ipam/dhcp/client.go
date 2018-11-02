package main

import (
	"github.com/d2g/dhcp4"
	"github.com/d2g/dhcp4client"
)

const (
	MaxDHCPLen = 576
)

//Send the Discovery Packet to the Broadcast Channel
func DhcpSendDiscoverPacket(c *dhcp4client.Client, options dhcp4.Options) (dhcp4.Packet, error) {
	discoveryPacket := c.DiscoverPacket()

	for opt, data := range options {
		discoveryPacket.AddOption(opt, data)
	}

	discoveryPacket.PadToMinSize()
	return discoveryPacket, c.SendPacket(discoveryPacket)
}

//Send Request Based On the offer Received.
func DhcpSendRequest(c *dhcp4client.Client, options dhcp4.Options, offerPacket *dhcp4.Packet) (dhcp4.Packet, error) {
	requestPacket := c.RequestPacket(offerPacket)

	for opt, data := range options {
		requestPacket.AddOption(opt, data)
	}

	requestPacket.PadToMinSize()

	return requestPacket, c.SendPacket(requestPacket)
}

//Send Decline to the received acknowledgement.
func DhcpSendDecline(c *dhcp4client.Client, acknowledgementPacket *dhcp4.Packet, options dhcp4.Options) (dhcp4.Packet, error) {
	declinePacket := c.DeclinePacket(acknowledgementPacket)

	for opt, data := range options {
		declinePacket.AddOption(opt, data)
	}

	declinePacket.PadToMinSize()

	return declinePacket, c.SendPacket(declinePacket)
}

/*
//Create Discover Packet
func DhcpDiscoverPacket(c *dhcp4client.Client, options dhcp4.Options) dhcp4.Packet {
	messageid := make([]byte, 4)
	c.generateXID(messageid)

	packet := dhcp4.NewPacket(dhcp4.BootRequest)
	packet.SetCHAddr(c.hardwareAddr)
	packet.SetXId(messageid)
	packet.SetBroadcast(c.broadcast)

	packet.AddOption(dhcp4.OptionDHCPMessageType, []byte{byte(dhcp4.Discover)})
	for opt, data := range options {
               packet.AddOption(opt, data)
	}
	//packet.PadToMinSize()
	return packet
}
*/

/*
//Create Request Packet
func DhcpRequestPacket(c *dhcp4client.Client, offerPacket *dhcp4.Packet, options dhcp4.Options) dhcp4.Packet {
	offerOptions := offerPacket.ParseOptions()

	packet := dhcp4.NewPacket(dhcp4.BootRequest)
	packet.SetCHAddr(c.hardwareAddr)

	packet.SetXId(offerPacket.XId())
	packet.SetCIAddr(offerPacket.CIAddr())
	packet.SetSIAddr(offerPacket.SIAddr())

	packet.SetBroadcast(c.broadcast)
	packet.AddOption(dhcp4.OptionDHCPMessageType, []byte{byte(dhcp4.Request)})
	packet.AddOption(dhcp4.OptionRequestedIPAddress, (offerPacket.YIAddr()).To4())
	packet.AddOption(dhcp4.OptionServerIdentifier, offerOptions[dhcp4.OptionServerIdentifier])

	for opt, data := range options {
               packet.AddOption(opt, data)
	}

	return packet
}
*/

/*
//Create Request Packet For a Renew
func DhcpRenewalRequestPacket(c *dhcp4client.Client, acknowledgement *dhcp4.Packet, options dhcp4.Options) dhcp4.Packet {
	messageid := make([]byte, 4)
	c.generateXID(messageid)

	acknowledgementOptions := acknowledgement.ParseOptions()

	packet := dhcp4.NewPacket(dhcp4.BootRequest)
	packet.SetCHAddr(acknowledgement.CHAddr())

	packet.SetXId(messageid)
	packet.SetCIAddr(acknowledgement.YIAddr())
	packet.SetSIAddr(acknowledgement.SIAddr())

	packet.SetBroadcast(c.broadcast)
	packet.AddOption(dhcp4.OptionDHCPMessageType, []byte{byte(dhcp4.Request)})
	packet.AddOption(dhcp4.OptionRequestedIPAddress, (acknowledgement.YIAddr()).To4())
	packet.AddOption(dhcp4.OptionServerIdentifier, acknowledgementOptions[dhcp4.OptionServerIdentifier])

	for opt, data := range options {
		packet.AddOption(opt, data)
	}

	return packet
}
*/

/*
//Create Release Packet For a Release
func DhcpReleasePacket(c *dhcp4client.Client, acknowledgement *dhcp4.Packet, options dhcp4.Options) dhcp4.Packet {
	messageid := make([]byte, 4)
	c.generateXID(messageid)

	acknowledgementOptions := acknowledgement.ParseOptions()

	packet := dhcp4.NewPacket(dhcp4.BootRequest)
	packet.SetCHAddr(acknowledgement.CHAddr())

	packet.SetXId(messageid)
	packet.SetCIAddr(acknowledgement.YIAddr())

	packet.AddOption(dhcp4.OptionDHCPMessageType, []byte{byte(dhcp4.Release)})
	packet.AddOption(dhcp4.OptionServerIdentifier, acknowledgementOptions[dhcp4.OptionServerIdentifier])

	for opt, data := range options {
		packet.AddOption(opt, data)
	}

	return packet
}
*/

/*
//Create Decline Packet
func DhcpDeclinePacket(c *dhcp4client.Client, acknowledgement *dhcp4.Packet, options dhcp4.Options) dhcp4.Packet {
	messageid := make([]byte, 4)
	c.generateXID(messageid)

	acknowledgementOptions := acknowledgement.ParseOptions()

	packet := dhcp4.NewPacket(dhcp4.BootRequest)
	packet.SetCHAddr(acknowledgement.CHAddr())
	packet.SetXId(messageid)

	packet.AddOption(dhcp4.OptionDHCPMessageType, []byte{byte(dhcp4.Decline)})
	packet.AddOption(dhcp4.OptionRequestedIPAddress, (acknowledgement.YIAddr()).To4())
	packet.AddOption(dhcp4.OptionServerIdentifier, acknowledgementOptions[dhcp4.OptionServerIdentifier])

	for opt, data := range options {
		packet.AddOption(opt, data)
	}

	return packet
}
*/

//Lets do a Full DHCP Request.
func DhcpRequest(c *dhcp4client.Client, options dhcp4.Options) (bool, dhcp4.Packet, error) {
	discoveryPacket, err := DhcpSendDiscoverPacket(c, options)
	if err != nil {
		return false, discoveryPacket, err
	}

	offerPacket, err := c.GetOffer(&discoveryPacket)
	if err != nil {
		return false, offerPacket, err
	}

	requestPacket, err := DhcpSendRequest(c, options, &offerPacket)
	if err != nil {
		return false, requestPacket, err
	}

	acknowledgement, err := c.GetAcknowledgement(&requestPacket)
	if err != nil {
		return false, acknowledgement, err
	}

	acknowledgementOptions := acknowledgement.ParseOptions()
	if dhcp4.MessageType(acknowledgementOptions[dhcp4.OptionDHCPMessageType][0]) != dhcp4.ACK {
		return false, acknowledgement, nil
	}

	return true, acknowledgement, nil
}

//Renew a lease backed on the Acknowledgement Packet.
//Returns Sucessfull, The AcknoledgementPacket, Any Errors
func DhcpRenew(c *dhcp4client.Client, acknowledgement dhcp4.Packet, options dhcp4.Options) (bool, dhcp4.Packet, error) {
	renewRequest := c.RenewalRequestPacket(&acknowledgement)

	for opt, data := range options {
		renewRequest.AddOption(opt, data)
	}

	renewRequest.PadToMinSize()

	err := c.SendPacket(renewRequest)
	if err != nil {
		return false, renewRequest, err
	}

	newAcknowledgement, err := c.GetAcknowledgement(&renewRequest)
	if err != nil {
		return false, newAcknowledgement, err
	}

	newAcknowledgementOptions := newAcknowledgement.ParseOptions()
	if dhcp4.MessageType(newAcknowledgementOptions[dhcp4.OptionDHCPMessageType][0]) != dhcp4.ACK {
		return false, newAcknowledgement, nil
	}

	return true, newAcknowledgement, nil
}

//Release a lease backed on the Acknowledgement Packet.
//Returns Any Errors
func DhcpRelease(c *dhcp4client.Client, acknowledgement dhcp4.Packet, options dhcp4.Options) error {
	release := c.ReleasePacket(&acknowledgement)

	for opt, data := range options {
		release.AddOption(opt, data)
	}

	release.PadToMinSize()

	return c.SendPacket(release)
}
