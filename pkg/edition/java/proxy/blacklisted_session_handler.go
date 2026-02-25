package proxy

import (
	"encoding/json"
	"fmt"

	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/edition/java/netmc"
	"go.minekube.com/gate/pkg/edition/java/proto/packet"
	"go.minekube.com/gate/pkg/gate/proto"
	"go.minekube.com/gate/pkg/util/netutil"
)

type blacklistedSessionHandler struct {
	*sessionHandlerDeps
	conn            netmc.MinecraftConn
	log             logr.Logger
	hanshake        *packet.Handshake
	inbound         Inbound
	pingResolveFunc pingResolveFunc
	receivedRequest bool
	source          string
	nopSessionHandler
}

func newBlacklistedSessionHandler(
	conn netmc.MinecraftConn,
	deps *sessionHandlerDeps,
	source string,
) netmc.SessionHandler {
	return &blacklistedSessionHandler{
		sessionHandlerDeps: deps,
		conn:               conn,
		source:             source,
		log:                logr.FromContextOrDiscard(conn.Context()).WithName("deniedSession"),
	}
}

func (h *blacklistedSessionHandler) HandlePacket(p *proto.PacketContext) {
	switch typed := p.Packet.(type) {
	case *packet.Handshake:
		h.handleHandshake(typed, p)
	case *packet.StatusRequest:
		h.handleStatusRequest(p)
	case *packet.StatusPing:
		h.handleStatusPing(p)
	default:
		h.log.Info(
			"Blacklisted client blocked for packet",
			"ip", h.conn.RemoteAddr(),
			"packetType", fmt.Sprintf("%T", p.Packet),
			"source", h.source,
		)
		_ = h.conn.Close()
	}
}

func (h *blacklistedSessionHandler) handleHandshake(handshake *packet.Handshake, pc *proto.PacketContext) {
	nextState := stateForProtocol(handshake.NextStatus)
	if nextState == nil {
		h.log.V(1).Info("client provided invalid next status state, closing connection",
			"nextStatus", handshake.NextStatus)
		_ = h.conn.Close()
		return
	}

	vHost := netutil.NewAddr(
		fmt.Sprintf("%s:%d", handshake.ServerAddress, handshake.Port),
		h.conn.LocalAddr().Network(),
	)
	handshakeIntent := handshake.Intent()
	h.inbound = newInitialInbound(h.conn, vHost, handshakeIntent)
	h.conn.SetState(nextState)
	h.conn.SetProtocol(proto.Protocol(handshake.ProtocolVersion))
}

func (h *blacklistedSessionHandler) handleStatusRequest(p *proto.PacketContext) {
	if h.receivedRequest {
		// Already sent response
		_ = h.conn.Close()
		return
	}
	h.receivedRequest = true

	e := &PingEvent{
		inbound: h.inbound,
		ping:    newInitialPing(h.proxy, p.Protocol),
	}

	if motd := h.config().IPBlacklist.Motd; motd != nil {
		e.ping.Description = motd.T()
	}
	if icon := h.config().IPBlacklist.Favicon; icon != "" {
		e.ping.Favicon = icon
	}

	h.eventMgr.Fire(e)

	if !h.inbound.Active() {
		return
	}

	response, err := json.Marshal(e.ping)
	if err != nil {
		_ = h.conn.Close()
		h.log.Error(err, "error marshaling ping response to json")
		return
	}
	_ = h.conn.WritePacket(&packet.StatusResponse{
		Status: string(response),
	})
}

func (h *blacklistedSessionHandler) handleStatusPing(p *proto.PacketContext) {
	defer h.conn.Close()
	if err := h.conn.Write(p.Payload); err != nil {
		h.log.Info("error writing StatusPing response", "error", err)
	}
}
