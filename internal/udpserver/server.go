// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

type Server struct {
	cfg config.ServerConfig
	log *logger.Logger
}

type request struct {
	data []byte
	addr *net.UDPAddr
}

func New(cfg config.ServerConfig, log *logger.Logger) *Server {
	return &Server{
		cfg: cfg,
		log: log,
	}
}

func (s *Server) Run(ctx context.Context) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(s.cfg.UDPHost),
		Port: s.cfg.UDPPort,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetReadBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("<yellow>set read buffer failed</yellow>: <cyan>%v</cyan>", err)
	}
	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("<yellow>set write buffer failed</yellow>: <cyan>%v</cyan>", err)
	}

	s.log.Infof(
		"<green>udp listener ready</green> addr=<cyan>%s</cyan> workers=<magenta>%d</magenta> queue=<magenta>%d</magenta>",
		s.cfg.Address(),
		s.cfg.DNSRequestWorkers,
		s.cfg.MaxConcurrentRequests,
	)

	reqCh := make(chan request, s.cfg.MaxConcurrentRequests)
	var wg sync.WaitGroup

	for i := 0; i < s.cfg.DNSRequestWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			s.worker(ctx, conn, reqCh, workerID)
		}(i + 1)
	}

	readErr := make(chan error, 1)
	go func() {
		readErr <- s.readLoop(ctx, conn, reqCh)
	}()

	select {
	case <-ctx.Done():
		_ = conn.SetReadDeadline(time.Now())
		close(reqCh)
		wg.Wait()
		return ctx.Err()
	case err := <-readErr:
		close(reqCh)
		wg.Wait()
		if errors.Is(err, context.Canceled) {
			return err
		}
		return err
	}
}

func (s *Server) readLoop(ctx context.Context, conn *net.UDPConn, reqCh chan<- request) error {
	buffer := make([]byte, s.cfg.MaxPacketSize)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return context.Canceled
				default:
					continue
				}
			}
			return err
		}

		packet := append([]byte(nil), buffer[:n]...)
		select {
		case reqCh <- request{data: packet, addr: addr}:
		case <-ctx.Done():
			return context.Canceled
		default:
			s.log.Warnf(
				"<yellow>request queue full</yellow>, dropping packet from <cyan>%s</cyan>",
				addr.String(),
			)
		}
	}
}

func (s *Server) worker(ctx context.Context, conn *net.UDPConn, reqCh <-chan request, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-reqCh:
			if !ok {
				return
			}

			response := s.handlePacket(req.data)
			if len(response) == 0 {
				continue
			}

			if _, err := conn.WriteToUDP(response, req.addr); err != nil {
				s.log.Debugf(
					"<magenta>worker</magenta> <cyan>%d</cyan> write error to <cyan>%s</cyan>: <yellow>%v</yellow>",
					workerID,
					req.addr.String(),
					err,
				)
			}
		}
	}
}

func (s *Server) handlePacket(packet []byte) []byte {
	return packet
}
