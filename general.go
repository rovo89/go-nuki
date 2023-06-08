package nuki

import (
	"context"
	"fmt"
	"github.com/go-ble/ble"
	"github.com/kevinburke/nacl"
	"github.com/tarent/go-nuki/communication"
	"github.com/tarent/go-nuki/communication/command"
	"time"
)

// ConnectionNotEstablishedError will be returned if the connection is not established before
var ConnectionNotEstablishedError = fmt.Errorf("the connection is not established")

// UnauthenticatedError will be returned if the client is not authenticated before
var UnauthenticatedError = fmt.Errorf("the client is not authenticated")

// InvalidPinError will be returned if the given pin is invalid
var InvalidPinError = fmt.Errorf("the given pin is invalid")

type Config struct {
	addr ble.Addr

	privateKey    nacl.Key
	publicKey     nacl.Key
	nukiPublicKey []byte
	authId        command.AuthorizationId

	pin command.Pin
}

type Client struct {
	config          *Config
	responseTimeout time.Duration

	client  ble.Client
	gdioCom communication.Communicator
	udioCom communication.Communicator
}

func NewConfig(addr ble.Addr) *Config {
	return &Config{
		addr: addr,
		pin: command.NoPin,
	}
}

func (cfg *Config) WithPin(pin string) error {
	parsedPin, err := command.NewPin(pin)
	if err != nil {
		return err
	}
	cfg.pin = parsedPin
	return nil
}

// WithTimeout sets the timeout which is used for each response waiting.
func (c *Client) WithTimeout(duration time.Duration) *Client {
	c.responseTimeout = duration
	return c
}

// EstablishConnection establish a connection to the given nuki device.
// Returns an error if there was a problem with connecting to the device.
func (cfg *Config) EstablishConnection(ctx context.Context, bleDevice ble.Device) (*Client, error) {
	c := &Client{
		config: cfg,
		responseTimeout: 10 * time.Second,
	}

	bleClient, err := bleDevice.Dial(ctx, cfg.addr)
	if err != nil {
		return nil, fmt.Errorf("error while establish connection: %w", err)
	}
	c.client = bleClient

	c.gdioCom, err = communication.NewGeneralDataIOCommunicator(bleClient)
	if err != nil {
		return nil, fmt.Errorf("error while establish communication: %w", err)
	}

	//in case of "re-establish" a connection (for example after reboot the device)
	if cfg.HasAuthentication() {
		err = c.Authenticate()
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

// GetDeviceType will return the discovered type of the connected device.
func (c *Client) GetDeviceType() communication.DeviceType {
	if c.gdioCom == nil {
		return communication.DeviceTypeUnknown
	}
	return c.gdioCom.GetDeviceType()
}

// GeneralDataIOCommunicator will return the communicator which is responsible for general data io.
// This is only available after the connection is established (EstablishConnection)
func (c *Client) GeneralDataIOCommunicator() communication.Communicator {
	return c.gdioCom
}

// UserSpecificDataIOCommunicator will return the communicator which is responsible for user specific data io.
// This is only available after the connection is established (EstablishConnection) and the authentication is done (Pair or Authenticate).
func (c *Client) UserSpecificDataIOCommunicator() communication.Communicator {
	return c.udioCom
}

// Close will close all underlying resources. This function should be called after
// the client will not be used anymore.
func (c *Client) Close() error {
	errors := make([]error, 0, 3)

	if c.gdioCom != nil {
		if err := c.gdioCom.Close(); err != nil {
			errors = append(errors, err)
		}
		c.gdioCom = nil
	}

	if c.udioCom != nil {
		if err := c.udioCom.Close(); err != nil {
			errors = append(errors, err)
		}
		c.udioCom = nil
	}

	if c.client != nil {
		if err := c.client.Conn().Close(); err != nil {
			errors = append(errors, err)
		}
		c.client = nil
	}

	if len(errors) > 0 {
		return fmt.Errorf("error while closing resources: [%v]", errors)
	}

	return nil
}

// PerformAction will request the connected and paired nuki opener to perform the given command.
func (c *Client) PerformAction(ctx context.Context, actionBuilder func(nonce []byte) command.Command) error {
	if c.client == nil {
		return ConnectionNotEstablishedError
	}
	if c.udioCom == nil {
		return UnauthenticatedError
	}

	err := c.udioCom.Send(command.NewRequest(command.IdChallenge))
	if err != nil {
		return fmt.Errorf("unable to send request for challenge: %w", err)
	}

	challenge, err := c.udioCom.WaitForSpecificResponse(ctx, command.IdChallenge, c.responseTimeout)
	if err != nil {
		return fmt.Errorf("error while waiting for challenge: %w", err)
	}

	toSend := actionBuilder(challenge.AsChallengeCommand().Nonce())
	err = c.udioCom.Send(toSend)
	if err != nil {
		return fmt.Errorf("unable to send action: %w", err)
	}

	status, err := c.udioCom.WaitForSpecificResponse(ctx, command.IdStatus, c.responseTimeout)
	if err != nil {
		return fmt.Errorf("error while waiting for status: %w", err)
	}

	if status.AsStatusCommand().IsAccepted() {
		// This will be returned to signal that a command has been accepted but the completion status will be signaled later.
		// So here we just wait for the second status.

		status, err = c.udioCom.WaitForSpecificResponse(ctx, command.IdStatus, c.responseTimeout)
		if err != nil {
			return fmt.Errorf("error while waiting for status: %w", err)
		}

		if !status.AsStatusCommand().IsComplete() {
			return fmt.Errorf("unexpected status: expect 0x%02x got 0x%02x", command.CompletionStatusComplete, status.AsStatusCommand().Status())
		}
	}

	return nil
}

func (c *Client) checkPrecondition() error {
	if c.client == nil {
		return ConnectionNotEstablishedError
	}
	if c.udioCom == nil {
		return UnauthenticatedError
	}
	if c.config.pin == command.NoPin {
		return nil
	}
	return nil
}
