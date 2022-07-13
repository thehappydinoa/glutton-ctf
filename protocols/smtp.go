package protocols

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// maximum lines that can be read after the "DATA" command
const maxDataRead = 500
const VALID_SENDER_DOMAIN = ".+"
const OUR_EMAIL_ADDR = "foo@censys.io"

var valid_sender, valid_receiver bool = false, false

// Client is a connection container
type Client struct {
	conn   net.Conn
	bufin  *bufio.Reader
	bufout *bufio.Writer
}

func (c *Client) w(s string) {
	c.bufout.WriteString(s + "\r\n")
	c.bufout.Flush()
}
func (c *Client) read() (string, error) {
	return c.bufin.ReadString('\n')
}

func rwait() {
	// makes the process sleep for random time
	rand.Seed(time.Now().Unix())
	// between 0.5 - 1.5 seconds
	rtime := rand.Intn(1500) + 500
	duration := time.Duration(rtime) * time.Millisecond
	time.Sleep(duration)
}
func validateMail(query string) bool {
	email := regexp.MustCompile(fmt.Sprintf("^MAIL FROM:<.+@%s>$", VALID_SENDER_DOMAIN))
	return email.MatchString(query)
}
func validateRCPT(query string) bool {
	rcpt := regexp.MustCompile(fmt.Sprintf("^RCPT TO:<%s>$", OUR_EMAIL_ADDR))
	return rcpt.MatchString(query)
}

// HandleSMTP takes a net.Conn and does basic SMTP communication
func HandleSMTP(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error(fmt.Sprintf("[smtp    ]  error: %v", err))
		}
	}()

	md, err := h.MetadataByConnection(conn)
	if err != nil {
		return err
	}

	client := &Client{
		conn:   conn,
		bufin:  bufio.NewReader(conn),
		bufout: bufio.NewWriter(conn),
	}
	rwait()
	client.w("220 Welcome!")

	for {
		h.UpdateConnectionTimeout(ctx, conn)
		data, err := client.read()
		if err != nil {
			break
		}
		query := strings.Trim(data, "\r\n")
		logger.Info(fmt.Sprintf("[smtp    ] Payload : %q", query))
		if strings.HasPrefix(query, "HELO ") {
			rwait()
			client.w("250 Hello! Pleased to meet you.\nOur first flag is ctf{8d637f30-ec7b-4f01-86b1-daf23d4f4643}")
		} else if validateMail(query) {
			rwait()
			valid_sender = true
			client.w("250 OK")
		} else if validateRCPT(query) {
			rwait()
			valid_receiver = true
			client.w("250 OK")
		} else if strings.Compare(query, "DATA") == 0 {
			client.w("354 End data with <CRLF>.<CRLF>")
			for readctr := maxDataRead; readctr >= 0; readctr-- {
				data, err = client.read()
				if err != nil {
					break
				}
				if err := h.Produce(conn, md, []byte(data)); err != nil {
					logger.Error("failed to produce message", zap.String("protocol", "smpt"), zap.Error(err))
				}
				logger.Info(fmt.Sprintf("[smtp    ] Data : %q", data))
				// exit condition
				if strings.Compare(data, ".\r\n") == 0 {
					break
				}
			}
			rwait()
			client.w("250 OK")
		} else if strings.Compare(query, "QUIT") == 0 {
			var message string = "Bye"
			if valid_sender && valid_receiver {
				// Respond with flag!
				message += "\nctf{87ae2896-72e0-4a57-b7ef-efcdc10448fd}"
			}
			client.w(message)
			// set sender and receiver back to false.
			valid_sender, valid_receiver = false, false
			break
		} else {
			client.w("Recheck the command you entered.")
		}
	}
	return nil
}
