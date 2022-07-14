package protocols

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kung-foo/freki"
	"go.uber.org/zap"
)

// Mirai botnet  - https://github.com/CymmetriaResearch/MTPot/blob/master/mirai_conf.json
// Hajime botnet - https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf
var miraiCom = map[string][]string{
	"ps":                                 {"1 pts/21   00:00:00 init"},
	"cat /proc/mounts":                   {"rootfs / rootfs rw 0 0\r\n/dev/root / ext2 rw,relatime,errors=continue 0 0\r\nproc /proc proc rw,relatime 0 0\r\nsysfs /sys sysfs rw,relatime 0 0\r\nudev /dev tmpfs rw,relatime 0 0\r\ndevpts /dev/pts devpts rw,relatime,mode=600,ptmxmode=000 0 0\r\n/dev/mtdblock1 /home/hik jffs2 rw,relatime 0 0\r\ntmpfs /run tmpfs rw,nosuid,noexec,relatime,size=3231524k,mode=755 0 0\r\n"},
	"(cat .s || cp /bin/echo .s)":        {"cat: .s: No such file or directory"},
	"nc":                                 {"nc: command not found"},
	"wget":                               {"wget: missing URL"},
	"(dd bs=52 count=1 if=.s || cat .s)": {"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00\xbc\x14\x01\x00\x34\x00\x00\x00"},
	"sh":                                 {"$"},
	"sh || shell":                        {"$"},
	"enable\x00":                         {"-bash: enable: command not found"},
	"system\x00":                         {"-bash: system: command not found"},
	"shell\x00":                          {"-bash: shell: command not found"},
	"sh\x00":                             {"$"},
	//	"fgrep XDVR /mnt/mtd/dep2.sh\x00":		   {"cd /mnt/mtd && ./XDVRStart.hisi ./td3500 &"},
	"busybox": {"BusyBox v1.16.1 (2014-03-04 16:00:18 CST) built-it shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n"},
	"echo -ne '\\x48\\x6f\\x6c\\x6c\\x61\\x46\\x6f\\x72\\x41\\x6c\\x6c\\x61\\x68\\x0a'\r\n": {"\x48\x6f\x6c\x6c\x61\x46\x6f\x72\x41\x6c\x6c\x61\x68\x0arn"},
	"cat | sh": {""},
	"echo -e \\x6b\\x61\\x6d\\x69/dev > /dev/.nippon": {""},
	"cat /dev/.nippon": {"kami/dev"},
	"rm /dev/.nippon":  {""},
	"echo -e \\x6b\\x61\\x6d\\x69/run > /run/.nippon": {""},
	"cat /run/.nippon":              {"kami/run"},
	"rm /run/.nippon":               {""},
	"cat /bin/sh":                   {"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x28\x00\x01\x00\x00\x00\x98\x30\x00\x00\x34\x00\x00\x00"},
	"/bin/busybox ps":               {"1 pts/21   00:00:00 init"},
	"/bin/busybox cat /proc/mounts": {"tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=3231524k,mode=755 0 0"},
	"/bin/busybox echo -e \\x6b\\x61\\x6d\\x69/dev > /dev/.nippon": {""},
	"/bin/busybox cat /dev/.nippon":                                {"kami/dev"},
	"/bin/busybox rm /dev/.nippon":                                 {""},
	"/bin/busybox echo -e \\x6b\\x61\\x6d\\x69/run > /run/.nippon": {""},
	"/bin/busybox cat /run/.nippon":                                {"kami/run"},
	"/bin/busybox rm /run/.nippon":                                 {""},
	"/bin/busybox cat /bin/sh":                                     {""},
	"/bin/busybox cat /bin/echo":                                   {"/bin/busybox cat /bin/echo\r\n\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00\x6c\xb9\x00\x00\x34\x00\x00\x00"},
	"rm /dev/.human":                                               {"rm: can't remove '/.t': No such file or directory\r\nrm: can't remove '/.sh': No such file or directory\r\nrm: can't remove '/.human': No such file or directory\r\ncd /dev"},
}

// WriteTelnetMsg writes a telnet message to the connection
func WriteTelnetMsg(conn net.Conn, msg string, logger Logger, h Honeypot) error {
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}
	ck := freki.NewConnKeyByString(host, port)
	md := h.ConnectionByFlow(ck)

	logger.Info(
		"telnet send",
		zap.String("handler", "telnet"),
		zap.String("msg", fmt.Sprintf("%q", msg)),
		zap.String("direction", "send"),
		zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		zap.String("src_ip", host),
		zap.String("src_port", port),
	)
	return h.Produce(conn, md, []byte(msg))
}

// ReadTelnetMsg reads a telnet message from a connection
func ReadTelnetMsg(conn net.Conn, logger Logger, h Honeypot) (string, error) {
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return msg, err
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		logger.Error(fmt.Sprintf("error: %v", err))
	}
	ck := freki.NewConnKeyByString(host, port)
	md := h.ConnectionByFlow(ck)

	logger.Info(
		"telnet recv",
		zap.String("handler", "telnet"),
		zap.String("msg", fmt.Sprintf("%q", msg)),
		zap.String("direction", "recv"),
		zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		zap.String("src_ip", host),
		zap.String("src_port", port),
	)
	return msg, h.Produce(conn, md, []byte(msg))
}

func getSample(cmd string, logger Logger, h Honeypot) error {
	url := cmd[strings.Index(cmd, "http"):]
	url = strings.Split(url, " ")[0]
	client := http.Client{
		Timeout: time.Duration(5 * time.Second),
	}
	logger.Info(fmt.Sprintf("getSample target URL: %s", url))
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New("getSample read http: error: Non 200 status code on getSample")
	}
	defer resp.Body.Close()
	if resp.ContentLength <= 0 {
		return errors.New("getSample read http: error: Empty response body")
	}
	bodyBuffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bodyBuffer)
	// Ignoring errors for if the folder already exists
	if err = os.MkdirAll("samples", os.ModePerm); err != nil {
		return err
	}
	sha256Hash := hex.EncodeToString(sum[:])
	path := filepath.Join("samples", sha256Hash)
	if _, err = os.Stat(path); err == nil {
		logger.Info("getSample already known", zap.String("sha", sha256Hash))
		return nil
	}
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = out.Write(bodyBuffer)
	if err != nil {
		return err
	}
	logger.Info(
		"new sample fetched from telnet",
		zap.String("handler", "telnet"),
		zap.String("sha256", sha256Hash),
		zap.String("source", url),
	)
	return nil
}

type player struct {
	health   int
	crowbar  bool
	bandages bool
	location string
}

func Intro(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	p := player{
		health:   5,
		crowbar:  false,
		bandages: false,
		location: "start",
	}
	if err := WriteTelnetMsg(conn, "You wake up alone, darkness cloaking the surrounding area.", logger, h); err != nil {
		return err
	}
	time.Sleep(time.Second)
	if err := WriteTelnetMsg(conn, "The air is musty and a root digs into your back and as you right yourself you find a flashlght laying on the ground next to you\n As you flick it on, you can see a trail leading to a structure in the distance, you can also hear water flowing in the opposite direction. Where do you go? (Water, Structure, Stay)", logger, h); err != nil {
		if err := WriteTelnetMsg(conn, "The lock clicks open and you finally have the means to escape your dire fate thanks to your amazing knowledge of Censys :)", logger, h); err != nil {
			return err
		}
		return err
	}
	msg, err := ReadTelnetMsg(conn, logger, h)
	if err != nil {
		return err
	}
	switch msg {
	case "Water":
		p.location = "waterfall"
	case "Structure":
		p.location = "cabin"
	default:
		if err := WriteTelnetMsg(conn, "You hear heavy breathing behind you, terrified you're frozen in place. Before you can turn around something crashes into the back of your head and all goes dark", logger, h); err != nil {
			return err
		}
		return
	}
}

func Waterfall_Encounter(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	if err := WriteTelnetMsg(conn, "As you walk to the sound, the trees start to deminish in frequency and a large body of water comes into view\nThere's a shed that has a padlock on it that holds 4 digits. As you examine the door you can see scratches carved into the door. How many more services does Censys scan compared to Shodan? What do you input?", logger, h); err != nil {
		return err
	}
	msg, err := ReadTelnetMsg(conn, logger, h)
	if err != nil {
		return err
	}
	for msg != "2733" {
		if err := WriteTelnetMsg(conn, "Nothing happens. Try again", logger, h); err != nil {
			return err
		}
		msg, err := ReadTelnetMsg(conn, logger, h)
		if err != nil {
			return err
		}
	}
	if err := WriteTelnetMsg(conn, "The lock clicks open and you finally have the means to escape your dire fate thanks to your amazing knowledge of Censys :)", logger, h); err != nil {
		return err
	}
}

func Cabin_Encounter(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	if err := WriteTelnetMsg(conn, "You wander into a small wooden cabin. Inside is dark - a lone candle burns low on the opposite end, providing just enough light for you to see 2 doors. You open both and see that one shows a ladder which goes up towards an attic, and behind the other is a kitchen, where someone has left a pot of soup boiling over an open fire. Which way do you go? (Attic, Kitchen)", logger, h); err != nil {
		return err
	}
}

// msg, err := ReadTelnetMsg(conn, logger, h)
/*if msg == "Kitchen" {

}*/

// HandleTelnet handles telnet communication on a connection
func HandleTelnet(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("failed to close telnet connection", zap.Error(err))
		}
	}()

	if err := WriteTelnetMsg(conn, "> ", logger, h); err != nil {
		return err
	}
}
