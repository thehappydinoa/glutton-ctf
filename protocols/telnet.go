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
	"gorm.io/gorm/logger"
)

const Flag = "ctf{36538663-11e6-4869-bdbf-6ab10d757fc7}"

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
	location string
}

func Intro(p player, ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	if err := WriteTelnetMsg(conn, "Helpful Links: https://search.censys.io/search/language?resource=hosts\nhttps://www.dcode.fr/en\nhttps://app.censys.io/", logger, h); err != nil {
		return err
	}
	if err := WriteTelnetMsg(conn, "You wake up alone, darkness cloaking the surrounding area.", logger, h); err != nil {
		return err
	}
	time.Sleep(time.Second)
	if err := WriteTelnetMsg(conn, "The air is musty and a root digs into your back and as you right yourself you find a flashlght laying on the ground next to you\n As you flick it on, you can see a trail leading to a structure in the distance, you can also hear water flowing in the opposite direction. Where do you go? (Water, Structure, Stay)", logger, h); err != nil {
		return err
	}
	msg, err := ReadTelnetMsg(conn, logger, h)
	if err != nil {
		return err
	}
	switch msg {
	case "Water":
		p.location = "water"
	case "Structure":
		p.location = "cabin"
	default:
		p.location = "default"
	}
}

func healthDecrement(p player) (string, bool) {
	p.health -= 1
	switch p.health {
	case 4:
		return "Nothing happens. You feel unsettled, but you try again.", false
	case 3:
		return "Nothing happens. The feeling grows in intensity and you can feel a distracting thrumming in you head. Try again.", false
	case 2:
		return "Nothing happens. You catch yourself staring at the cracks in the door, your focus slipping. Try again.", false
	case 1:
		return "Nothing happens. Should you be doing something? Should you try again?", false
	case 0:
		return "Nothing happens. It's safe here. You sit down by the door and decide to rest.", true
		if err := conn.Close(); err != nil {
			logger.Error("failed to close telnet connection", zap.Error(err))
		}
	}
}

func PayphoneEncounter(p player, ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	puzzleIntro := "As you walk towards the sound of flowing water, the trees start to deminish in frequency as a large body of water comes into view. You see a lone payphone booth near the beach; maybe you can find what you need here? Approaching the booth you see what you think are bones scattered around the inside of the door. The next thing that catches your eye is a series of notes pinned to the wall accompanied by the phone. You read the note."
	puzzleOne := "izl{36538663-11k6-4869-hjhl-6gh10j757li7}"
	answerOne := Flag
	if err := WriteTelnetMsg(conn, puzzleOne, logger, h); err != nil {
		return err
	}
	msg, err := ReadTelnetMsg(conn, logger, h)
	if err != nil {
		return err
	}
	for msg != answerOne {
		warningMsg, alive := healthDecrement(p)
		if err := WriteTelnetMsg(conn, warningMsg, logger, h); err != nil {
			return err
		}
		if !alive {
			if err := conn.Close(); err != nil {
				logger.Error("failed to close telnet connection", zap.Error(err))
			}
		}
		msg, err := ReadTelnetMsg(conn, logger, h)
		if err != nil {
			return err
		}
	}
	if err := WriteTelnetMsg(conn, "A strong sense of accomplishment fills you.", logger, h); err != nil {
		return err
	}
	//QUESTION ONE PASSED
	if err := conn.Close(); err != nil {
		logger.Error("failed to close telnet connection", zap.Error(err))
	}
}

func Cabin_Encounter(p player, ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	puzzleIntro := "You step cautiously into the cabin. The space is dimly lit by the screen of a single laptop, clearly recently used. You approach carefully, and see a logo of several intersecting circles of some myserious site on the screen. Large across the center is a search field. A note has been taped to the corner of the screen, reading 'I hope you've learned how to search. Complete the following challenges in 5 tries if you value your life'. To any normal person, this would be a frightening thing to read. You however, are confident in your search skills, and waste no time in tackling the problems:"
	question1 := "If the banner is exactly equal to -> and the service port is on 17000, what kinds of hosts (OS) are returned? (no spaces)"
	question2 := "The following search contains an error: services.http.html_title: \"Metasploit\" AND (services.tls.certificates.leaf_data.subject.organization: \"Rapid7\" OR services.tls.certificates.leaf_data.subject.common_name: \"MetasploitSelfSignedCA\"). What word needs to be added to fix it?"
	question3 := "You want to search for exposed environment variables on hosts with HTTP services. Fill in the blank: _________ \"consumer_key\", \"aws_secret\", \"db_password\", \"aws_key\", \"github_token\", \"encryption_key\", \"aws_token\", \"aws_access_key\", `S3_SECRET_ACCESS_KEY`, `AWS_ACCESS_KEY_ID`}"
	answer1 := "bosesoundtouch"
	answer2 := "response"
	answer3 := "services.http.response.body: {"
	questions := [3]string{question1, question2, question3}
	answers := [3]string{answer1, answer2, answer3}
	index := 0
	tries := 0
	if err := WriteTelnetMsg(conn, puzzleIntro, logger, h); err != nil {
		return err
	}
	for correct < 3 && tries < 5 {
		if err := WriteTelnetMsg(conn, questions[index], logger, h); err != nil {
			return err
		}
		msg, err := ReadTelnetMsg(conn, logger, h)
		if msg == answers[index] {
			index++
		} else {
			if err := WriteTelnetMsg(conn, "Incorrect, try again.", logger, h); err != nil {
				return err
			}
		}
		tries++
	}
	if tries > 5 {
		if err := WriteTelnetMsg(conn, "All of a sudden the computer shuts off and the room goes black. You stumbled wildly towards the door, but you feel nothing but solid wall. Desperation rises, but nothing changes and eventually you realize the note may have been serious...", logger, h); err != nil {
			return err
		}
	} else {
		if err := WriteTelnetMsg(conn, Flag, logger, h); err != nil {
			return err
		}
		if err := conn.Close(); err != nil {
			logger.Error("failed to close telnet connection", zap.Error(err))
		}
	}
	if err := conn.Close(); err != nil {
		logger.Error("failed to close telnet connection", zap.Error(err))
	}
}
func FenceEncounter(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	puzzleOne := "What does ASM stand for? Rumors are that the last tenent was stabbed 10 times.\nThe loud sounds of the payphone are deafening as you enter the following into the phone..."
	answerOne := "Attack Surface Management"
	puzzleTwo := "How would you search for all hosts with with HTTP with a status code of 300?"
	answerTwo := "services.http.response.status_code: 300"
	puzzleThree := "What wildcard indicates a single character for partial matches?"
	answerThree := "?"
	puzzleFour := "Out of AND, OR, NOR, and NOT, what logic operation is not included in search?"
	answerFour := "NOR"
	encounterIntro = "You decide to stay put, however after a few moments of silence you can see lights flashing behind some trees. Curious you decide to investigate. Walking towards these lights cautiously, a massive bulding comes into view. It looks to be a research facility. Walking to the gate, you find a terminal with a series of questions. You start to read"

	if err := WriteTelnetMsg(conn, puzzleOne, logger, h); err != nil {
		return err
	}
	msg, err := ReadTelnetMsg(conn, logger, h)
	if err != nil {
		return err
	}
	for msg != answerOne {
		warningMsg, alive := healthDecrement(p)
		if err := WriteTelnetMsg(conn, warningMsg, logger, h); err != nil {
			return err
		}
		if !alive {
			if err := conn.Close(); err != nil {
				logger.Error("failed to close telnet connection", zap.Error(err))
			}
		}
		msg, err := ReadTelnetMsg(conn, logger, h)
		if err != nil {
			return err
		}
	}
	if err := WriteTelnetMsg(conn, puzzleThree, logger, h); err != nil {
		return err
	}
	msg, err := ReadTelnetMsg(conn, logger, h)
	if err != nil {
		return err
	}
	for msg != answerThree {
		warningMsg, alive := healthDecrement(p)
		if err := WriteTelnetMsg(conn, warningMsg, logger, h); err != nil {
			return err
		}
		if !alive {
			if err := conn.Close(); err != nil {
				logger.Error("failed to close telnet connection", zap.Error(err))
			}
		}
		msg, err := ReadTelnetMsg(conn, logger, h)
		if err != nil {
			return err
		}
	}
	//QUESTION TWO PASSED
	if err := WriteTelnetMsg(conn, puzzleFour, logger, h); err != nil {
		return err
	}
	msg, err := ReadTelnetMsg(conn, logger, h)
	if err != nil {
		return err
	}
	for msg != answerFour {
		warningMsg, alive := healthDecrement(p)
		if err := WriteTelnetMsg(conn, warningMsg, logger, h); err != nil {
			return err
		}
		if !alive {
			if err := conn.Close(); err != nil {
				logger.Error("failed to close telnet connection", zap.Error(err))
			}
		}
		msg, err := ReadTelnetMsg(conn, logger, h)
		if err != nil {
			return err
		}
	}
	if err := WriteTelnetMsg(conn, "A message apears on the screen. You leave the facility sucessful.", logger, h); err != nil {
		return err
	}
	if err := WriteTelnetMsg(conn, Flag, logger, h); err != nil {
		return err
	}
	if err := conn.Close(); err != nil {
		logger.Error("failed to close telnet connection", zap.Error(err))
	}
}

// HandleTelnet handles telnet communication on a connection
func HandleTelnet(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("failed to close telnet connection", zap.Error(err))
		}
	}()
	p := player{
		health:   5,
		location: "start",
	}
	Intro(p, ctx, conn, logger, h)
	switch p.location {
	case "cabin":
		Cabin_Encounter(p, ctx, conn, logger, h)
	case "water":
		PayphoneEncounter(p, ctx, conn, logger, h)
	case "default":
		FenceEncounter(p, ctx, conn, logger, h)
	}
}
