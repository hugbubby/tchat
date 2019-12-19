package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/gdamore/tcell"
	"github.com/gorilla/websocket"
	. "github.com/hugbubby/tchatlib"
	"github.com/hugbubby/torgo"
	"github.com/pkg/errors"
	"github.com/rivo/tview"
	"golang.org/x/crypto/ed25519"
)

func main() {
	conf, err := func() (Config, error) {
		var config Config
		b, err := ioutil.ReadFile(ConfigPath("config.json"))
		if err == nil {
			err = json.Unmarshal(b, &config)
			if err == nil && config.Tor.ProxyAddress == "" {
				config.Tor.ProxyAddress = "127.0.0.1:9050"
				if b, err = json.Marshal(config); err == nil {
					err = ioutil.WriteFile(ConfigPath("config.json"), b, 0600)
				}
			}
		}
		return config, err
	}()
	if err != nil {
		panic(errors.Wrap(err, "error reading config file"))
	}

	//Load public and private keys from disk
	pubKey, privKey, err := GetKeys()
	if err != nil {
		panic(errors.Wrap(err, "error reading encryption keys"))
	}

	messenger := make(chan Message)

	chatWindow := tview.NewInputField()
	chatWindow.SetDoneFunc(messageDoneFunc(messageDoneFuncInput{
		conf:        conf,
		messenger:   messenger,
		item:        chatWindow,
		destination: os.Args[1],
		pubKey:      pubKey,
		privKey:     privKey,
	}))

	chatList := tview.NewList()

	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(chatList, 0, 30, true).
		AddItem(chatWindow, 0, 1, true)
	app := tview.NewApplication()
	go func() {
		err := syncChatLog(conf, messenger, chatList)
		app.Stop()
		panic(err)
	}()

	if err = app.SetRoot(flex, true).SetFocus(chatWindow).Run(); err != nil {
		panic(err)
	}
}

func serviceMessage(err error) Message {
	return Message{
		ServiceID: "(System)",
		Content:   err.Error(),
	}
}

type messageDoneFuncInput struct {
	conf        Config
	privKey     ed25519.PrivateKey
	pubKey      ed25519.PublicKey
	messenger   chan<- Message
	destination string
	item        *tview.InputField
}

func messageDoneFunc(inp messageDoneFuncInput) func(key tcell.Key) {
	serviceID, err := torgo.ServiceIDFromEd25519(inp.pubKey)
	if err != nil {
		panic(errors.Wrap(err, "could not get service id from public key:"))
	}
	inp.destination = strings.TrimSuffix(inp.destination, ".onion")
	sendMessage := func() (Message, *http.Response, error) {
		var msg = Message{
			ServiceID: serviceID,
			Content:   inp.item.GetText(),
		}
		if c, err := torgo.NewClient(inp.conf.Tor.ProxyAddress); err != nil {
			return msg, nil, err
		} else {
			if b, err := json.Marshal(msg); err != nil {
				return msg, nil, err
			} else {
				msgEnc := base64.RawStdEncoding.EncodeToString(b)
				sig := ed25519.Sign(inp.privKey, b)
				sigEnc := base64.RawStdEncoding.EncodeToString(sig)
				vals := make(url.Values)
				vals["signature"] = []string{sigEnc}
				vals["message"] = []string{msgEnc}
				resp, err := c.PostForm(inp.destination+".onion/send", vals)
				return msg, resp, err
			}
		}
	}
	return func(key tcell.Key) {
		message, resp, err := sendMessage()
		if err != nil {
			inp.messenger <- serviceMessage(errors.Wrap(err, "error sending message"))
		} else if resp.StatusCode != 200 {
			inp.messenger <- serviceMessage(errors.New("error sending message: received status code " + fmt.Sprintf("%d", resp.StatusCode)))
		} else {
			inp.item.SetText("")
			inp.messenger <- message
		}
	}
}

func syncChatLog(conf Config, messenger chan Message, chatList *tview.List) error {
	u := url.URL{Scheme: "ws", Host: conf.ServerAddress, Path: "/read"}
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return errors.Wrap(err, "could not connect to tchatd server")
	}
	if err = conn.WriteMessage(websocket.TextMessage, []byte(conf.ReadCookie)); err == nil {
		if _, p, err := conn.ReadMessage(); err == nil {
			if !reflect.DeepEqual(p, []byte("accepted")) {
				return errors.New("failed to authenticate to tchatd server")
			}
		} else {
			return errors.Wrap(err, "could not authenticate to tchatd server")
		}
	} else {
		return errors.Wrap(err, "could not authenticate to tchatd server")
	}

	defer conn.Close()

	go func() {
		for {
			select {
			case msg := <-messenger:
				chatList.AddItem(msg.ServiceID+"> "+msg.Content, "", 0, nil)
			}
		}
	}()

	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			messenger <- Message{
				ServiceID: "(System)",
				Content:   errors.Wrap(err, "An error occured parsing this message:").Error(),
			}
		} else {
			messenger <- msg
		}
	}
}
