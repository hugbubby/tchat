package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
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
    if len(os.Args) != 2 {
        fmt.Println("Must provide single argument of chat recipient.")
    }
    os.Args[1] = strings.TrimSuffix(os.Args[1], ".onion")

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
    pubKey, _, err := GetKeys("onion_id_ecc")
    if err != nil {
        panic(errors.Wrap(err, "error reading encryption keys"))
    }

    messenger := make(chan Message)

    app := tview.NewApplication()
    chatWindow := tview.NewInputField()
    chatWindow.SetDoneFunc(messageDoneFunc(messageDoneFuncInput{
        app:         app,
        conf:        conf,
        messenger:   messenger,
        item:        chatWindow,
        destination: os.Args[1],
        pubKey:      pubKey,
    }))

    chatView := tview.NewTextView()

    flex := tview.NewFlex().
    SetDirection(tview.FlexRow).
    AddItem(chatView, 0, 30, true).
    AddItem(chatWindow, 0, 1, true)

    go func() {
        err := syncChatLog(conf, messenger, chatView)
        app.Stop()
        log.Fatal(err)
    }()

    if err = app.SetRoot(flex, true).SetFocus(chatWindow).Run(); err != nil {
        app.Stop()
        log.Fatal(err)
    }
}

func serviceMessage(err error) Message {
    return Message{
        ServiceID: "(System)",
        Content:   err.Error(),
    }
}

type messageDoneFuncInput struct {
    app         *tview.Application
    conf        Config
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
        if b, err := json.Marshal(msg); err != nil {
            return msg, nil, err
        } else {
            resp, err := http.PostForm("http://"+inp.conf.PrivateServerAddress+"/send", url.Values{
            "destination": []string{inp.destination},
            "message":     []string{string(b)},
        })
        return msg, resp, err
    }
}
return func(key tcell.Key) {
    message, resp, err := sendMessage()
    if err != nil {
        inp.messenger <- serviceMessage(errors.Wrap(err, "error sending message"))
    } else if resp.StatusCode != 200 {
        b, err := ioutil.ReadAll(resp.Body)
        if err == nil {
            inp.messenger <- serviceMessage(
                errors.New(
                    fmt.Sprintf("error sending message: received status code %d: %s", resp.StatusCode, string(b)),
                ),
            )
        } else {
            inp.messenger <- serviceMessage(
                errors.Wrap(
                    err,
                    fmt.Sprintf("error sending message: received status code %d, and could not parse body", resp.StatusCode),
                ),
            )
        }
    } else {
        inp.messenger <- message
    }
    inp.item.SetText("")
    inp.app.Draw()
}
}

func syncChatLog(conf Config, messenger chan Message, chatBox *tview.TextView) error {
    u := url.URL{Scheme: "ws", Host: conf.PrivateServerAddress, Path: "/read"}
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
                runes := []rune(msg.Content)
                for i := 0; i < len(runes); i++ {
                    if runes[i] == rune('\n') {
                        runes = append(runes[:i], runes[i+1:]...)
                    }
                }
                for i := 80; i < len(runes); i += 80 {
                    runes = append(runes[:i], append([]rune{'\n', '\t'}, runes[i:]...)...)
                }
                chatBox.SetText(chatBox.GetText(false) + msg.ServiceID + "> " + string(runes) + "\n")
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
