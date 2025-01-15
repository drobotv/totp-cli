package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

var salt = []byte("42069")

func deriveKey(password string) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 1<<15, 8, 1, chacha20poly1305.KeySize)
}

type model struct {
	state         string // login, main, addService, addSecret
	passwordInput string
	masterKey     []byte
	cursor        int

	errMsg string
	errExp time.Time
}

func initialModel() model {
	return model{
		state: "login",
	}
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Init() tea.Cmd {
	return tickCmd()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.state {
	case "login":
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "enter":
				key, err := deriveKey(m.passwordInput)
				if err != nil {
					m.errMsg = "Key derivation failed"
					m.errExp = time.Now().Add(5 * time.Second)
					return m, nil
				}
				m.masterKey = key
				m.state = "main"
				return m, nil
			case "q", "esc", "ctrl+c":
				return m, tea.Quit
			case "backspace":
				if len(m.passwordInput) > 0 {
					m.passwordInput = m.passwordInput[:len(m.passwordInput)-1]
				}
			default:
				if msg.Type == tea.KeyRunes {
					m.passwordInput += string(msg.Runes)
				}
			}
		case tickMsg:
			return m, tickCmd()
		}
	case "main":
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "q", "esc", "ctrl+c":
				return m, tea.Quit
			}
		case tickMsg:
			return m, tickCmd()
		}
	}
	return m, nil
}

func (m model) View() string {
	switch m.state {
	case "login":
		return loginView(m)
	case "main":
		return mainView(m)
	case "addService":
		return "Add Service"
	case "addSecret":
		return "Add Secret"
	default:
		return "Unknown"
	}
}

func loginView(m model) string {
	return "Enter master password: " + strings.Repeat("*", len(m.passwordInput)) + "\n"
}

func mainView(m model) string {
	return string(m.masterKey)
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Println("Error starting program:", err)
	}
}
