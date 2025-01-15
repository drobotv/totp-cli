package main

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type model struct {
	state         string // login, main, addService, addSecret
	passwordInput string
	masterKey     []byte
	cursor        int
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
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q":
			return m, tea.Quit
		}
	case tickMsg:
		return m, tickCmd()
	}
	return m, nil
}

func (m model) View() string {
	return "Init view"
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Println("Error starting program:", err)
	}
}
