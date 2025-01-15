package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
	_ "modernc.org/sqlite"
)

var salt = []byte("42069")

func deriveKey(password string) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 1<<15, 8, 1, chacha20poly1305.KeySize)
}

func encrypt(plain string, key []byte) (string, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(plain), nil)
	combined := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

func decrypt(cipher string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		return "", err
	}
	if len(data) < chacha20poly1305.NonceSize {
		return "", fmt.Errorf("invalid data")
	}
	nonce := data[:chacha20poly1305.NonceSize]
	ciphertext := data[chacha20poly1305.NonceSize:]
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func openDB() (*sql.DB, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".totp-cli")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dir, "secrets.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	stmt := `CREATE TABLE IF NOT EXISTS services (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)`
	_, err = db.Exec(stmt)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func (m *model) loadServices() error {
	rows, err := m.db.Query("SELECT id, name, secret FROM services")
	if err != nil {
		return err
	}
	defer rows.Close()
	var svcs []service
	for rows.Next() {
		var s service
		var encSecret string
		if err := rows.Scan(&s.id, &s.name, &encSecret); err != nil {
			continue
		}
		decSecret, err := decrypt(encSecret, m.masterKey)
		if err != nil {
			continue
		}
		s.secret = decSecret
		svcs = append(svcs, s)
	}
	m.services = svcs
	return nil
}

func (m *model) addService(name, secret string) error {
	enc, err := encrypt(secret, m.masterKey)
	if err != nil {
		return err
	}
	res, err := m.db.Exec("INSERT INTO services (name, secret) VALUES (?, ?)", name, enc)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	m.services = append(m.services, service{id: int(id), name: name, secret: secret})
	return nil
}

func (m *model) deleteService(index int) error {
	if index < 0 || index >= len(m.services) {
		return nil
	}
	svc := m.services[index]
	_, err := m.db.Exec("DELETE FROM services WHERE id = ?", svc.id)
	if err != nil {
		return err
	}
	m.services = append(m.services[:index], m.services[index+1:]...)
	if m.cursor >= len(m.services) && m.cursor > 0 {
		m.cursor--
	}
	return nil
}

func (m *model) recalcCodes() {
	m.codes = make(map[int]string)
	for i, svc := range m.services {
		code, err := totp.GenerateCode(svc.secret, time.Now())
		if err != nil {
			m.codes[i] = "Error: Check validity of the provided secret"
		} else {
			m.codes[i] = code
		}
	}
}

type service struct {
	id     int
	name   string
	secret string
}

type model struct {
	state      string // login, main, addService, addSecret
	db         *sql.DB
	masterKey  []byte
	services   []service
	cursor     int
	tick       time.Time
	lastPeriod int64
	codes      map[int]string

	passwordInput string
	serviceInput  string
	secretInput   string

	errMsg string
	errExp time.Time
}

func initialModel() model {
	return model{
		state:      "login",
		codes:      make(map[int]string),
		lastPeriod: time.Now().Unix() / 30,
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
				db, err := openDB()
				if err != nil {
					m.errMsg = "Failed to open database"
					m.errExp = time.Now().Add(5 * time.Second)
					return m, nil
				}
				m.db = db
				if err := m.loadServices(); err != nil {
					m.errMsg = "Failed to load services"
					m.errExp = time.Now().Add(5 * time.Second)
					return m, nil
				}
				m.recalcCodes()
				m.passwordInput = ""
				m.state = "main"
				m.lastPeriod = time.Now().Unix() / 30
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
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.services)-1 {
					m.cursor++
				}
			case "c":
				if len(m.services) > 0 {
					if code, ok := m.codes[m.cursor]; ok {
						clipboard.WriteAll(code)
						m.errMsg = fmt.Sprintf("Code for %s copied to clipboard", m.services[m.cursor].name)
						m.errExp = time.Now().Add(5 * time.Second)
					}
				}
			case "a":
				m.state = "addService"
				m.serviceInput = ""
			case "d":
				if len(m.services) > 0 {
					_ = m.deleteService(m.cursor)
					m.recalcCodes()
				}
			}
		case tickMsg:
			period := time.Now().Unix() / 30
			if period != m.lastPeriod {
				m.lastPeriod = period
				m.recalcCodes()
			}
			if time.Now().After(m.errExp) {
				m.errMsg = ""
			}
			m.tick = time.Time(msg)
			return m, tickCmd()
		}
	case "addService":
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "enter":
				m.state = "addSecret"
				m.secretInput = ""
			case "esc":
				m.state = "main"
			case "backspace":
				if len(m.serviceInput) > 0 {
					m.serviceInput = m.serviceInput[:len(m.serviceInput)-1]
				}
			default:
				if msg.Type == tea.KeyRunes {
					m.serviceInput += string(msg.Runes)
				}
			}
		case tickMsg:
			return m, tickCmd()
		}
	case "addSecret":
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "enter":
				err := m.addService(m.serviceInput, m.secretInput)
				if err != nil {
					m.errMsg = "Failed to add service"
					m.errExp = time.Now().Add(5 * time.Second)
				} else {
					m.recalcCodes()
				}
				m.serviceInput = ""
				m.secretInput = ""
				m.state = "main"
			case "esc":
				m.state = "main"
			case "backspace":
				if len(m.secretInput) > 0 {
					m.secretInput = m.secretInput[:len(m.secretInput)-1]
				}
			default:
				if msg.Type == tea.KeyRunes {
					m.secretInput += string(msg.Runes)
				}
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
		return addServiceView(m)
	case "addSecret":
		return addSecretView(m)
	default:
		return loginView(m)
	}
}

func loginView(m model) string {
	return "Enter master password: " + strings.Repeat("*", len(m.passwordInput)) + "\n"
}

func mainView(m model) string {
	var b strings.Builder
	timeLeft := 30 - (time.Now().Unix() % 30)
	b.WriteString(fmt.Sprintf("Refresh in: %ds\n\n", timeLeft))
	b.WriteString("Services:\n")

	for i, svc := range m.services {
		cursor := " "
		if i == m.cursor {
			cursor = ">"
		}
		code := m.codes[i]
		b.WriteString(fmt.Sprintf("%s %s: %s\n", cursor, svc.name, code))
	}

	b.WriteString("\n\nPress 'a' to add a new service\nPress 'd' to delete selected service\nPress 'c' to copy code\nPress 'q' to quit\n")

	if m.errMsg != "" && time.Now().Before(m.errExp) {
		b.WriteString("Info: " + m.errMsg)
	}

	return b.String()
}

func addServiceView(m model) string {
	return "Enter service name (press Enter to confirm, Esc to cancel): " + m.serviceInput
}

func addSecretView(m model) string {
	return "Enter service secret (press Enter to confirm, Esc to cancel): " + m.secretInput
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Println("Error starting program:", err)
	}
}
