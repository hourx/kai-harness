package program

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidationGate renders the Skeptic checklist with the answers kai already
// knows. It does not validate anything: every conclusion is left blank for the
// agent, and every prefill states what file it came from. A missing file is
// "unknown", never permission.
func ValidationGate(pDir string) (string, error) {
	name := filepath.Base(pDir)
	scope := readGateFile(filepath.Join(pDir, "scope.txt"))
	outScope := readGateFile(filepath.Join(pDir, "out-of-scope.txt"))
	bound := readGateFile(filepath.Join(pDir, "boundaries.md"))
	dupes := readGateFile(filepath.Join(pDir, "findings", "dupes.md"))
	lessons := readGateFile(filepath.Join(pDir, "findings", "lessons.md"))

	var in Intake
	if b, err := os.ReadFile(filepath.Join(pDir, "intake.json")); err == nil {
		_ = json.Unmarshal(b, &in)
	}
	submission := in.Boundaries.SubmissionChannel
	if submission == "" {
		submission = "unknown — tidak ditemukan di program page"
	}
	contacts := strings.Join(in.Boundaries.SubmissionContact, ", ")
	if contacts == "" {
		contacts = "tidak ada kontak publik yang tercatat"
	}

	queue := 0
	if b, err := os.ReadFile(filepath.Join(pDir, "next.json")); err == nil {
		var plan struct {
			Items []struct {
				Target string `json:"target"`
			} `json:"items"`
		}
		if json.Unmarshal(b, &plan) == nil {
			queue = len(plan.Items)
		}
	}

	ledger := "belum ada ledger"
	if b, err := os.ReadFile(filepath.Join(pDir, "findings", "ledger.json")); err == nil {
		var doc struct {
			Findings []json.RawMessage `json:"findings"`
		}
		if json.Unmarshal(b, &doc) == nil {
			ledger = fmt.Sprintf("%d entri di findings/ledger.json", len(doc.Findings))
		} else {
			var arr []json.RawMessage
			if json.Unmarshal(b, &arr) == nil {
				ledger = fmt.Sprintf("%d entri di findings/ledger.json", len(arr))
			} else if len(strings.TrimSpace(string(b))) > 2 {
				ledger = "findings/ledger.json ada (format tidak dikenali)"
			}
		}
	}

	var out strings.Builder
	fmt.Fprintf(&out, "# Validation gate — %s\n\n", name)
	out.WriteString("Dibuat otomatis oleh `kai export`. Prefill berasal dari file; ")
	out.WriteString("semua kesimpulan masih kosong dan wajib diisi Skeptic.\n\n")

	fmt.Fprintf(&out, "1. **Scope**: apakah target lolos aturan?\n   - scope.txt: %s\n   - out-of-scope.txt: %s\n   - JAWABAN: ______\n\n",
		gateSummary(scope, "tidak ada scope.txt — jangan menebak"),
		gateSummary(outScope, "tidak ada out-of-scope.txt — anggap unknown"))

	fmt.Fprintf(&out, "2. **Aturan program**: apakah kelas dampak diterima?\n   - boundaries.md: %s\n   - JAWABAN: ______\n\n",
		gateSummary(bound, "tidak ada boundaries.md — jalankan `kai boundaries "+name+"`"))

	fmt.Fprintf(&out, "3. **Bukti**: apakah ada PoC/reproducible?\n   - %s\n   - antrian kai: %d hipotesis\n   - JAWABAN: ______\n\n",
		ledger, queue)

	fmt.Fprintf(&out, "4. **Duplikat**: apakah sudah dilaporkan sebelumnya?\n   - dupes.md: %s\n   - lessons.md: %s\n   - JAWABAN: ______\n\n",
		gateSummary(dupes, "tidak ada catatan duplikat"),
		gateSummary(lessons, "tidak ada pelajaran tercatat"))

	fmt.Fprintf(&out, "5. **Kanal submit**: apakah ini kanal resmi?\n   - kanal: %s\n   - kontak: %s (kontak bukan kanal)\n   - JAWABAN: ______\n\n",
		submission, contacts)

	fmt.Fprintf(&out, "6. **Penyerang & korban**: siapa yang harus punya akses, dan siapa yang terdampak?\n   - JAWABAN: ______\n\n")
	fmt.Fprintf(&out, "7. **Reproduksi 3x**: apakah bisa diulang dari nol dengan langkah tertulis?\n   - JAWABAN: ______\n")

	return out.String(), nil
}

func readGateFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func gateSummary(text, empty string) string {
	if strings.TrimSpace(text) == "" {
		return empty
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > 3 {
		lines = lines[:3]
	}
	return strings.Join(lines, " | ")
}
