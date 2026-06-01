package baseline

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "time"
)

type BaselineEntry struct {
    Hash     string    `json:"hash"`
    LastSeen time.Time `json:"last_seen"`
}

func hashFile(path string) string {

    f, err := os.Open(path)
    if err != nil {
        return ""
    }
    defer f.Close()

    h := sha256.New()
    io.Copy(h, f)

    return hex.EncodeToString(h.Sum(nil))
}

func ScanAndStore(dirs []string) {

    baseline := make(map[string]BaselineEntry)

    fmt.Println("[BASELINE MODE]")
    fmt.Println("Scanning filesystem...")

    for _, dir := range dirs {

        filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {

            if err != nil || info.IsDir() {
                return nil
            }

            hash := hashFile(path)

            baseline[path] = BaselineEntry{
                Hash:     hash,
                LastSeen: time.Now(),
            }

            fmt.Println(path, "→ hash stored")

            return nil
        })
    }

    data, _ := json.MarshalIndent(baseline, "", "  ")

    os.WriteFile("config/baseline.json", data, 0644)

    fmt.Println("Baseline saved successfully")
}
