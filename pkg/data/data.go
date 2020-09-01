package data

import (
        "fmt"
        "os"
        "time"

        "github.com/briandowns/spinner"
        "github.com/logrusorgru/aurora"
)

// Save the wordlist
func saveToFile(data []string, suffix string, filename string) {

        s := spinner.New(spinner.CharSets[9], 100*time.Millisecond) // Build our new spinner
        s.Suffix = suffix
        s.Start()
        s.Color("red") // Set the spinner color to red
        time.Sleep(time.Second * 2)

        f, err := os.Create(filename)
        if err != nil {
                fmt.Println(Bold(aRed(err)))
                return
        }
        for _, v := range data {
                _, err := f.WriteString(v + "\n")
                if err != nil {
                        fmt.Println(Bold(Red(err)))
                        f.Close()
                        return
                }
        }
        f.Close()
        s.Stop()
}
