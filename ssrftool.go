package main

import (
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
	flag.IntVar(&concurrency, "c", 30, "Set the concurrency for greater speeds")
	flag.StringVar(&payloads, "pL", "", "The payloads list")
	flag.StringVar(&match, "m", "", "Match the response with a pattern (e.g.) 'Success:'")
	flag.BoolVar(&appendMode, "a", false, "Append the payload to the parameter")
	flag.BoolVar(&paths, "p", false, "(true or false) for testing paths or parameters")
	flag.BoolVar(&silent, "s", false, "silent output")
	flag.Parse()

	if payloads != "" && match != "" {

		s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)  // Build our new spinner
		s.Suffix =" Please be patient"
		s.Start()
		s.Color("red") // Set the spinner color to red
		time.Sleep(time.Second * 2)
		if silent == false { s.Stop() }
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
	}else {
		flag.PrintDefaults()
	}
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
