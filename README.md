
# 😎 SSRF-Detector 😎

A SSRF-Tool written in golang

**Version 1.0**

***
### 🔥 Upcoming Features 🔥
- Fetch endpoints from Javascript files
- Bruteforce parameters
- Find SSRF in those parameters
- Match multiple patterns in the response


***
### Features
- Wordlist Creation
- Inject in every parameter one by one
- Very fast speed
- Inject into paths
- Silent Mode
***

### Note

***
Make sure when creating wordlists or finding ssrf with my tool that the domains are resolved.
You can use:
- httpx
- httprobe
- massdns

To do so. 
***

### Install

**`$ go get -u github.com/ethicalhackingplayground/ssrf-tool`**

***

![GitHub Logo](carbon4.png)
  
![GitHub Logo](carbon2.png)

***

### Find SSRF with Subfinder,httpx
**`$ subfinder -d yahoo.com -silent | httpx -silent | ./ssrf-tool -pL payloads.txt -s=false -p=true -m '"Code" : "Success"'`**

***

[![Image from Gyazo](https://i.gyazo.com/4b74c62de553e2cda60e45f51c0fc8a4.gif)](https://gyazo.com/4b74c62de553e2cda60e45f51c0fc8a4)

***

### Wordlist Creation
**`$ echo "https://www.yahoo.com" | getJS -complete | ./ssrf-tool -w=true -s=false`**

***

### Wordlist Creation With Subdomains
**`$ subfinder -all -d paypal.com -silent | httpx -silent | getJS -complete | ./ssrf-tool -w=true -s=false`**

***

[![Image from Gyazo](https://i.gyazo.com/9e50667879ebc2e2d834d2db8e058cc9.gif)](https://gyazo.com/9e50667879ebc2e2d834d2db8e058cc9)



**If you get a bounty please support by buying me a coffee**

<br>
<a href="https://www.buymeacoffee.com/krypt0mux" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

