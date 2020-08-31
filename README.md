
# 😎 SSRF-Detector 😎

A SSRF-Tool written in golang

**Version 1.0**

### Install

**`$ go get -u github.com/ethicalhackingplayground/ssrf-tool`**

[![Image from Gyazo](https://i.gyazo.com/44ff89e18f473e337ba1e7cf9aa3d1fe.gif)](https://gyazo.com/44ff89e18f473e337ba1e7cf9aa3d1fe)


```

 _____ _____ _____ _____
|   __|   __| __  |   __|
|__   |__   |    -|   __|
|_____|_____|__|__|__|
    1.0 - @z0idsec


Usage of ./ssrf-tool:
  -a    Append the payload to the parameter
  -c int
        Set the concurrency for greater speeds (default 30)
  -m string
        Match the response with a pattern (e.g.) 'Success:'
  -p    Only test ssrf in paths
  -pL string
        The payloads list
  -s    Only print vulnerable hosts
  ```

### Fetch Links from JS with Subfinder
**`$ subfinder -d yahoo.com -silent | ./ssrf-tool -pL payloads.txt -s=false -p=true -m '"Code" : "Success"'`**




**If you get a bounty please support by buying me a coffee**

<br>
<a href="https://www.buymeacoffee.com/krypt0mux" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

