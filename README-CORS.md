# CORS

Link: <https://developer.mozilla.org/de/docs/Web/HTTP/CORS>

To access the event-digger app with Chrome you need to start the browser in developer mode (with web security disabled).

## For Windows

- Open the start menu
- Type windows+R or open "Run"
- Execute the following command:

  ```bat
  chrome.exe --user-data-dir="C://Chrome dev session" --disable-web-security
  ```

### For Mac

- Go to Terminal
- Execute the following command:

  ```sh
  open /Applications/Google\ Chrome.app --args --user-data-dir="/var/tmp/Chrome dev session" --disable-web-security
  ```

- A new web security disabled chrome browser should open with the following message:
- If you want to open new instance of web security disabled Chrome browser without closing existing tabs then use below command

  ```sh
  open -na Google\ Chrome --args --user-data-dir=/tmp/temporary-chrome-profile-dir --disable-web-security
  ```

- It will open new instance of web security disabled Chrome browser as shown below.
