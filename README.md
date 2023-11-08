# hanko-passkey-example

## Setup

1. Install dependencies with `npm i`
2. Run:

```
PASSKEY_TENANT_ID=<your tenant id> PASSKEY_SECRET_API_KEY=<your secret api key> node ./index.js
```

Then go to [localhost:3000](http://localhost:3000) and try it out!

The example has two accounts you can try:

-   **John Doe** / **`password123`**
-   **Omar Doe** / **`SHUSHforTHISisAsecret`**

Log in with one, then click on "register passkey". You'll be prompted to select a passkey to add to the account you're logged in with.
