import express from "express";
import { jwtDecode } from "jwt-decode";
import cookieParser from "cookie-parser";
import { tenant } from "@teamhanko/passkeys-sdk";

const app = express();

/**
 * Our in-memory database :)
 * This is just for the sake of the example;
 * you should use something like Postgres, MySQL, MongoDB, ...
 *
 * @type {{users: User[]}}
 */
const db = {
	users: [
		{
			id: "4e5f0181-a4e0-4202-8da1-b2d2b92f8b04",
			username: "John Doe",
			email: "john.doe@example.com",
			password: "password123",
			mfaEnabled: false,
		},
		{
			id: "d7af38a2-562b-4561-8f6b-47e77ac33af0",
			username: "Omar Doe",
			email: "omar.doe@example.com",
			password: "SHUSHforTHISisAsecret",
			mfaEnabled: false,
		},
	],
};

const tenantId = process.env.PASSKEYS_TENANT_ID;
if (!tenantId) throw new Error("Missing PASSKEYS_TENANT_ID");

const apiKey = process.env.PASSKEYS_SECRET_API_KEY;
if (!apiKey) throw new Error("Missing PASSKEYS_SECRET_API_KEY");

const passkeyApi = tenant({ apiKey, tenantId, baseUrl: "https://passkey.stg.hanko.io" });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// This cookieParser secret is required to make the MFA (two-factor) endpoints safe.
// Otherwise, we can't tell if the client modified with the "authuid-mfa" cookie (which is dangerous!)
app.use(cookieParser("c3705079e1f5c18155d5c48fe8101898"));
//                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                    In the real world, this should be an env var.

const dirname = new URL(".", import.meta.url).pathname;
app.get("/", (req, res) => {
	res.sendFile("index.html", { root: dirname });
});

app.use(async (req, res, next) => {
	// This is not secure! Kept brief for the example.
	const userId = req.cookies["authuid"];
	const user = userId && db.users.find((u) => u.id === userId);

	if (user) {
		req.session = { user };
	}

	next();
});

// ---------- Basic username/password login ----------
app.post("/username-password/login", (req, res) => {
	const { username, password } = req.body;

	const user = db.users.find((u) => u.username === username && u.password === password);

	if (!user) {
		res.status(401).send("Invalid username or password");
		return;
	}

	if (user.mfaEnabled) {
		// User has MFA enabled. Don't set authuid directly, but require a call to authuid-mfa to complete the login.
		console.log("User authenticated with username+password, but still requires MFA to log in:", user.username);

		res.cookie("authuid-mfa", user.id, { signed: true });
		res.redirect("/?mfa=required");
	} else {
		console.log("User logged in:", user.username);

		res.cookie("authuid", user.id);
		res.redirect("/");
	}
});

app.get("/me", (req, res) => {
	if (!req.session?.user) {
		res.status(401).send("Not logged in");
		return;
	}

	res.status(200).json(req.session.user);
});

app.post("/logout", (req, res) => {
	res.clearCookie("authuid");
	res.redirect("/");
});

// ---------- Passkey registration ----------
app.post("/passkey/start-registration", async (req, res) => {
	// Remember: to register a passkey, the user needs to be logged in first.
	//           Once the passkey is added to the user's account, they can
	//           use it to log in.
	//
	// This is the currently logged in user:
	const user = req.session?.user;

	if (!user) {
		res.status(401).send("Not logged in");
		return;
	}

	console.log("Starting passkey registration for user:", user.username);

	// Send the id and name of the user stored in our DB.
	// Both fields are required but can be anything you want (as long as they're unique).
	const creationOptions = await passkeyApi.registration.initialize({
		userId: user.id,
		username: user.username,
	});

	console.log("Passkey registration started:", creationOptions);

	// creationOptions is an object that can directly be passed to create() on the frontend.
	// Note: create() is the function that opens the browser's "create passkey" dialog.
	res.json(creationOptions);
});

app.post("/passkey/finalize-registration", async (req, res) => {
	const data = await passkeyApi.registration.finalize(req.body); // req.body = the newly created credential

	// The response from the Passkey API contains a JWT (`data.token`).
	// What you do with this JWT is up to you.
	//
	// You don't have to use the JWT: as long as you receive the JWT,
	// the registration was successful.
	//
	// The JWT is typically used for client-first logins.
	// See https://docs.hanko.io/passkey-api/client-first-login-flow.
	console.log("Done: passkey registration finalized!", data);

	res.redirect("/");
});

// ---------- Passkey login ----------
app.post("/passkey/start-login", async (req, res) => {
	if (req.session) {
		res.status(409).send("Already logged in");
		return;
	}

	const loginOptions = await passkeyApi.login.initialize();

	console.log("Passkey login started:", loginOptions);

	// loginOptions is an object that can directly be passed to get() on the frontend.
	// Note: get() is the function that opens the browser's "select passkey" dialog.
	res.json(loginOptions);
});

app.post("/passkey/finalize-login", async (req, res) => {
	const data = await passkeyApi.login.finalize(req.body); // req.body = the passkey the user selected

	// The JWT's...
	// - "sub"  claim is the user_id we sent in /registration/initialize
	// - "cred" claim is the credential_id (the ID of the credential the user chose to log in with)
	// - "aud"  always is the ID of the relying party (your app)
	const jwt = jwtDecode(data.token);
	res.cookie("authuid", jwt.sub);

	console.log("Done: user logged in with passkey!", data);

	res.redirect("/");
});

// ---------- MFA ----------
// Two-factor auth (where the passkey is the second factor)

app.post("/mfa/enable", async (req, res) => {
	const user = req.session?.user;

	if (!user) {
		res.status(401).send("Not logged in");
		return;
	}

	console.log("Enabling MFA for user:", user.username);

	const creationOptions = await passkeyApi.user(user.id).mfa.registration.initialize({
		userId: user.id,
		username: user.username,
	});

	res.json(creationOptions);
});

app.post("/mfa/finalize-enable", async (req, res) => {
	const user = req.session?.user;

	if (!user) {
		res.status(401).send("Not logged in");
		return;
	}

	const data = await passkeyApi.user(user.id).mfa.registration.finalize(req.body);

	// Require MFA credentials for this user to log in with username+password from now on:
	db.users.find((u) => u.id === user.id).mfaEnabled = true;

	console.log("Done: MFA enabled for user:", user.username, data);

	res.redirect("/");
});

/**
 * @type {import("express").RequestHandler}
 */
const prepareMfa = (req, res, next) => {
	const userId = req.signedCookies["authuid-mfa"];
	if (!userId) {
		res.status(401).send("Not logged in");
		return;
	}

	const user = db.users.find((u) => u.id === userId);
	if (!user) {
		res.status(401).send("Not logged in");
		return;
	}

	req.userToBeLoggedIn = user;

	next();
};

app.post("/mfa/login", prepareMfa, async (req, res) => {
	// The frontend logs in with username+password. We grab the user from our DB. Then we start the MFA login and send back the challenge (loginOptions) to the frontend.
	// When they pass the challenge (/mfa/finalize-login), we know they
	const userId = req.userToBeLoggedIn.id;

	const loginOptions = await passkeyApi.user(userId).mfa.login.initialize({
		userId,
	});

	console.log("Passkey two-factor attempt started:", loginOptions);

	res.json(loginOptions);
});

app.post("/mfa/finalize-login", prepareMfa, async (req, res) => {
	const userId = req.userToBeLoggedIn.id;

	const data = await passkeyApi.user(userId).mfa.login.finalize(req.body);

	const jwt = jwtDecode(data.token);
	res.cookie("authuid", jwt.sub);

	console.log("Done: user logged in with username+password and confirmed with second-factor passkey!", data);

	res.redirect("/?mfa=passed");
});

app.listen(3000);
console.info("Listening on http://localhost:3000");
