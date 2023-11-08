import express from "express";
import { jwtDecode } from "jwt-decode";
import cookieParser from "cookie-parser";

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
		},
		{
			id: "d7af38a2-562b-4561-8f6b-47e77ac33af0",
			username: "Omar Doe",
			email: "omar.doe@example.com",
			password: "SHUSHforTHISisAsecret",
		},
	],
};

const tenantId = process.env.PASSKEY_TENANT_ID;
if (!tenantId) throw new Error("Missing PASSKEY_TENANT_ID");

const apiKey = process.env.PASSKEY_SECRET_API_KEY;
if (!apiKey) throw new Error("Missing PASSKEY_SECRET_API_KEY");

const baseUrl = `https://passkey.stg.hanko.io/${tenantId}`;
const headers = { apiKey, "Content-Type": "application/json" };

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

const dirname = new URL(".", import.meta.url).pathname;
app.get("/", (req, res) => {
	res.sendFile("index.html", { root: dirname });
});

app.use(async (req, res, next) => {
	// This is not secure
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

	res.cookie("authuid", user.id);

	console.log("User logged in:", user.username);

	res.redirect("/");
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

	// This is the currently logged in user:
	const user = req.session?.user;

	if (!user) {
		res.status(401).send("Not logged in");
		return;
	}

	console.log("Starting passkey registration for user:", user.username);

	// Send the id and name of the user stored in our DB.
	// (both fields are required)
	const creationOptions = await fetch(baseUrl + "/registration/initialize", {
		method: "POST",
		headers,
		body: JSON.stringify({
			user_id: user.id.toString(), // Must be a string!
			username: user.username,
		}),
	}).then((res) => res.json());

	console.log("Passkey registration started:", creationOptions);

	creationOptions.publicKey.authenticatorSelection = {
		requireResidentKey: false,
		userVerification: "preferred",
		residentKey: "preferred",
	};

	creationOptions.publicKey.extensions = { credProps: true };

	// creationOptions is an object that can directly be passed to create(...)
	// (the function that opens the "create passkey" dialog) on the frontend.
	res.json(creationOptions);
});

app.post("/passkey/finalize-registration", async (req, res) => {
	const data = await fetch(baseUrl + "/registration/finalize", {
		method: "POST",
		headers,
		body: JSON.stringify(req.body), // Forward the newly created credential
	}).then((res) => res.json());

	// The response from the Passkey API contains a JWT (`data.token`).
	// What you do with this JWT is up to you.
	//
	// Here, we don't need to do anything with it, since the user already
	// is logged in. In the login endpoints, later in this guide, we'll
	// use the data contained in the JWT to create a session for our user.

	console.log("Done: passkey registration finalized!", data);

	res.redirect("/");
});

// ---------- Passkey login ----------
app.post("/passkey/start-login", async (req, res) => {
	if (req.session) {
		res.status(409).send("Already logged in");
		return;
	}

	const loginOptions = await fetch(baseUrl + "/login/initialize", {
		method: "POST",
		headers,
	}).then((res) => res.json());

	// loginOptions is an object that can directly be passed to get()
	// (the function that opens the "select passkey" dialog)
	// in the frontend.
	res.json(loginOptions);
});

app.post("/passkey/finalize-login", async (req, res) => {
	const data = await fetch(baseUrl + "/login/finalize", {
		method: "POST",
		headers,
		body: JSON.stringify(req.body), // Forward the credential the user selected
	}).then((res) => res.json());

	const jwt = jwtDecode(data.token);

	// The JWT's...
	// - "sub" claim is the user_id we sent in /registration/initialize
	// - "cred" claim is the credential_id (the ID of the credential the user chose to log in with)
	// - "aud" always is the ID of the relying party (your app)
	res.cookie("authuid", jwt.sub);

	res.redirect("/");
});

app.listen(3000);
console.info("Listening on http://localhost:3000");
