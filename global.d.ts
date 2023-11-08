interface User {
	// We don't store the passkey at all - the Hanko Passkey API does!
	// This means it'll work with our existing auth system and database schema.
	// The only requirements are two things: a unique user ID and a username-like field (could also be an email, for example)
	id: string;
	username: string;
	email: string;
	password: string;
}

namespace Express {
	interface Request {
		session?: {
			user: User;
		};
	}
}
