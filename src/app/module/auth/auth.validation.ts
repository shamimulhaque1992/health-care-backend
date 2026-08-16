import z from "zod";

const PatientRegistrationZodSchema = z.object({
	name: z
		.string("Not a string!!")
		.min(3, "Name must be at least 3 characters long")
		.max(10, "Name must be at most 10 characters long")
		.trim(),
	email: z.email("Invalid email address").trim(),
	password: z
		.string("Not a string!!")
		.min(6, "Password must be at least 6 characters long")
		.max(100, "Password must be at most 100 characters long")
		.regex(/[a-z]/, "Password must contain atleast 1 Lowercase Letter")
		.regex(/[A-Z]/, "Password must contain atleast 1 Uppercase Letter")
		.regex(/[0-9]/, "Password must contain atleast 1 Number")
		.regex(/[^A-Za-z0-9]/, "Password must contain atleast 1 Special Character")
		.trim(),
});
const LoginZodSchema = z.object({
	email: z.email(),
	password: z
		.string()
		.min(8, "Password Must Minimum 8 Characters Long.")
		.regex(/[a-z]/, "Password must contain atleast 1 Lowercase Letter")
		.regex(/[A-Z]/, "Password must contain atleast 1 Uppercase Letter")

		.regex(/[0-9]/, "Password must contain atleast 1 Number")
		.regex(/[^A-Za-z0-9]/, "Password must contain atleast 1 Special Character"),
});

export const UserValidation = {
	PatientRegistrationZodSchema,
	LoginZodSchema,
};
