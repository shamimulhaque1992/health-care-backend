import bcrypt from "bcryptjs";
import crypto from "crypto";
import ejs from "ejs";
import type { TokenPayload } from "google-auth-library";
import type { JwtPayload, SignOptions } from "jsonwebtoken";
import path from "path";
import { AuthProvider, Role, UserStatus } from "../../../generated/prisma/enums";
import config from "../../config";
import { googleClient } from "../../lib/googleAuth";
import { transporter } from "../../lib/nodemailer";
import { prisma } from "../../lib/prisma";
import { redisClient } from "../../lib/redis";
import { jwtUtils } from "../../utils/jwt";
import { sendEmail } from "../../utils/sendEmail";
import type {
	IForgotPasswordPayload,
	IGoogleLoginPayload,
	ILoginUserPayload,
	IRegisterPatientPayload,
	IRequestUser,
	IResetPasswordPayload,
	IVerifyEmailPayload,
} from "./auth.interface";

const registerPatient = async (payload: IRegisterPatientPayload) => {
	const { name, password, patient: patientData } = payload;
	const email = payload.email.trim().toLowerCase();

	const isUserExists = await prisma.user.findUnique({
		where: { email },
	});

	if (isUserExists) {
		throw new Error("User with this email already exists");
	}

	const hashedPassword = await bcrypt.hash(password, 8);

	const expirationSeconds = 5 * 60;
	const otpKey = `register-patient-otp:${email}`;
	const otpValue = crypto.randomInt(100000, 1000000).toString();

	await redisClient.set(otpKey, otpValue, {
		expiration: {
			type: "EX",
			value: expirationSeconds,
		},
	});

	const patientRegistrationKey = `patient-registration-data:${email}`;
	const patientRegistrationPayload = {
		name,
		email,
		password: hashedPassword,
		patient: patientData,
	};

	await redisClient.set(
		patientRegistrationKey,
		JSON.stringify(patientRegistrationPayload),
		{
			expiration: {
				type: "EX",
				value: expirationSeconds,
			},
		},
	);

	const templateData = {
		name,
		email,
		otp: otpValue,
		expirationMinutes: expirationSeconds / 60,
	};

	await sendEmail("verify-email.ejs", templateData, {
		from: config.email_sender,
		to: email,
		subject: "Verify your email",
	});
};

const verifyUserEmail = async (payload: IVerifyEmailPayload) => {
	const { otp } = payload;
	const email = payload.email.trim().toLowerCase();

	const isUserExits = await prisma.user.findUnique({
		where: { email },
	});

	if (isUserExits?.status === UserStatus.BLOCKED) {
		throw new Error("User is blocked");
	}
	if (isUserExits?.emailVerified) {
		throw new Error("User is already verified");
	}

	if (isUserExits?.isDeleted || isUserExits?.status === UserStatus.DELETED) {
		throw new Error("User is deleted");
	}

	const otpKey = `register-patient-otp:${email}`;
	const redisOtp = await redisClient.get(otpKey);

	if (!redisOtp) {
		throw new Error("OTP has expired or is invalid");
	}

	if (redisOtp !== otp) {
		throw new Error("OTP did not match");
	}
	const patientRegistrationKey = `patient-registration-data:${email}`;
	const patientRegistrationStringifiedData = await redisClient.get(
		patientRegistrationKey,
	);

	if (!patientRegistrationStringifiedData) {
		throw new Error("Patient registration data not found");
	}

	const patientRegistrationData: IRegisterPatientPayload = JSON.parse(
		patientRegistrationStringifiedData,
	);

	const createdUser = await prisma.user.create({
		data: {
			name: patientRegistrationData.name,
			email: patientRegistrationData.email,
			password: patientRegistrationData.password,
			role: Role.PATIENT,
			status: UserStatus.ACTIVE,
			emailVerified: true,
			patient: {
				create: {
					name: patientRegistrationData.name,
					email: patientRegistrationData.email,
					contactNumber: patientRegistrationData.patient?.contactNumber || null,
				},
			},
		},
		omit: { password: true },
		include: { patient: true },
	});

	await sendEmail(
		"email-verified-success.ejs",
		{ name: createdUser.name, email: createdUser.email },
		{
			from: config.email_sender,
			to: createdUser.email,
			subject: "Email Verified Successfully",
		},
	);

	await redisClient.del(otpKey);
	await redisClient.del(patientRegistrationKey);

	const { patient, ...user } = createdUser;
	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		user,
		patient,
		accessToken,
		refreshToken,
	};
};

const loginUser = async (payload: ILoginUserPayload) => {
	const { password } = payload;
	const email = payload.email.trim().toLowerCase();

	const user = await prisma.user.findUnique({
		where: { email },
	});

	if (!user) {
		throw new Error("User not found");
	}

	if (user.status === UserStatus.BLOCKED) {
		throw new Error("User is blocked");
	}

	if (user.isDeleted || user.status === UserStatus.DELETED) {
		throw new Error("User is deleted");
	}
	console.log(user, "user");

	if (user.password === null && user.googleId) {
		throw new Error(
			"User already registered with Google. Please login with Google.",
		);
	}

	const isPasswordMatched = await bcrypt.compare(
		password,
		user.password as string,
	);

	if (!isPasswordMatched) {
		throw new Error("Invalid credentials");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};

const getMe = async (user: IRequestUser) => {
	const isUserExists = await prisma.user.findUnique({
		where: {
			id: user.userId,
		},
		include: {
			patient: true,
		},
		omit: {
			password: true,
		},
	});

	if (!isUserExists) {
		throw new Error("User not found");
	}

	return isUserExists;
};

const refreshToken = async (token: string) => {
	const verifiedRefreshToken = jwtUtils.verifyToken(
		token,
		config.jwt_refresh_secret,
	);

	if (!verifiedRefreshToken.success || !verifiedRefreshToken.data) {
		throw new Error(
			config.node_env === "development"
				? verifiedRefreshToken.error
				: "Invalid refresh token",
		);
	}

	const data = verifiedRefreshToken.data as JwtPayload;

	const user = await prisma.user.findUnique({
		where: { id: data.userId },
	});

	if (!user || user.isDeleted || user.status !== UserStatus.ACTIVE) {
		throw new Error("User is inactive or not found");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};

const googleLogin = async (payload: IGoogleLoginPayload) => {
	let googleIdTokenPayload: TokenPayload | null | undefined = null;
	try {
		const ticket = await googleClient.verifyIdToken({
			idToken: payload.idToken,
			audience: config.google_client_id,
		});
		googleIdTokenPayload = ticket.getPayload();
	} catch (error) {
		console.log("google id token verification failed");
		throw new Error("Invalid Google ID token");
	}

	if (!googleIdTokenPayload) {
		throw new Error("Failed to retrieve Google ID token payload");
	}
	if (!googleIdTokenPayload.email) {
		throw new Error("Google ID token payload does not contain an email");
	}
	if (!googleIdTokenPayload.name) {
		throw new Error("Google ID token payload does not contain an name");
	}

	const isPatientExistsWithGoogleAuth = await prisma.user.findUnique({
		where: {
			email: googleIdTokenPayload.email,
			role: Role.PATIENT,
			googleId: googleIdTokenPayload.sub,
		},
	});

	let user = isPatientExistsWithGoogleAuth;

	if (!isPatientExistsWithGoogleAuth) {
		const isPatientWithCredentialsExists = await prisma.user.findUnique({
			where: {
				email: googleIdTokenPayload.email,
				role: Role.PATIENT,
			},
		});

		if (isPatientWithCredentialsExists) {
			if (isPatientWithCredentialsExists?.status === UserStatus.BLOCKED) {
				throw new Error("User is blocked");
			}
			if (!isPatientWithCredentialsExists?.emailVerified) {
				throw new Error(
					"User email is not verified. Please verify your email first!",
				);
			}

			if (
				isPatientWithCredentialsExists.isDeleted ||
				isPatientWithCredentialsExists.status === UserStatus.DELETED
			) {
				throw new Error("User is deleted");
			}

			user = await prisma.user.update({
				where: {
					email: googleIdTokenPayload.email,
					role: Role.PATIENT,
				},
				data: {
					googleId: googleIdTokenPayload.sub,
				},
			});
		} else {
			user = await prisma.user.create({
				data: {
					email: googleIdTokenPayload.email,
					name: googleIdTokenPayload.name,
					googleId: googleIdTokenPayload.sub,
					authProvider: AuthProvider.GOOGLE,
					role: Role.PATIENT,
					status: UserStatus.ACTIVE,
					emailVerified: true,
					patient: {
						create: {
							email: googleIdTokenPayload.email,
							name: googleIdTokenPayload.name,
						},
					},
				},
			});

			await sendEmail(
				"googl-register-success.ejs",
				{ name: googleIdTokenPayload.name, email: googleIdTokenPayload.email },
				{
					from: config.email_sender,
					to: googleIdTokenPayload.email,
					subject: "Google Registration Successful",
				},
			);
		}

		// user = await prisma.user.create({
		// 	data: {
		// 		email: googleIdTokenPayload.email,
		// 		name: googleIdTokenPayload.name,
		// 		googleId: googleIdTokenPayload.sub,
		// 		role: Role.PATIENT,
		// 		status: UserStatus.ACTIVE,
		// 		emailVerified: true,
		// 		patient: {
		// 			create: {
		// 				email: googleIdTokenPayload.email,
		// 				name: googleIdTokenPayload.name,
		// 			},
		// 		},
		// 	},
		// });
	}
	if (!user) {
		throw new Error(
			"Failed to create or update user with Google authentication",
		);
	}

	if (user?.status === UserStatus.BLOCKED) {
		throw new Error("User is blocked");
	}

	if (user.isDeleted || user.status === UserStatus.DELETED) {
		throw new Error("User is deleted");
	}
	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};

const forgotPassword = async (payload: IForgotPasswordPayload) => {
	const { email } = payload;

	const isUserExists = await prisma.user.findUnique({
		where: { email },
	});

	if (!isUserExists) {
		throw new Error("User with this email does not exist");
	}

	if (isUserExists.status === UserStatus.BLOCKED) {
		throw new Error("User is blocked");
	}

	if (isUserExists.isDeleted || isUserExists.status === UserStatus.DELETED) {
		throw new Error("User is deleted");
	}
	if (!isUserExists.emailVerified) {
		throw new Error(
			"User email is not verified. Please verify your email first!",
		);
	}

	if (isUserExists.googleId && isUserExists.authProvider === "GOOGLE") {
		throw new Error(
			"User is registered with Google. Please login with Google.",
		);
	}

	//after all check crate otp by crypto
	const otp = crypto.randomInt(100000, 1000000).toString(); // Generate a 6-digit OTP

	// then create key for redis
	const key = `forgot-password-otp:${email}`;
	// expiration time for otp is 5 minutes
	const expirationSeconds = 5 * 60;

	await redisClient.set(key, otp, {
		expiration: {
			type: "EX",
			value: expirationSeconds,
		},
	});

	const templatePath = path.join(
		process.cwd(),
		"src/app/templates/forgot-password.ejs",
	);

	const html = await ejs.renderFile(templatePath, {
		name: isUserExists.name,
		otp,
		expirationMinutes: expirationSeconds / 60,
	});

	await transporter.sendMail({
		to: isUserExists.email,
		from: config.email_sender,
		subject: "Forgot Password OTP",
		html,
	});
};
const resetPassword = async (payload: IResetPasswordPayload) => {
	const { email, otp, newPassword } = payload;

	const isUserExists = await prisma.user.findUnique({
		where: { email },
	});

	if (!isUserExists) {
		throw new Error("User with this email does not exist");
	}

	if (isUserExists.status === UserStatus.BLOCKED) {
		throw new Error("User is blocked");
	}

	if (isUserExists.isDeleted || isUserExists.status === UserStatus.DELETED) {
		throw new Error("User is deleted");
	}
	if (!isUserExists.emailVerified) {
		throw new Error(
			"User email is not verified. Please verify your email first!",
		);
	}

	if (isUserExists.googleId && isUserExists.authProvider === "GOOGLE") {
		throw new Error(
			"User is registered with Google. Please login with Google.",
		);
	}
	const key = `forgot-password-otp:${isUserExists.email}`;
	const redisOtp = await redisClient.get(key);

	if (!redisOtp) {
		throw new Error("OTP has expired or is invalid");
	}

	if (redisOtp !== otp) {
		throw new Error("OTP did not match");
	}

	const hashedPassword = await bcrypt.hash(
		newPassword,
		Number(config.bcrypt_salt_rounds),
	);

	await prisma.user.update({
		where: {
			email: isUserExists.email,
		},
		data: {
			password: hashedPassword,
		},
	});

	await redisClient.del(key);

	const templatePath = path.join(
		process.cwd(),
		"src/app/templates/reset-password-success.ejs",
	);

	const html = await ejs.renderFile(templatePath, {
		name: isUserExists.name,
	});

	await transporter.sendMail({
		to: isUserExists.email,
		from: config.email_sender,
		subject: "Password Reset Successful",
		html,
	});
};

export const AuthService = {
	registerPatient,
	verifyUserEmail,
	loginUser,
	getMe,
	refreshToken,
	googleLogin,
	forgotPassword,
	resetPassword,
};
