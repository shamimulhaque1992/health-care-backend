import bcrypt from "bcryptjs";
import type { TokenPayload } from "google-auth-library";
import type { JwtPayload, SignOptions } from "jsonwebtoken";
import { Role, UserStatus } from "../../../generated/prisma/enums";
import config from "../../config";
import { googleClient } from "../../lib/googleAuth";
import { prisma } from "../../lib/prisma";
import { jwtUtils } from "../../utils/jwt";
import crypto from "crypto";
import type {
  IForgotPasswordPayload,
  IGoogleLoginPayload,
  ILoginUserPayload,
  IRegisterPatientPayload,
  IRequestUser,
  IResetPasswordPayload,
} from "./auth.interface";
import { redisClient } from "../../lib/redis";

const registerPatient = async (payload: IRegisterPatientPayload) => {
  const { name, password } = payload;
  const email = payload.email.trim().toLowerCase();

  const isUserExists = await prisma.user.findUnique({
    where: { email },
  });

  if (isUserExists) {
    throw new Error("User with this email already exists");
  }

  const hashedPassword = await bcrypt.hash(password, 8);

  const createdUser = await prisma.user.create({
    data: {
      name,
      email,
      password: hashedPassword,
      role: Role.PATIENT,
      status: UserStatus.ACTIVE,
      emailVerified: false,
      patient: {
        create: { name, email },
      },
    },
    omit: { password: true },
    include: { patient: true },
  });

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
    }

    user = await prisma.user.create({
      data: {
        email: googleIdTokenPayload.email,
        name: googleIdTokenPayload.name,
        googleId: googleIdTokenPayload.sub,
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
};

export const AuthService = {
  registerPatient,
  loginUser,
  getMe,
  refreshToken,
  googleLogin,
  forgotPassword,
  resetPassword,
};
