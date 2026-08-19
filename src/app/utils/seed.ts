import bcrypt from "bcryptjs";
import { Role } from "../../generated/prisma/enums";
import config from "../config";
import { prisma } from "../lib/prisma";

export const seedSupperAdmin = async () => {
	try {
		const isSupperAdminExists = await prisma.user.findFirst({
			where: {
				role: Role.SUPER_ADMIN,
			},
		});

		if (isSupperAdminExists) {
			console.log("Supper admin exists!!");
			return;
		}
		const name = config.super_admin_name;
		const email = config.super_admin_email;
		const password = config.super_admin_password;
		if (!name || !email || !password) {
			throw new Error(
				"Super admin credentials are not provided in the environment variables.",
			);
		}

		const hashedPassword = await bcrypt.hash(
			password,
			Number(config.bcrypt_salt_rounds),
		);

		const supperAdmin = await prisma.user.create({
			data: {
				name,
				email,
				password: hashedPassword,
				role: Role.SUPER_ADMIN,
				emailVerified: true,
				needPasswordChange: false,
			},
		});

		console.log("Supper admin crated", supperAdmin);
	} catch (error) {
		await prisma.user.delete({
			where: {
				email: config.super_admin_email,
			},
		});
	}
};

export const seedTesterAdmin = async () => {
	try {
		const isTesterAdminExists = await prisma.user.findUnique({
			where: {
				email: config.tester_admin_email,
			},
		});

		if (isTesterAdminExists) {
			console.log("Tester admin exists!!");
			return;
		}
		const name = config.tester_admin_name;
		const email = config.tester_admin_email;
		const password = config.tester_admin_password;
		if (!name || !email || !password) {
			throw new Error(
				"Tester admin credentials are not provided in the environment variables.",
			);
		}

		const hashedPassword = await bcrypt.hash(
			password,
			Number(config.bcrypt_salt_rounds),
		);

		const testerAdmin = await prisma.user.create({
			data: {
				name,
				email,
				password: hashedPassword,
				role: Role.ADMIN,
				emailVerified: true,
				needPasswordChange: false,
			},
		});

		console.log("Tester admin created", testerAdmin);
	} catch (error) {
		console.log("🚀 ~ seedTesterAdmin ~ error:", error);
		await prisma.user.delete({
			where: {
				email: config.tester_admin_email,
			},
		});
	}
};

export const seedTesterDoctor = async () => {
	try {
		const isTesterDoctor = await prisma.user.findUnique({
			where: {
				email: config.tester_doctor_email,
			},
		});

		if (isTesterDoctor) {
			console.log("Tester doctor exists!!");
			return;
		}
		const name = config.tester_doctor_name;
		const email = config.tester_doctor_email;
		const password = config.tester_doctor_password;
		if (!name || !email || !password) {
			throw new Error(
				"Tester doctor credentials are not provided in the environment variables.",
			);
		}

		const hashedPassword = await bcrypt.hash(
			password,
			Number(config.bcrypt_salt_rounds),
		);

		const testerDoctor = await prisma.user.create({
			data: {
				name,
				email,
				password: hashedPassword,
				role: Role.DOCTOR,
				emailVerified: true,
				needPasswordChange: false,
			},
		});

		console.log("Tester doctor created", testerDoctor);
	} catch (error) {
		console.log("🚀 ~ seedTesterDoctor ~ error:", error);
		await prisma.user.delete({
			where: {
				email: config.tester_doctor_email,
			},
		});
	}
};
