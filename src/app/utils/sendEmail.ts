import path from "node:path";
import ejs from "ejs";
import { transporter } from "../lib/nodemailer";

interface EmailInfo {
	from: string;
	to: string;
	subject: string;
}
export const sendEmail = async <T extends Record<string, unknown>>(
	filePath: string,
	templateData: T,
	emailInfo: EmailInfo,
) => {
	const { from, to, subject } = emailInfo;
	const templatePath = path.join(
		process.cwd(),
		`src/app/templates/${filePath}`,
	);

	const html = await ejs.renderFile(templatePath, templateData);

	await transporter.sendMail({
		from,
		to,
		subject,
		html,
	});
};
